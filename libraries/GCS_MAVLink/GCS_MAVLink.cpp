/*
   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/// @file	GCS_MAVLink.cpp

/*
This provides some support code and variables for MAVLink enabled sketches

*/

#define AP_MAVLINK_ENCRYPT 1

#include "GCS_config.h"

#if HAL_MAVLINK_BINDINGS_ENABLED

#include "GCS.h"
#include "GCS_MAVLink.h"

#include <AP_Common/AP_Common.h>
#include <AP_HAL/AP_HAL.h>

//Mis include

#include <stdint.h>
#include <string.h>

// Socket includes para envío UDP directo
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// ASCON libreria
#include "../ascon/api.h"
#include "../ascon/crypto_aead.h"

// Termina mis

extern const AP_HAL::HAL& hal;

#ifdef MAVLINK_SEPARATE_HELPERS
// Shut up warnings about missing declarations; TODO: should be fixed on
// mavlink/pymavlink project for when MAVLINK_SEPARATE_HELPERS is defined
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-declarations"
#include "include/mavlink/v2.0/mavlink_helpers.h"
#pragma GCC diagnostic pop
#endif

mavlink_message_t* mavlink_get_channel_buffer(uint8_t chan) {
#if HAL_GCS_ENABLED
    GCS_MAVLINK *link = gcs().chan(chan);
    if (link == nullptr) {
        return nullptr;
    }
    return link->channel_buffer();
#else
    return nullptr;
#endif
}

mavlink_status_t* mavlink_get_channel_status(uint8_t chan) {
#if HAL_GCS_ENABLED
    GCS_MAVLINK *link = gcs().chan(chan);
    if (link == nullptr) {
        return nullptr;
    }
    return link->channel_status();
#else
    return nullptr;
#endif
}

#endif // HAL_MAVLINK_BINDINGS_ENABLED

#if HAL_GCS_ENABLED

AP_HAL::UARTDriver	*mavlink_comm_port[MAVLINK_COMM_NUM_BUFFERS];
bool gcs_alternative_active[MAVLINK_COMM_NUM_BUFFERS];

// per-channel lock
static HAL_Semaphore chan_locks[MAVLINK_COMM_NUM_BUFFERS];
static bool chan_discard[MAVLINK_COMM_NUM_BUFFERS];

// Buffer de acumulación para manejar fragmentación de mensajes MAVLink
struct mavlink_fragment_buffer_t {
    uint8_t buffer[300];         // Buffer para acumular el mensaje completo
    uint16_t accumulated_len;    // Bytes acumulados hasta ahora
    uint16_t expected_len;       // Longitud total esperada del mensaje
    bool    is_accumulating;     // Si estamos en proceso de acumulación
    uint32_t last_fragment_ms;   // Timestamp del último fragmento (para timeout)
};

//static mavlink_fragment_buffer_t fragment_buffers[MAVLINK_COMM_NUM_BUFFERS];

mavlink_system_t mavlink_system = {7,1};

// routing table
MAVLink_routing GCS_MAVLINK::routing;

GCS_MAVLINK *GCS_MAVLINK::find_by_mavtype_and_compid(uint8_t mav_type, uint8_t compid, uint8_t &sysid) {
    mavlink_channel_t channel;
    if (!routing.find_by_mavtype_and_compid(mav_type, compid, sysid, channel)) {
        return nullptr;
    }
    return gcs().chan(channel);
}

// set a channel as private. Private channels get sent heartbeats, but
// don't get broadcast packets or forwarded packets
void GCS_MAVLINK::set_channel_private(mavlink_channel_t _chan)
{
    const uint8_t mask = (1U<<(unsigned)_chan);
    mavlink_private |= mask;
}

// return a MAVLink parameter type given a AP_Param type
MAV_PARAM_TYPE GCS_MAVLINK::mav_param_type(enum ap_var_type t)
{
    if (t == AP_PARAM_INT8) {
	    return MAV_PARAM_TYPE_INT8;
    }
    if (t == AP_PARAM_INT16) {
	    return MAV_PARAM_TYPE_INT16;
    }
    if (t == AP_PARAM_INT32) {
	    return MAV_PARAM_TYPE_INT32;
    }
    // treat any others as float
    return MAV_PARAM_TYPE_REAL32;
}


/// Check for available transmit space on the nominated MAVLink channel
///
/// @param chan		Channel to check
/// @returns		Number of bytes available
uint16_t comm_get_txspace(mavlink_channel_t chan)
{
    GCS_MAVLINK *link = gcs().chan(chan);
    if (link == nullptr) {
        return 0;
    }
    return link->txspace();
}

#ifdef AP_MAVLINK_ENCRYPT

#include "ascon_ctx.h"

// ===== MAVLink v2 constants =====
#define MAVLINK_V2_STX       0xFD
#define MAVLINK_V2_HDR_LEN   10
#define MAVLINK_V2_SIG_LEN   13
#define MAVLINK_IFLAG_SIGNED 0x01
#define MAVLINK_IFLAG_ENCRYPTED 0x02  // Flag para mensajes cifrados con ASCON

//Construir el nonce para ASCON:
// A 128-bit value is used only once, ensuring
// that the ciphertext differs for each nonce. This prevents
// various attacks on the communication.
static inline void build_nonce(uint8_t npub[CRYPTO_NPUBBYTES],
                               uint64_t iv_boot,
                               uint8_t sysid, uint8_t compid, uint8_t seq)
{
    // [ iv_boot(8) | sysid(1) | compid(1) | seq(1) | pad(5) ] = 16 bytes
    memcpy(&npub[0], &iv_boot, 8);
    npub[8]  = sysid;
    npub[9]  = compid;
    npub[10] = seq;
    memset(&npub[11], 0, 5);
}

static inline size_t build_aad(uint8_t *aad,
                               uint8_t incompat_flags,
                               uint8_t compat_flags,
                               uint8_t seq,
                               uint8_t sysid,
                               uint8_t compid,
                               uint32_t msgid)
{
    // [incompat|compat|seq|sysid|compid|msgid(3)] = 8 bytes
    aad[0] = incompat_flags;
    aad[1] = compat_flags;
    aad[2] = seq;
    aad[3] = sysid;
    aad[4] = compid;
    aad[5] = (uint8_t)(msgid & 0xFF);
    aad[6] = (uint8_t)((msgid >> 8) & 0xFF);
    aad[7] = (uint8_t)((msgid >> 16) & 0xFF);
    return 8;
}
#endif

/*
  send a buffer out a MAVLink channel
 */
void comm_send_buffer(mavlink_channel_t chan, const uint8_t *buf, uint8_t len)
{
    // **ESTE PRINTF DEBE APARECER SÍ O SÍ**
    printf("[SEND-DEBUG] Canal=%u, len=%u, buf[0]=0x%02X\n", 
           (unsigned)chan, len, (len > 0) ? buf[0] : 0);
    
    // Validaciones básicas
    if (!valid_channel(chan)) {
        printf("[SEND-DEBUG] Canal inválido\n");
        return;
    }
    
    if (mavlink_comm_port[chan] == nullptr) {
        printf("[SEND-DEBUG] Puerto NULL\n");
        return;
    }
    
    if (chan_discard[chan]) {
        printf("[SEND-DEBUG] Canal descartado\n");
        return;
    }

    // **ESTRATEGIA SIMPLE**: 
    // - Canal 0 (MAVProxy): SIN cifrar
    // - Otros canales: Intentar cifrado ASCON
    
    printf("[SEND-DEBUG] Pasó validaciones, procesando...\n");
    
    const bool should_encrypt = (chan != MAVLINK_COMM_0);
    
    if (!should_encrypt) {
        printf("[SEND-DEBUG] Canal 0 - Enviando SIN cifrar\n");
        const size_t written = mavlink_comm_port[chan]->write(buf, len);
        printf("[SEND-DEBUG] Escritos %zu de %u bytes\n", written, len);
        
#if CONFIG_HAL_BOARD == HAL_BOARD_SITL
        if (written < len && !mavlink_comm_port[chan]->is_write_locked()) {
            AP_HAL::panic("Short write on UART: %lu < %u", 
                         (unsigned long)written, len);
        }
#endif
        return;
    }
    
    printf("[SEND-DEBUG] Canal %u - Intentando cifrado ASCON\n", (unsigned)chan);
    
    // Verificar que es MAVLink v2
    if (len < MAVLINK_V2_HDR_LEN || buf[0] != MAVLINK_V2_STX) {
        printf("[SEND-DEBUG] No es MAVLink v2 o muy corto, enviando sin cifrar\n");
        mavlink_comm_port[chan]->write(buf, len);
        return;
    }
    
    const uint8_t payload_len = buf[1];
    const uint16_t expected_len = MAVLINK_V2_HDR_LEN + payload_len + 2;
    
    printf("[SEND-DEBUG] MAVLink v2: payload_len=%u, expected=%u\n", 
           payload_len, expected_len);
    
    if (len < expected_len) {
        printf("[SEND-DEBUG] Mensaje incompleto (%u < %u), enviando sin cifrar\n", 
               len, expected_len);
        mavlink_comm_port[chan]->write(buf, len);
        return;
    }
    
    // Extraer header
    const uint8_t incompat_flags = buf[2];
    const uint8_t compat_flags   = buf[3];
    const uint8_t seq            = buf[4];
    const uint8_t sysid          = buf[5];
    const uint8_t compid         = buf[6];
    const uint32_t msgid = (uint32_t)buf[7] | 
                          ((uint32_t)buf[8] << 8) | 
                          ((uint32_t)buf[9] << 16);
    
    printf("[SEND-DEBUG] msgid=%u, seq=%u, sysid=%u, compid=%u, incompat=0x%02X\n",
           msgid, seq, sysid, compid, incompat_flags);
    
    // No cifrar firmados
    if (incompat_flags & MAVLINK_IFLAG_SIGNED) {
        printf("[SEND-DEBUG] Mensaje firmado, enviando sin cifrar\n");
        mavlink_comm_port[chan]->write(buf, len);
        return;
    }
    
    // Verificar tamaño
    if ((uint16_t)payload_len + CRYPTO_ABYTES > 255) {
        printf("[SEND-DEBUG] Payload muy grande para cifrar\n");
        mavlink_comm_port[chan]->write(buf, len);
        return;
    }
    
    // Buscar crc_extra
    const mavlink_msg_entry_t *entry = mavlink_get_msg_entry(msgid);
    if (entry == nullptr) {
        printf("[SEND-DEBUG] msgid=%u no encontrado en tabla\n", msgid);
        mavlink_comm_port[chan]->write(buf, len);
        return;
    }
    
    const uint8_t crc_extra = entry->crc_extra;
    printf("[SEND-DEBUG] crc_extra=0x%02X\n", crc_extra);
    
    // **CIFRAR**
    printf("[SEND-DEBUG] *** INICIANDO CIFRADO ASCON ***\n");
    
    uint8_t encrypted[300];
    
    // Copiar header y modificar
    memcpy(encrypted, buf, MAVLINK_V2_HDR_LEN);
    encrypted[1] = payload_len + CRYPTO_ABYTES;
    encrypted[2] |= MAVLINK_IFLAG_ENCRYPTED;
    
    printf("[SEND-DEBUG] Nuevo LEN=%u, incompat_flags=0x%02X\n", 
           encrypted[1], encrypted[2]);
    
    // Construir AAD
    uint8_t aad[16];
    const size_t aad_len = build_aad(aad, encrypted[2], compat_flags, 
                                     seq, sysid, compid, msgid);
    
    // Construir Nonce
    uint8_t npub[CRYPTO_NPUBBYTES];
    build_nonce(npub, g_ascon_ctx.iv_boot, sysid, compid, seq);
    
    // Cifrar
    const uint8_t *plaintext  = buf + MAVLINK_V2_HDR_LEN;
    uint8_t       *ciphertext = encrypted + MAVLINK_V2_HDR_LEN;
    
    unsigned long long clen_out = 0;
    printf("[SEND-DEBUG] Llamando crypto_aead_encrypt...\n");
    
    int rc = crypto_aead_encrypt(
        ciphertext,
        &clen_out,
        plaintext,
        payload_len,
        aad,
        aad_len,
        nullptr,
        npub,
        g_ascon_ctx.key
    );
    
    printf("[SEND-DEBUG] crypto_aead_encrypt retornó: rc=%d, clen=%llu\n", 
           rc, clen_out);
    
    if (rc != 0 || clen_out != (unsigned long long)(payload_len + CRYPTO_ABYTES)) {
        printf("[SEND-DEBUG] ¡ERROR! Cifrado falló\n");
        mavlink_comm_port[chan]->write(buf, len);
        return;
    }
    
    printf("[SEND-DEBUG] ¡Cifrado exitoso!\n");
    
    // Recalcular CRC
    uint16_t crc;
    crc_init(&crc);
    crc_accumulate_buffer(&crc, (const char*)ciphertext, encrypted[1]);
    crc_accumulate(crc_extra, &crc);
    
    printf("[SEND-DEBUG] CRC calculado: 0x%04X\n", crc);
    
    // Escribir CRC
    const uint16_t payload_end = MAVLINK_V2_HDR_LEN + encrypted[1];
    encrypted[payload_end + 0] = (uint8_t)(crc & 0xFF);
    encrypted[payload_end + 1] = (uint8_t)(crc >> 8);
    
    const uint8_t final_len = payload_end + 2;
    
    printf("[SEND-DEBUG] Mensaje cifrado completo: %u bytes\n", final_len);
    
    // **ENVIAR**
    const size_t written = mavlink_comm_port[chan]->write(encrypted, final_len);
    
    printf("[SEND-DEBUG] Escritos %zu de %u bytes cifrados\n", written, final_len);
    
    if (written != final_len) {
        printf("[SEND-DEBUG] ¡ADVERTENCIA! Envío incompleto\n");
    }
    
#if CONFIG_HAL_BOARD == HAL_BOARD_SITL
    if (written < final_len && !mavlink_comm_port[chan]->is_write_locked()) {
        AP_HAL::panic("Short write on UART: %lu < %u", 
                     (unsigned long)written, final_len);
    }
#endif
    
    printf("[SEND-DEBUG] *** FIN CIFRADO ASCON ***\n");
}


/*
  lock a channel for send
  if there is insufficient space to send size bytes then all bytes
  written to the channel by the mavlink library will be discarded
  while the lock is held.
 */
void comm_send_lock(mavlink_channel_t chan_m, uint16_t size)
{
    const uint8_t chan = uint8_t(chan_m);
    chan_locks[chan].take_blocking();
    if (mavlink_comm_port[chan]->txspace() < size) {
        chan_discard[chan] = true;
        gcs_out_of_space_to_send(chan_m);
    }
}

/*
  unlock a channel
 */
void comm_send_unlock(mavlink_channel_t chan_m)
{
    const uint8_t chan = uint8_t(chan_m);
    chan_discard[chan] = false;
    chan_locks[chan].give();
}

/*
  return reference to GCS channel lock, allowing for
  HAVE_PAYLOAD_SPACE() to be run with a locked channel
 */
HAL_Semaphore &comm_chan_lock(mavlink_channel_t chan)
{
    return chan_locks[uint8_t(chan)];
}

#endif  // HAL_GCS_ENABLED
