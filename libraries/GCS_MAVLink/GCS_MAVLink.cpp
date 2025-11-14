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

#include "GCS_config.h"

#if HAL_MAVLINK_BINDINGS_ENABLED

#include "GCS.h"
#include "GCS_MAVLink.h"

#include <AP_Common/AP_Common.h>
#include <AP_HAL/AP_HAL.h>

//Mis includes
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define MAVLINK_ENCRYPTION_ENABLED 1

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


// Clave compartida (en producción usar gestión segura de claves)
static const uint8_t encryption_key[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

// Estructura MAVLink compatible
typedef struct {
    uint8_t magic;
    uint8_t len;
    uint8_t incompat_flags;
    uint8_t compat_flags;
    uint8_t seq;
    uint8_t sysid;
    uint8_t compid;
    uint8_t msgid[3];
    uint8_t payload[255];
    uint16_t checksum;
    uint8_t signature[13];
} __attribute__((packed)) mavlink_msg_encrypted_t;

// ENCRIPTAR payload de MAVLink
static int encrypt_mavlink_payload(
    uint8_t *buf,              // Buffer del mensaje
    uint8_t len,               // Longitud total del mensaje
    const uint8_t *key,
    uint8_t *iv_out,
    uint8_t *tag_out)
{
    EVP_CIPHER_CTX *ctx;
    int evp_len;
    int ciphertext_len;
    
    mavlink_msg_encrypted_t *msg = (mavlink_msg_encrypted_t*)buf;
    
    // Generar IV único (96 bits)
    if(1 != RAND_bytes(iv_out, 12)) {
        return -1;
    }
    
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        return -1;
    }
    
    // Inicializar ChaCha20-Poly1305
    if(1 != EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key, iv_out)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    // AAD: Header (primeros 10 bytes)
    uint8_t *aad = buf;
    int aad_len = 10;
    
    if(1 != EVP_EncryptUpdate(ctx, NULL, &evp_len, aad, aad_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    // Cifrar payload in-place
    uint8_t *plaintext = msg->payload;
    int plaintext_len = msg->len;
    
    if(1 != EVP_EncryptUpdate(ctx, plaintext, &evp_len, plaintext, plaintext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = evp_len;
    
    if(1 != EVP_EncryptFinal_ex(ctx, plaintext + evp_len, &evp_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += evp_len;
    
    // Obtener tag
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag_out)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

/*
  send a buffer out a MAVLink channel
 */
void comm_send_buffer(mavlink_channel_t chan, const uint8_t *buf, uint8_t len)
{
    if (!valid_channel(chan) || mavlink_comm_port[chan] == nullptr || chan_discard[chan]) {
        return;
    }
#if HAL_HIGH_LATENCY2_ENABLED
    // if it's a disabled high latency channel, don't send
    GCS_MAVLINK *link = gcs().chan(chan);
    if (link->is_high_latency_link && !gcs().get_high_latency_status()) {
        return;
    }
#endif
    if (gcs_alternative_active[chan]) {
        // an alternative protocol is active
        return;
    }
    
#ifdef MAVLINK_ENCRYPTION_ENABLED
    // === CIFRADO AGREGADO AQUÍ ===
    
    // Buffer para mensaje cifrado + IV + Tag
    uint8_t encrypted_buffer[300];  // Suficientemente grande
    memcpy(encrypted_buffer, buf, len);
    
    uint8_t iv[12];
    uint8_t tag[16];
    
    // Encriptar el payload
    int encrypted_len = encrypt_mavlink_payload(
        encrypted_buffer, 
        len, 
        encryption_key, 
        iv, 
        tag
    );
    
    if (encrypted_len > 0) {
        // Agregar IV y Tag al final del mensaje
        memcpy(encrypted_buffer + len, iv, 12);
        memcpy(encrypted_buffer + len + 12, tag, 16);
        
        // Enviar: mensaje_cifrado + IV (12) + Tag (16)
        const size_t total_len = len + 28;  // +28 por IV y Tag
        const size_t written = mavlink_comm_port[chan]->write(encrypted_buffer, total_len);
        
#if CONFIG_HAL_BOARD == HAL_BOARD_SITL
        if (written < total_len && !mavlink_comm_port[chan]->is_write_locked()) {
            AP_HAL::panic("Short write on UART: %lu < %u", (unsigned long)written, (unsigned)total_len);
        }
#else
        (void)written;
#endif
    } else {
        // Error en cifrado, enviar sin cifrar (fallback)
        const size_t written = mavlink_comm_port[chan]->write(buf, len);
#if CONFIG_HAL_BOARD == HAL_BOARD_SITL
        if (written < len && !mavlink_comm_port[chan]->is_write_locked()) {
            AP_HAL::panic("Short write on UART: %lu < %u", (unsigned long)written, len);
        }
#else
        (void)written;
#endif
    }
    
#else
    // === CÓDIGO ORIGINAL (SIN CIFRADO) ===
    const size_t written = mavlink_comm_port[chan]->write(buf, len);
#if CONFIG_HAL_BOARD == HAL_BOARD_SITL
    if (written < len && !mavlink_comm_port[chan]->is_write_locked()) {
        AP_HAL::panic("Short write on UART: %lu < %u", (unsigned long)written, len);
    }
#else
    (void)written;
#endif
#endif  // MAVLINK_ENCRYPTION_ENABLED
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
