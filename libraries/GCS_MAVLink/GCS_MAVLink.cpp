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

static mavlink_fragment_buffer_t fragment_buffers[MAVLINK_COMM_NUM_BUFFERS];

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
// MAVLINK_CFLAG_ENCRYPTED 0x80 ahora definido en GCS_MAVLink.h

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
    // **DEBUG**: Interceptar todos los envíos para ver qué pasa
    printf("[DEBUG] comm_send_buffer: Canal=%u, len=%u\n", (unsigned)chan, len);
    
    if (!valid_channel(chan) || mavlink_comm_port[chan] == nullptr || chan_discard[chan]) {
        printf("[DEBUG] Canal inválido o descartado\n");
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

    // Obtener buffer de fragmentación para este canal
    mavlink_fragment_buffer_t *frag_buf = &fragment_buffers[chan];
    const uint32_t now_ms = AP_HAL::millis();
    
    // Timeout para limpiar buffer incompleto (1 segundo)
    if (frag_buf->is_accumulating && (now_ms - frag_buf->last_fragment_ms) > 1000) {
        printf("[FRAGMENTACION] Timeout - reseteando buffer del canal %d\n", chan);
        frag_buf->is_accumulating = false;
        frag_buf->accumulated_len = 0;
    }

    // Detectar inicio de mensaje MAVLink v2
    if (len >= MAVLINK_V2_HDR_LEN && buf[0] == MAVLINK_V2_STX) {
        const uint8_t payload_len = buf[1];
        const uint16_t expected_total = MAVLINK_V2_HDR_LEN + payload_len + 2; // +2 para CRC
        
        printf("[FRAGMENTACION] Detectado inicio MAVLink v2: len=%u, payload_len=%u, expected_total=%u\n", 
               len, payload_len, expected_total);
        
        // Si el mensaje está completo en este buffer, procesarlo directamente
        if (len >= expected_total) {
            printf("[FRAGMENTACION] Mensaje completo en un solo fragmento\n");
            send_complete_mavlink_message(chan, buf, len);
            return;
        }
        
        // El mensaje está fragmentado - iniciar acumulación
        printf("[FRAGMENTACION] Mensaje fragmentado - iniciando acumulación\n");
        frag_buf->is_accumulating = true;
        frag_buf->accumulated_len = 0;
        frag_buf->expected_len = expected_total;
        frag_buf->last_fragment_ms = now_ms;
        
        // Copiar este primer fragmento (len como uint8_t siempre cabe en buffer[300])
        memcpy(frag_buf->buffer, buf, len);
        frag_buf->accumulated_len = len;
        printf("[FRAGMENTACION] Primer fragmento acumulado: %u/%u bytes\n", 
               frag_buf->accumulated_len, frag_buf->expected_len);
        return;
    }
    
    // Si estamos acumulando y este no es un inicio de MAVLink v2
    if (frag_buf->is_accumulating) {
        printf("[FRAGMENTACION] Fragmento adicional recibido: len=%u\n", len);
        
        // Verificar que cabe en el buffer y no excede el mensaje esperado
        if (frag_buf->accumulated_len + len <= sizeof(frag_buf->buffer) && 
            frag_buf->accumulated_len + len <= frag_buf->expected_len) {
            
            // Agregar este fragmento al buffer acumulado
            memcpy(frag_buf->buffer + frag_buf->accumulated_len, buf, len);
            frag_buf->accumulated_len += len;
            frag_buf->last_fragment_ms = now_ms;
            
            printf("[FRAGMENTACION] Fragmento acumulado: %u/%u bytes\n", 
                   frag_buf->accumulated_len, frag_buf->expected_len);
            
            // ¿Tenemos el mensaje completo?
            if (frag_buf->accumulated_len >= frag_buf->expected_len) {
                printf("[FRAGMENTACION] ¡Mensaje completo reconstruido!\n");
                
                // Procesar mensaje completo
                send_complete_mavlink_message(chan, frag_buf->buffer, frag_buf->accumulated_len);
                
                // Resetear buffer
                frag_buf->is_accumulating = false;
                frag_buf->accumulated_len = 0;
            }
            return;
        } else {
            printf("[FRAGMENTACION] ERROR: Fragmento excede límites esperados\n");
            frag_buf->is_accumulating = false;
        }
    }

    // Fallback: enviar sin cifrar (para mensajes no MAVLink v2 o errores)
    printf("[FRAGMENTACION] Enviando mensaje sin procesar (%u bytes)\n", len);
    const size_t written = mavlink_comm_port[chan]->write(buf, len);
#if CONFIG_HAL_BOARD == HAL_BOARD_SITL
    if (written < len && !mavlink_comm_port[chan]->is_write_locked()) {
        AP_HAL::panic("Short write on UART: %lu < %u", (unsigned long)written, len);
    }
#else
    (void)written;
#endif
}

/*
  Procesar y enviar un mensaje MAVLink completo (con cifrado si aplica)
 */
void send_complete_mavlink_message(mavlink_channel_t chan, const uint8_t *buf, uint8_t len)
{
    // DEBUG: Mostrar información del canal
    printf("[CIFRADO] Canal=%u, len=%u\n", (unsigned)chan, len);
    
    // **TEMPORAL**: Forzar algunos mensajes a Canal 1 para probar cifrado
    static uint32_t msg_count = 0;
    msg_count++;
    
    // DEBUG: Mostrar contador cada 10 mensajes
    if ((msg_count % 10) == 0) {
        printf("[CIFRADO] Contador: %u mensajes procesados\n", msg_count);
    }
    
    // Cada 3 mensajes, cifrar para hacer pruebas más frecuentes
    mavlink_channel_t test_chan = chan;
    bool force_encrypt = false;
    if ((msg_count % 3) == 0 && chan == MAVLINK_COMM_0) {
        test_chan = MAVLINK_COMM_1;  // Lógica de cifrado
        force_encrypt = true;
        printf("[CIFRADO] **FORZANDO** Cifrado para prueba (msg #%u) - Enviará por Canal %u\n", msg_count, (unsigned)chan);
    }
    
    // NO CIFRAR mensajes del canal 0 (MAVProxy necesita mensajes legibles)
    if (test_chan == MAVLINK_COMM_0 && !force_encrypt) {
        printf("[CIFRADO] SKIP: Canal 0 (MAVProxy), enviando sin cifrar\n");
        const size_t written = mavlink_comm_port[chan]->write(buf, len);  // Usar chan original para el envío real
#if CONFIG_HAL_BOARD == HAL_BOARD_SITL
        if (written < len && !mavlink_comm_port[chan]->is_write_locked()) {
            AP_HAL::panic("Short write on UART: %lu < %u", (unsigned long)written, len);
        }
#endif
        return;
    }
    
    printf("[CIFRADO] CIFRANDO Canal %u\n", (unsigned)test_chan);
    
    // Cifrado ASCON para mensajes MAVLink v2 (solo canales != 0)
    if (len >= MAVLINK_V2_HDR_LEN && buf[0] == MAVLINK_V2_STX) {
        const uint8_t  in_payload_len = buf[1];
        
        printf("[CIFRADO] Detectado MAVLink v2: len=%u, payload_len=%u\n", len, in_payload_len);
        
        // Verificar que tenemos un mensaje completo
        const uint16_t expected_len = MAVLINK_V2_HDR_LEN + in_payload_len + 2; // +2 para CRC
        if (len >= expected_len) {
            printf("[CIFRADO] Mensaje completo: len=%u >= expected=%u\n", len, expected_len);
            
            const uint8_t  incompat_flags = buf[2];
            const uint8_t  compat_flags   = buf[3];
            const uint8_t  seq            = buf[4];
            const uint8_t  sysid          = buf[5];
            const uint8_t  compid         = buf[6];
            const uint32_t msgid          = (uint32_t)buf[7] | ((uint32_t)buf[8] << 8) | ((uint32_t)buf[9] << 16);

            printf("[CIFRADO] msgid=%u, seq=%u, sysid=%u, compid=%u\n", msgid, seq, sysid, compid);
            
            const bool signed_frame = (incompat_flags & MAVLINK_IFLAG_SIGNED) != 0;

            // Cifrar solo frames no firmados
            if (!signed_frame) {
                printf("[CIFRADO] Frame no firmado, procediendo a cifrar\n");
                // Verificar que el payload + tag cabe en el campo LEN (0-255)
                if ((uint16_t)in_payload_len + CRYPTO_ABYTES <= 255) {
                    printf("[CIFRADO] Tamaño OK: payload=%u + tag=%u = %u <= 255\n", 
                           in_payload_len, CRYPTO_ABYTES, in_payload_len + CRYPTO_ABYTES);
                    
                    // Buscar crc_extra del msgid
                    const mavlink_msg_entry_t *entry = mavlink_get_msg_entry(msgid);
                    if (entry != nullptr) {
                        printf("[CIFRADO] Entrada msgid encontrada, crc_extra=0x%02X\n", entry->crc_extra);
                        
                        // Mostrar payload original antes del cifrado
                        printf("[CIFRADO] Payload original (%u bytes): ", in_payload_len);
                        for(uint8_t i = 0; i < in_payload_len && i < 16; i++) {
                            printf("%02X ", buf[MAVLINK_V2_HDR_LEN + i]);
                        }
                        if(in_payload_len > 16) printf("...");
                        printf("\n");
                        
                        const uint8_t crc_extra = entry->crc_extra;
                        
                        // Buffer de salida: header + payload_cifrado + tag + CRC
                        uint8_t out[300];
                        
                        memcpy(out, buf, MAVLINK_V2_HDR_LEN);  // copia header
                        out[1] = in_payload_len + CRYPTO_ABYTES; // nuevo LEN
                        out[2] = (out[2] | MAVLINK_IFLAG_SIGNED) & 0xFF;   // mantener otros bits válidos, asegurar SIGNED
                        out[3] = out[3] | MAVLINK_CFLAG_ENCRYPTED;        // marcar "encrypted" en compat_flags
                        printf("[CIFRADO] Marcando mensaje como cifrado (compat_flags=0x%02X)\n", out[3]);
                        
                        // DEBUG: Verificar que el flag se mantenga
                        printf("[CIFRADO] Header final: ");
                        for(int i = 0; i < 10; i++) {
                            printf("%02X ", out[i]);
                        }
                        printf("\n");

                        // AAD + Nonce
                        uint8_t aad[16];
                        const size_t aad_len = build_aad(aad, out[2], out[3], seq, sysid, compid, msgid);

                        printf("[CIFRADO] sysid=%u, compid=%u, seq=%u\n", sysid, compid, seq);
                        printf("[CIFRADO] incompat_flags=0x%02X, compat_flags=0x%02X (cifrado marcado)\n", out[2], out[3]);
                        printf("[CIFRADO] AAD (%zu bytes): ", aad_len);
                        for(size_t i = 0; i < aad_len && i < 16; i++) {
                            printf("%02X ", aad[i]);
                        }
                        printf("\n");

                        uint8_t npub[CRYPTO_NPUBBYTES];
                        build_nonce(npub, g_ascon_ctx.iv_boot, sysid, compid, seq);

                        printf("[CIFRADO] Nonce (16 bytes): ");
                        for(int i = 0; i < CRYPTO_NPUBBYTES; i++) {
                            printf("%02X ", npub[i]);
                        }
                        printf("\n");

                        printf("[CIFRADO] Clave (16 bytes): ");
                        for(int i = 0; i < 16; i++) {
                            printf("%02X ", g_ascon_ctx.key[i]);
                        }
                        printf("\n");

                        // Punteros a payload
                        const uint8_t *m_in  = buf + MAVLINK_V2_HDR_LEN;     // plaintext (input)
                        uint8_t       *c_out = out + MAVLINK_V2_HDR_LEN;     // ciphertext (output)

                        // Llamada a ASCON: c_out queda [ciphertext || tag]; clen = mlen + CRYPTO_ABYTES
                        unsigned long long clen_out = 0ULL;
                        printf("[CIFRADO] Iniciando cifrado ASCON...\n");
                        
                        int rc = crypto_aead_encrypt(/*c=*/(unsigned char*)c_out,
                                                     /*clen=*/&clen_out,
                                                     /*m=*/(const unsigned char*)m_in,
                                                     /*mlen=*/(unsigned long long)in_payload_len,
                                                     /*ad=*/(const unsigned char*)aad,
                                                     /*adlen=*/(unsigned long long)aad_len,
                                                     /*nsec=*/nullptr,
                                                     /*npub=*/(const unsigned char*)npub,
                                                     /*k=*/(const unsigned char*)g_ascon_ctx.key);
                        
                        printf("[CIFRADO] ASCON resultado: rc=%d, clen_out=%llu, esperado=%u\n", 
                               rc, clen_out, in_payload_len + CRYPTO_ABYTES);
                        
                        if (rc == 0 && clen_out == (unsigned long long)(in_payload_len + CRYPTO_ABYTES)) {
                            printf("[CIFRADO] ¡Cifrado exitoso!\n");
                            
                            // Mostrar payload cifrado
                            printf("[CIFRADO] Payload cifrado (%llu bytes): ", clen_out);
                            for(uint8_t i = 0; i < clen_out && i < 16; i++) {
                                printf("%02X ", c_out[i]);
                            }
                            if(clen_out > 16) printf("...");
                            printf("\n");
                            
                            // Recalcular CRC sobre NUEVO payload (ciphertext) + crc_extra
                            uint16_t crc;
                            crc_init(&crc);
                            crc_accumulate_buffer(&crc, (const char*)c_out, out[1]); // out[1] = nuevo LEN
                            crc_accumulate(crc_extra, &crc);

                            printf("[CIFRADO] CRC recalculado: 0x%04X\n", crc);

                            // Escribir CRC al final
                            const uint16_t payload_end = (uint16_t)MAVLINK_V2_HDR_LEN + out[1];
                            out[payload_end + 0] = (uint8_t)(crc & 0xFF);
                            out[payload_end + 1] = (uint8_t)(crc >> 8);

                            const uint8_t out_len = (uint8_t)(payload_end + 2);
                            
                            printf("[CIFRADO] Mensaje cifrado completo: out_len=%u, payload_end=%u\n", 
                                   out_len, payload_end);

                            // **TEMPORAL**: Enviar mensaje cifrado por Canal 1 (puerto 14551) para evitar conflictos
                            printf("[CIFRADO] Enviando mensaje cifrado de %u bytes al PUERTO UDP 15550\n", out_len);
                            printf("[CIFRADO] Puerto destino: UDP directo 127.0.0.1:15550\n");
                            
                            // DEBUG: Verificar flag antes del envío
                            printf("[CIFRADO] VERIFICACION FINAL - Mensaje a enviar (primeros 10 bytes): ");
                            for(int i = 0; i < 10 && i < out_len; i++) {
                                printf("%02X ", out[i]);
                            }
                            printf("\n");
                            printf("[CIFRADO] Flag COMPAT en posición 3: 0x%02X (¿cifrado? %s)\n", 
                                   out[3], (out[3] & MAVLINK_CFLAG_ENCRYPTED) ? "SÍ" : "NO");
                            
                            // **DOBLE ENVÍO**: 
                            // 1. Enviar mensaje ORIGINAL sin cifrar al canal actual (MAVProxy)
                            // 2. Enviar mensaje CIFRADO al puerto UDP 14551
                            
                            // 1. Envío normal para MAVProxy
                            printf("[CIFRADO] Enviando mensaje NORMAL al Canal %u (MAVProxy)\n", (unsigned)chan);
                            size_t written_normal = mavlink_comm_port[chan]->write(buf, len);  // mensaje original
                            printf("[CIFRADO] Mensaje normal enviado: Written=%zu bytes\n", written_normal);
                            
                            // 2. **NUEVA ESTRATEGIA**: Crear socket UDP directo para cifrado
                            // Usar puerto 15550 (no usado por MAVProxy)
                            static int crypto_socket = -1;
                            static struct sockaddr_in crypto_addr;
                            
                            if (crypto_socket < 0) {
                                // Crear socket UDP solo una vez
                                crypto_socket = socket(AF_INET, SOCK_DGRAM, 0);
                                if (crypto_socket >= 0) {
                                    crypto_addr.sin_family = AF_INET;
                                    crypto_addr.sin_port = htons(15550);
                                    crypto_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
                                    printf("[CIFRADO] Socket UDP cifrado creado para puerto 15550\n");
                                } else {
                                    printf("[CIFRADO] ERROR: No se pudo crear socket UDP\n");
                                }
                            }
                            
                            if (crypto_socket >= 0) {
                                printf("[CIFRADO] Enviando mensaje CIFRADO al puerto UDP 15550\n");
                                ssize_t sent = sendto(crypto_socket, out, out_len, 0, 
                                                    (struct sockaddr*)&crypto_addr, sizeof(crypto_addr));
                                printf("[CIFRADO] Mensaje cifrado enviado: %zd bytes\n", sent);
                                
                                if (sent != (ssize_t)out_len) {
                                    printf("[CIFRADO] ADVERTENCIA: Envío incompleto %zd < %u\n", sent, out_len);
                                }
                            } else {
                                printf("[CIFRADO] Socket UDP no disponible - solo enviado normal\n");
                            }
                            
                            // DEBUG: Mostrar primeros bytes del mensaje cifrado
                            printf("[CIFRADO] Mensaje cifrado (primeros 20 bytes): ");
                            for(int i = 0; i < 20 && i < out_len; i++) {
                                printf("%02X ", out[i]);
                            }
                            printf("\n");
                            printf("[CIFRADO] ¡CIFRADO ASCON COMPLETADO!\n");
                            return;
                        } else {
                            printf("[CIFRADO] ERROR: Cifrado falló - rc=%d, clen_out=%llu\n", rc, clen_out);
                        }
                    } else {
                        printf("[CIFRADO] SKIP: msgid=%u no encontrado en tabla\n", msgid);
                    }
                } else {
                    printf("[CIFRADO] SKIP: Payload muy grande - %u + %u > 255\n", 
                           in_payload_len, CRYPTO_ABYTES);
                }
            } else {
                printf("[CIFRADO] SKIP: Frame firmado\n");
            }
        } else {
            printf("[CIFRADO] SKIP: Mensaje incompleto - len=%u < expected=%u\n", len, expected_len);
        }
    } else {
        if (len > 0) {
            printf("[CIFRADO] SKIP: No es MAVLink v2 - len=%u, buf[0]=0x%02X\n", len, buf[0]);
        }
    }

    // Fallback: enviar sin cifrar
    printf("[CIFRADO] Enviando mensaje SIN cifrar (%u bytes)\n", len);
    const size_t written = mavlink_comm_port[chan]->write(buf, len);
#if CONFIG_HAL_BOARD == HAL_BOARD_SITL
    if (written < len && !mavlink_comm_port[chan]->is_write_locked()) {
        AP_HAL::panic("Short write on UART: %lu < %u", (unsigned long)written, len);
    }
#else
    (void)written;
#endif
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
