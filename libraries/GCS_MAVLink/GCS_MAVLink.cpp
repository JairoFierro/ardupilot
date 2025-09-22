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

// ASCON crypto includes
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


extern "C" {
#include "ascon/api.h"
}

//Uso ascon_ctx_t
struct ascon_ctx_t {
    uint8_t  key[CRYPTO_KEYBYTES]; // PSK 128-bit
    uint64_t iv_boot;              // cambia cada boot/rekey
};
extern ascon_ctx_t g_ascon_ctx;


// ===== MAVLink v2 constants =====
#define MAVLINK_V2_STX       0xFD
#define MAVLINK_V2_HDR_LEN   10
#define MAVLINK_V2_SIG_LEN   13
#define MAVLINK_IFLAG_SIGNED 0x01

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


        // ===== Cifrado solo para MAVLink v2 sin firma =====
    if (len >= (MAVLINK_V2_HDR_LEN + 2) && buf[0] == MAVLINK_V2_STX) {
        const uint8_t  in_payload_len = buf[1];
        const uint8_t  incompat_flags = buf[2];
        const uint8_t  compat_flags   = buf[3];
        const uint8_t  seq            = buf[4];
        const uint8_t  sysid          = buf[5];
        const uint8_t  compid         = buf[6];
        const uint32_t msgid          = (uint32_t)buf[7] | ((uint32_t)buf[8] << 8) | ((uint32_t)buf[9] << 16);

        const uint16_t plain_total_no_sig = (uint16_t)MAVLINK_V2_HDR_LEN + in_payload_len + 2; // +CRC
        const bool     signed_frame       = (incompat_flags & MAVLINK_IFLAG_SIGNED) != 0;

        // Solo tratamos frames sin firma y con longitud exacta (sin firma)
        if (!signed_frame && len == plain_total_no_sig) {

            // ¿Cabe el tag (+CRYPTO_ABYTES) en LEN (0..255)?
            if ((uint16_t)in_payload_len + CRYPTO_ABYTES <= 255) {

                // Busca crc_extra del msgid (helper de c_library_v2)
                const mavlink_msg_entry_t *entry = mavlink_get_msg_entry(msgid);
                if (entry) {
                    const uint8_t crc_extra = entry->crc_extra;

                    // Buffer de salida: header + payload_cifrado + tag + CRC
                    uint8_t out[300];
                    memcpy(out, buf, MAVLINK_V2_HDR_LEN);  // copia header
                    out[1] = in_payload_len + CRYPTO_ABYTES; // nuevo LEN

                    // AAD + Nonce
                    uint8_t aad[16];
                    const size_t aad_len = build_aad(aad, incompat_flags, compat_flags, seq, sysid, compid, msgid);

                    uint8_t npub[CRYPTO_NPUBBYTES];
                    build_nonce(npub, g_ascon_ctx.iv_boot, sysid, compid, seq);

                    // Punteros a payload
                    const uint8_t *m_in  = buf + MAVLINK_V2_HDR_LEN;     // plaintext (input)
                    uint8_t       *c_out = out + MAVLINK_V2_HDR_LEN;     // ciphertext (output)

                    // Llama a tu ASCON: c_out queda [ciphertext || tag]; clen = mlen + CRYPTO_ABYTES
                    unsigned long long clen_out = 0ULL;
                    int rc = crypto_aead_encrypt(/*c=*/(unsigned char*)c_out,
                                                 /*clen=*/&clen_out,
                                                 /*m=*/(const unsigned char*)m_in,
                                                 /*mlen=*/(unsigned long long)in_payload_len,
                                                 /*ad=*/(const unsigned char*)aad,
                                                 /*adlen=*/(unsigned long long)aad_len,
                                                 /*nsec=*/nullptr,
                                                 /*npub=*/(const unsigned char*)npub,
                                                 /*k=*/(const unsigned char*)g_ascon_ctx.key);
                    if (rc == 0 && clen_out == (unsigned long long)(in_payload_len + CRYPTO_ABYTES)) {
                        // Recalcular CRC sobre NUEVO payload (ciphertext) + crc_extra
                        uint16_t crc;
                        crc_init(&crc);
                        crc_accumulate_buffer(&crc, (const char*)c_out, out[1]); // out[1] = nuevo LEN
                        crc_accumulate(crc_extra, &crc);

                        // Escribir CRC al final
                        const uint16_t payload_end = (uint16_t)MAVLINK_V2_HDR_LEN + out[1];
                        out[payload_end + 0] = (uint8_t)(crc & 0xFF);
                        out[payload_end + 1] = (uint8_t)(crc >> 8);

                        const uint8_t out_len = (uint8_t)(payload_end + 2);

                        // Enviar frame cifrado
                        const size_t written = mavlink_comm_port[chan]->write(out, out_len);
#if CONFIG_HAL_BOARD == HAL_BOARD_SITL
                        if (written < out_len && !mavlink_comm_port[chan]->is_write_locked()) {
                            AP_HAL::panic("Short write on UART: %lu < %u", (unsigned long)written, out_len);
                        }
#endif
                        return; // listo (cifrado y enviado)
                    }
                    // si ASCON falla, hacemos fallback en claro
                }
            }
        }
    }





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
