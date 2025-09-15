#include "api.h"  // para CRYPTO_KEYBYTES
#include "GCS_MAVLink/GCS_MAVLink.h" // si ahí declaraste el extern

ascon_ctx_t g_ascon_ctx = {
    // Clave fija de ejemplo (¡cambia esto en producción!)
    .key = {0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,
            0x08,0x09,0x0A,0x0B, 0x0C,0x0D,0x0E,0x0F},
    // iv_boot distinto en cada arranque
    .iv_boot = 0x1122334455667788ULL
};