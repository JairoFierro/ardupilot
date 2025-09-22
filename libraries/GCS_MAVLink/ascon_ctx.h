#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "ascon/api.h"

// ASCON context structure
struct ascon_ctx_t {
    uint8_t  key[CRYPTO_KEYBYTES]; // 16B
    uint64_t iv_boot;              // cambia en cada boot/rekey
};

// Global ASCON context
extern struct ascon_ctx_t g_ascon_ctx;

#ifdef __cplusplus
}
#endif