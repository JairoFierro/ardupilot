#pragma once

#include <stdint.h>

// Include ASCON API first
#ifdef __cplusplus
extern "C" {
#endif
#include "../ascon/api.h"
#ifdef __cplusplus
}
#endif

// ASCON context structure
struct ascon_ctx_t {
    uint8_t  key[CRYPTO_KEYBYTES]; // 16B
    uint64_t iv_boot;              // cambia en cada boot/rekey
};

// Global ASCON context declaration
#ifdef __cplusplus
extern "C" {
#endif
extern struct ascon_ctx_t g_ascon_ctx;
#ifdef __cplusplus
}
#endif