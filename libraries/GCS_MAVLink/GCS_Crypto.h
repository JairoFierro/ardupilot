// GCS_Crypto.h
#pragma once
#include <stdint.h>

#define CHACHA_KEY_LEN   32
#define CHACHA_NONCE_LEN 12
#define CHACHA_TAG_LEN   16

// Contexto compartido TX/RX
typedef struct {
    uint8_t  key[CHACHA_KEY_LEN];
    uint64_t iv_boot;
    uint32_t ctr;      // si no lo usas, igual déjalo
} chacha_ctx_t;

// Variable global compartida (declaración)
extern chacha_ctx_t g_chacha_ctx;

// Helpers compartidos (declaraciones)
uint32_t build_aad_v2(uint8_t aad[10],
                      uint8_t len_field,
                      uint8_t incompat_flags,
                      uint8_t compat_flags,
                      uint8_t seq,
                      uint8_t sysid,
                      uint8_t compid,
                      uint32_t msgid);

void build_nonce12_scq(uint8_t n[CHACHA_NONCE_LEN],
                       uint64_t iv_boot,
                       uint8_t sysid,
                       uint8_t compid,
                       uint8_t seq);

// Inicialización (clave/iv_boot)
void chacha_init_once(void);
