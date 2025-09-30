#include "GCS_MAVLink.h"      
#include "GCS_MAVLink_crypt.h"
#include "ascon_ctx.h"
#include <string.h>
#include <stdio.h>

#ifdef AP_MAVLINK_ENCRYPT

extern "C" {
#include "../ascon/crypto_aead.h"
}

static inline void ascon_build_nonce(uint8_t npub[CRYPTO_NPUBBYTES],
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

static inline size_t ascon_build_aad(uint8_t *aad,
                                     uint8_t incompat_flags, uint8_t compat_flags,
                                     uint8_t seq, uint8_t sysid, uint8_t compid,
                                     uint32_t msgid)
{
    size_t off = 0;
    aad[off++] = incompat_flags;
    aad[off++] = compat_flags;
    aad[off++] = seq;
    aad[off++] = sysid;
    aad[off++] = compid;
    aad[off++] = (uint8_t)(msgid & 0xFF);
    aad[off++] = (uint8_t)((msgid >> 8) & 0xFF);
    aad[off++] = (uint8_t)((msgid >> 16) & 0xFF);
    return off; // 8 bytes
}

bool ascon_decrypt_msg_payload_inplace(mavlink_message_t* msg)
{
    // Solo MAVLink v2
    if (msg->magic != 0xFD) {
        return true; // nada que hacer
    }
    // Debe haber al menos el tag
    if (msg->len < CRYPTO_ABYTES) {
        return false;
    }

    printf("[DESCIFRADO] Iniciando descifrado - msgid=%u, len=%u\n", msg->msgid, msg->len);
    printf("[DESCIFRADO] sysid=%u, compid=%u, seq=%u\n", msg->sysid, msg->compid, msg->seq);
    printf("[DESCIFRADO] incompat_flags=0x%02X, compat_flags=0x%02X\n", msg->incompat_flags, msg->compat_flags);

    // (opcional) filtra por msg->msgid si NO cifras todo
    // if (!should_decrypt(msg->msgid)) return true;

    // Construir AAD y Nonce como en TX
    uint8_t aad[16];
    const size_t aad_len = ascon_build_aad(
        aad,
        msg->incompat_flags,
        msg->compat_flags,
        msg->seq,
        msg->sysid,
        msg->compid,
        msg->msgid
    );

    printf("[DESCIFRADO] AAD (%zu bytes): ", aad_len);
    for(size_t i = 0; i < aad_len && i < 16; i++) {
        printf("%02X ", aad[i]);
    }
    printf("\n");

    uint8_t npub[CRYPTO_NPUBBYTES];
    ascon_build_nonce(npub, g_ascon_ctx.iv_boot, msg->sysid, msg->compid, msg->seq);

    printf("[DESCIFRADO] Nonce (16 bytes): ");
    for(int i = 0; i < CRYPTO_NPUBBYTES; i++) {
        printf("%02X ", npub[i]);
    }
    printf("\n");

    printf("[DESCIFRADO] Clave (16 bytes): ");
    for(int i = 0; i < 16; i++) {
        printf("%02X ", g_ascon_ctx.key[i]);
    }
    printf("\n");

    // Punteros a payload
    uint8_t* c_in  = (uint8_t*)_MAV_PAYLOAD(msg);               // ciphertext || tag
    uint8_t* m_out = (uint8_t*)_MAV_PAYLOAD_NON_CONST(msg);     // plaintext out (mismo buffer)

    printf("[DESCIFRADO] Payload cifrado (%u bytes): ", msg->len);
    for(int i = 0; i < msg->len && i < 32; i++) {
        printf("%02X ", c_in[i]);
    }
    if(msg->len > 32) printf("...");
    printf("\n");

    unsigned long long mlen = 0ULL;
    const int rc = crypto_aead_decrypt(
        /*m=*/(unsigned char*)m_out, &mlen,
        /*nsec=*/nullptr,
        /*c=*/(const unsigned char*)c_in, (unsigned long long)msg->len,
        /*ad=*/(const unsigned char*)aad, (unsigned long long)aad_len,
        /*npub=*/(const unsigned char*)npub,
        /*k=*/(const unsigned char*)g_ascon_ctx.key
    );

    if (rc != 0) {
        // autenticidad falló
        printf("[DESCIFRADO] ERROR: Descifrado falló - rc=%d\n", rc);
        printf("[DESCIFRADO] Posibles causas:\n");
        printf("[DESCIFRADO]   - Clave incorrecta\n");
        printf("[DESCIFRADO]   - Nonce diferente\n");
        printf("[DESCIFRADO]   - AAD diferente\n");
        printf("[DESCIFRADO]   - Datos corruptos\n");
        return false;
    }

    // Ajusta longitud al claro (quita el tag)
    msg->len = (uint8_t)mlen;
    printf("[DESCIFRADO] ¡Descifrado exitoso! Nueva longitud: %u\n", msg->len);
    printf("[DESCIFRADO] Payload descifrado (%u bytes): ", msg->len);
    for(int i = 0; i < msg->len && i < 16; i++) {
        printf("%02X ", m_out[i]);
    }
    if(msg->len > 16) printf("...");
    printf("\n");
    return true;
}

#endif