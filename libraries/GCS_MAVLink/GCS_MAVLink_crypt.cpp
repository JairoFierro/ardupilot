#include "GCS_MAVLink_crypt.h"
#include <string.h>
#include "ascon/api.h"
#include "ascon/crypto_aead.h"

// Contexto global (debes definirlo en algún .cpp y cargar la clave/iv_boot allí)
extern struct ascon_ctx_t {
    uint8_t  key[CRYPTO_KEYBYTES]; // 16B
    uint64_t iv_boot;              // cambia en cada boot/rekey
} g_ascon_ctx;

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

    uint8_t npub[CRYPTO_NPUBBYTES];
    ascon_build_nonce(npub, g_ascon_ctx.iv_boot, msg->sysid, msg->compid, msg->seq);

    // Punteros a payload
    uint8_t* c_in  = (uint8_t*)_MAV_PAYLOAD(msg);               // ciphertext || tag
    uint8_t* m_out = (uint8_t*)_MAV_PAYLOAD_NON_CONST(msg);     // plaintext out (mismo buffer)

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
        return false;
    }

    // Ajusta longitud al claro (quita el tag)
    msg->len = (uint8_t)mlen;
    return true;
}