/*
 * ASCON-128 Crypto Helpers para ArduPilot
 * Traducción del código Python GCS con soporte ASCON-128
 */

#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "crypto_aead.h"  // De la librería ASCON oficial

// Misma clave e IV que en Python
static const uint8_t ASCON_KEY[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

static const uint64_t IV_BOOT = 0x1122334455667788ULL;

#define ASCON_NONCE_SIZE 16
#define CRYPTO_ABYTES 16  // Tag size para ASCON-128

/**
 * Construye nonce de 16 bytes como en Python
 * Formato: [iv_boot (8 bytes BE)] [sysid] [compid] [seq] [padding 5 bytes]
 * 
 * @param nonce: buffer de salida (debe ser al menos 16 bytes)
 * @param iv_boot: IV de arranque (64 bits)
 * @param sysid: System ID
 * @param compid: Component ID
 * @param seq: Número de secuencia
 */
static void construct_nonce(uint8_t *nonce, uint64_t iv_boot, uint8_t sysid, uint8_t compid, uint8_t seq)
{
    // Limpiar buffer
    memset(nonce, 0, ASCON_NONCE_SIZE);
    
    // Bytes 0-7: IV_BOOT en Big Endian
    nonce[0] = (iv_boot >> 56) & 0xFF;
    nonce[1] = (iv_boot >> 48) & 0xFF;
    nonce[2] = (iv_boot >> 40) & 0xFF;
    nonce[3] = (iv_boot >> 32) & 0xFF;
    nonce[4] = (iv_boot >> 24) & 0xFF;
    nonce[5] = (iv_boot >> 16) & 0xFF;
    nonce[6] = (iv_boot >> 8) & 0xFF;
    nonce[7] = iv_boot & 0xFF;
    
    // Bytes 8-10: sysid, compid, seq
    nonce[8] = sysid;
    nonce[9] = compid;
    nonce[10] = seq;
    
    // Bytes 11-15: quedan en cero (padding)
}

/**
 * Descifra un mensaje MAVLink recibido
 * 
 * @param ciphertext: mensaje cifrado (incluye tag de 16 bytes al final)
 * @param ciphertext_len: longitud total (payload cifrado + tag)
 * @param plaintext: buffer de salida para texto plano
 * @param plaintext_len: puntero donde se guardará la longitud del texto plano
 * @param sysid: System ID del mensaje
 * @param compid: Component ID del mensaje
 * @param seq: Número de secuencia del mensaje
 * @return: true si el descifrado fue exitoso, false en caso contrario
 */
bool ascon_decrypt_message(
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    uint8_t *plaintext,
    size_t *plaintext_len,
    uint8_t sysid,
    uint8_t compid,
    uint8_t seq)
{
    // Verificar longitud mínima (debe incluir el tag)
    if (ciphertext_len < CRYPTO_ABYTES) {
        return false;
    }
    
    // Construir nonce
    uint8_t nonce[ASCON_NONCE_SIZE];
    construct_nonce(nonce, IV_BOOT, sysid, compid, seq);
    
    // Descifrar con ASCON
    // crypto_aead_decrypt returns 0 on success, -1 on failure (tag verification)
    unsigned long long mlen = 0;
    int result = crypto_aead_decrypt(
        plaintext,              // mensaje en claro (salida)
        &mlen,                  // longitud del mensaje en claro (salida)
        NULL,                   // nsec (no usado en ASCON)
        ciphertext,             // texto cifrado + tag
        ciphertext_len,         // longitud total
        NULL,                   // associated data (vacío)
        0,                      // longitud de associated data
        nonce,                  // nonce
        ASCON_KEY               // clave
    );
    
    if (result == 0) {
        *plaintext_len = (size_t)mlen;
        return true;
    }
    
    return false;
}

/**
 * Cifra un mensaje MAVLink para enviar
 * 
 * @param plaintext: mensaje en claro
 * @param plaintext_len: longitud del mensaje en claro
 * @param ciphertext: buffer de salida (debe tener espacio para plaintext_len + CRYPTO_ABYTES)
 * @param ciphertext_len: puntero donde se guardará la longitud total (plaintext + tag)
 * @param sysid: System ID para el nonce
 * @param compid: Component ID para el nonce
 * @param seq: Número de secuencia para el nonce
 * @return: true si el cifrado fue exitoso, false en caso contrario
 */
bool ascon_encrypt_message(
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *ciphertext,
    size_t *ciphertext_len,
    uint8_t sysid,
    uint8_t compid,
    uint8_t seq)
{
    // Construir nonce
    uint8_t nonce[ASCON_NONCE_SIZE];
    construct_nonce(nonce, IV_BOOT, sysid, compid, seq);
    
    // Cifrar con ASCON
    unsigned long long clen = 0;
    int result = crypto_aead_encrypt(
        ciphertext,             // texto cifrado + tag (salida)
        &clen,                  // longitud total (salida)
        plaintext,              // mensaje en claro
        plaintext_len,          // longitud del mensaje en claro
        NULL,                   // associated data (vacío)
        0,                      // longitud de associated data
        NULL,                   // nsec (no usado)
        nonce,                  // nonce
        ASCON_KEY               // clave
    );
    
    if (result == 0) {
        *ciphertext_len = (size_t)clen;
        return true;
    }
    
    return false;
}

/**
 * Función auxiliar para imprimir el nonce en formato hex (para debug)
 */
#ifdef DEBUG_ASCON
#include <stdio.h>
void print_nonce_debug(uint8_t sysid, uint8_t compid, uint8_t seq)
{
    uint8_t nonce[ASCON_NONCE_SIZE];
    construct_nonce(nonce, IV_BOOT, sysid, compid, seq);
    
    printf("Nonce (sysid:%d compid:%d seq:%d): ", sysid, compid, seq);
    for (int i = 0; i < ASCON_NONCE_SIZE; i++) {
        printf("%02X", nonce[i]);
    }
    printf("\n");
}
#endif
