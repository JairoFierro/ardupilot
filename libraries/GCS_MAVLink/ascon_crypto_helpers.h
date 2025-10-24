/*
 * ASCON-128 Crypto Helpers - Header
 * Para integración en ArduPilot
 */

#ifndef ASCON_CRYPTO_HELPERS_H
#define ASCON_CRYPTO_HELPERS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// Tamaño del tag ASCON (Authentication tag)
#define CRYPTO_ABYTES 16

// Tamaño del nonce ASCON
#define ASCON_NONCE_SIZE 16

/**
 * Descifra un mensaje MAVLink recibido usando ASCON-128
 * 
 * El ciphertext debe incluir el tag de autenticación (16 bytes) al final.
 * El nonce se construye automáticamente usando iv_boot + sysid + compid + seq.
 * 
 * @param ciphertext: Mensaje cifrado (payload + tag de 16 bytes)
 * @param ciphertext_len: Longitud total del ciphertext (incluyendo tag)
 * @param plaintext: Buffer donde se escribirá el mensaje descifrado
 * @param plaintext_len: Puntero donde se guardará la longitud del texto plano
 * @param sysid: System ID del emisor (usado en nonce)
 * @param compid: Component ID del emisor (usado en nonce)
 * @param seq: Número de secuencia del mensaje (usado en nonce)
 * @return: true si el descifrado y verificación del tag fueron exitosos
 */
bool ascon_decrypt_message(
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    uint8_t *plaintext,
    size_t *plaintext_len,
    uint8_t sysid,
    uint8_t compid,
    uint8_t seq
);

/**
 * Cifra un mensaje MAVLink para enviar usando ASCON-128
 * 
 * Genera el ciphertext + tag de autenticación (16 bytes adicionales).
 * El nonce se construye automáticamente usando iv_boot + sysid + compid + seq.
 * 
 * @param plaintext: Mensaje en claro a cifrar
 * @param plaintext_len: Longitud del mensaje en claro
 * @param ciphertext: Buffer de salida (debe tener espacio para plaintext_len + 16 bytes)
 * @param ciphertext_len: Puntero donde se guardará la longitud total (plaintext + tag)
 * @param sysid: System ID del emisor (usado en nonce)
 * @param compid: Component ID del emisor (usado en nonce)
 * @param seq: Número de secuencia del mensaje (usado en nonce)
 * @return: true si el cifrado fue exitoso
 */
bool ascon_encrypt_message(
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *ciphertext,
    size_t *ciphertext_len,
    uint8_t sysid,
    uint8_t compid,
    uint8_t seq
);

// Función de debug (solo si DEBUG_ASCON está definido)
#ifdef DEBUG_ASCON
void print_nonce_debug(uint8_t sysid, uint8_t compid, uint8_t seq);
#endif

#endif // ASCON_CRYPTO_HELPERS_H
