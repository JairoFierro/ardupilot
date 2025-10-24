/*
 * Test de verificación - Generado automáticamente
 * Verifica que el código C descifre correctamente lo que Python cifró
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "ascon_crypto_helpers.h"

// Función helper para comparar bytes
bool compare_bytes(const uint8_t *a, const uint8_t *b, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (a[i] != b[i]) {
            printf("    Diferencia en byte %zu: esperado 0x%02X, obtenido 0x%02X\n", 
                   i, a[i], b[i]);
            return false;
        }
    }
    return true;
}

// Función helper para imprimir hex
void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len && i < 32; i++) {
        printf("%02X", data[i]);
    }
    if (len > 32) printf("...");
    printf(" (%zu bytes)\n", len);
}

int main() {
    printf("========================================\n");
    printf("TEST: Descifrado de vectores Python\n");
    printf("========================================\n\n");
    
    int passed = 0;
    int failed = 0;
    
    // Test 1: Mensaje corto
    {
        printf("Test 1: Mensaje corto\n");
        
        // Ciphertext generado por Python
        const uint8_t ciphertext[] = {
            0x5d, 0xbc, 0x5d, 0x5f, 0x84, 0xd5, 0x6d, 0xd4, 0x36, 0x22, 0x05, 0x33, 0xe7, 0x79, 0x06, 0x07, 0x91, 0x32, 0xc1, 0xbd, 0x0b
        };
        
        // Plaintext esperado
        const uint8_t expected[] = {
            0x48, 0x65, 0x6c, 0x6c, 0x6f
        };
        
        uint8_t plaintext[256];
        size_t plaintext_len = 0;
        
        // Descifrar
        bool success = ascon_decrypt_message(
            ciphertext, sizeof(ciphertext),
            plaintext, &plaintext_len,
            1, 1, 0
        );
        
        if (!success) {
            printf("  ✗ FALLO: Error al descifrar\n");
            failed++;
        } else if (plaintext_len != sizeof(expected)) {
            printf("  ✗ FALLO: Longitud incorrecta (esperado %zu, obtenido %zu)\n",
                   sizeof(expected), plaintext_len);
            failed++;
        } else if (!compare_bytes(plaintext, expected, plaintext_len)) {
            printf("  ✗ FALLO: El plaintext no coincide\n");
            print_hex("    Esperado", expected, sizeof(expected));
            print_hex("    Obtenido", plaintext, plaintext_len);
            failed++;
        } else {
            printf("  ✓ ÉXITO\n");
            passed++;
        }
        printf("\n");
    }
    
    // Test 2: HEARTBEAT payload
    {
        printf("Test 2: HEARTBEAT payload\n");
        
        // Ciphertext generado por Python
        const uint8_t ciphertext[] = {
            0x45, 0x6f, 0x3e, 0xf6, 0x75, 0x68, 0x28, 0x9b, 0x94, 0x45, 0x5e, 0xc6, 0x84, 0x31, 0x26, 0x7d, 0x12, 0xb0, 0xa8, 0xd8, 0x91, 0x32, 0x9b, 0x33, 0xa4
        };
        
        // Plaintext esperado
        const uint8_t expected[] = {
            0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x51, 0x03, 0x03
        };
        
        uint8_t plaintext[256];
        size_t plaintext_len = 0;
        
        // Descifrar
        bool success = ascon_decrypt_message(
            ciphertext, sizeof(ciphertext),
            plaintext, &plaintext_len,
            1, 1, 42
        );
        
        if (!success) {
            printf("  ✗ FALLO: Error al descifrar\n");
            failed++;
        } else if (plaintext_len != sizeof(expected)) {
            printf("  ✗ FALLO: Longitud incorrecta (esperado %zu, obtenido %zu)\n",
                   sizeof(expected), plaintext_len);
            failed++;
        } else if (!compare_bytes(plaintext, expected, plaintext_len)) {
            printf("  ✗ FALLO: El plaintext no coincide\n");
            print_hex("    Esperado", expected, sizeof(expected));
            print_hex("    Obtenido", plaintext, plaintext_len);
            failed++;
        } else {
            printf("  ✓ ÉXITO\n");
            passed++;
        }
        printf("\n");
    }
    
    // Test 3: Comando GCS
    {
        printf("Test 3: Comando GCS\n");
        
        // Ciphertext generado por Python
        const uint8_t ciphertext[] = {
            0x0e, 0x81, 0x6e, 0xcb, 0x17, 0xd1, 0x34, 0x93, 0x8b, 0xac, 0x0e, 0x0d, 0xe7, 0x7f, 0xc6, 0x00, 0x8f, 0x1d, 0x75, 0x96, 0x67, 0xbc, 0xa4, 0x76, 0x66, 0xf2, 0x0e, 0x48, 0x1b, 0x09, 0x83, 0x99, 0x2f, 0xdd, 0x68, 0x52, 0x58, 0x06, 0xd6, 0x14, 0x2a, 0xdb, 0x87, 0x36, 0x47, 0x09, 0x7d, 0x4e, 0x70, 0x7f, 0x3a
        };
        
        // Plaintext esperado
        const uint8_t expected[] = {
            0x43, 0x4f, 0x4d, 0x4d, 0x41, 0x4e, 0x44, 0x5f, 0x4c, 0x4f, 0x4e, 0x47, 0x5f, 0x50, 0x41, 0x59, 0x4c, 0x4f, 0x41, 0x44, 0x5f, 0x48, 0x45, 0x52, 0x45, 0x5f, 0x33, 0x32, 0x42, 0x59, 0x54, 0x45, 0x53, 0x21, 0x21
        };
        
        uint8_t plaintext[256];
        size_t plaintext_len = 0;
        
        // Descifrar
        bool success = ascon_decrypt_message(
            ciphertext, sizeof(ciphertext),
            plaintext, &plaintext_len,
            255, 190, 128
        );
        
        if (!success) {
            printf("  ✗ FALLO: Error al descifrar\n");
            failed++;
        } else if (plaintext_len != sizeof(expected)) {
            printf("  ✗ FALLO: Longitud incorrecta (esperado %zu, obtenido %zu)\n",
                   sizeof(expected), plaintext_len);
            failed++;
        } else if (!compare_bytes(plaintext, expected, plaintext_len)) {
            printf("  ✗ FALLO: El plaintext no coincide\n");
            print_hex("    Esperado", expected, sizeof(expected));
            print_hex("    Obtenido", plaintext, plaintext_len);
            failed++;
        } else {
            printf("  ✓ ÉXITO\n");
            passed++;
        }
        printf("\n");
    }
    
    printf("========================================\n");
    printf("RESUMEN: %d pasados, %d fallidos\n", passed, failed);
    printf("========================================\n");
    
    return (failed == 0) ? 0 : 1;
}
