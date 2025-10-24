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
            0xd3, 0xa7, 0xbb, 0x4b, 0x1b, 0x39, 0xf6, 0x48, 0xc9, 0x37, 0x94, 0xdf, 0x79, 0xc0, 0xae, 0xd7, 0x9f, 0x87, 0xea, 0x96, 0x71
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
            0x1a, 0x70, 0x3e, 0x88, 0x59, 0xbd, 0x5e, 0xdd, 0xbc, 0xba, 0x57, 0x28, 0xb0, 0x2f, 0xbe, 0x22, 0xfc, 0x52, 0x1c, 0xdf, 0x93, 0x12, 0x05, 0xda, 0x6f
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
            0x1a, 0x49, 0x91, 0x16, 0xda, 0x1d, 0xe4, 0x1a, 0xdd, 0xcf, 0xde, 0xa8, 0x01, 0x74, 0xfb, 0xd4, 0xa0, 0x83, 0x88, 0xac, 0x26, 0xb8, 0xdc, 0x0a, 0xc4, 0x25, 0x87, 0x2e, 0x46, 0x6d, 0xc0, 0x82, 0x7e, 0xe1, 0xd7, 0xeb, 0x5c, 0xb1, 0xe9, 0xef, 0xc9, 0x34, 0x4b, 0x84, 0x22, 0x18, 0x79, 0x7c, 0x69, 0x8c, 0xcc
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
