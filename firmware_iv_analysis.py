#!/usr/bin/env python3
"""
Calcular el IV exacto de ASCON-128a del firmware ArduPilot
"""

# Constantes del firmware (constants.h)
ASCON_AEAD_VARIANT = 1
ASCON_PA_ROUNDS = 12
ASCON_128A_PB_ROUNDS = 8
ASCON_TAG_SIZE = 16
ASCON_128A_RATE = 16

# Calcular ASCON_128A_IV según el firmware
# #define ASCON_128A_IV
#   (((uint64_t)(ASCON_AEAD_VARIANT) << 0) |
#    ((uint64_t)(ASCON_PA_ROUNDS) << 16) |
#    ((uint64_t)(ASCON_128A_PB_ROUNDS) << 20) |
#    ((uint64_t)(ASCON_TAG_SIZE * 8) << 24) |
#    ((uint64_t)(ASCON_128A_RATE) << 40))

ascon_128a_iv = (
    (ASCON_AEAD_VARIANT << 0) |
    (ASCON_PA_ROUNDS << 16) |
    (ASCON_128A_PB_ROUNDS << 20) |
    ((ASCON_TAG_SIZE * 8) << 24) |
    (ASCON_128A_RATE << 40)
)

print(f"🔍 CÁLCULO DEL IV ASCON-128A DEL FIRMWARE:")
print(f"ASCON_AEAD_VARIANT = {ASCON_AEAD_VARIANT}")
print(f"ASCON_PA_ROUNDS = {ASCON_PA_ROUNDS}")
print(f"ASCON_128A_PB_ROUNDS = {ASCON_128A_PB_ROUNDS}")
print(f"ASCON_TAG_SIZE = {ASCON_TAG_SIZE}")
print(f"ASCON_128A_RATE = {ASCON_128A_RATE}")

print(f"\n📊 COMPONENTES DEL IV:")
print(f"ASCON_AEAD_VARIANT << 0  = 0x{ASCON_AEAD_VARIANT << 0:016X}")
print(f"ASCON_PA_ROUNDS << 16    = 0x{ASCON_PA_ROUNDS << 16:016X}")
print(f"ASCON_128A_PB_ROUNDS << 20 = 0x{ASCON_128A_PB_ROUNDS << 20:016X}")
print(f"(ASCON_TAG_SIZE * 8) << 24 = 0x{(ASCON_TAG_SIZE * 8) << 24:016X}")
print(f"ASCON_128A_RATE << 40    = 0x{ASCON_128A_RATE << 40:016X}")

print(f"\n🎯 ASCON_128A_IV = 0x{ascon_128a_iv:016X}")
print(f"ASCON_128A_IV (decimal) = {ascon_128a_iv}")

# Convertir a bytes para comparar
iv_bytes = ascon_128a_iv.to_bytes(8, byteorder='little')
print(f"ASCON_128A_IV (bytes LE) = {iv_bytes.hex().upper()}")

# El problema: la librería Python 'ascon' usa su propio IV predefinido
# que es diferente al del firmware ArduPilot
print(f"\n❌ PROBLEMA IDENTIFICADO:")
print(f"1. El firmware ArduPilot usa IV personalizado = 0x{ascon_128a_iv:016X}")
print(f"2. La librería Python 'ascon' usa IV estándar (diferente)")
print(f"3. Por eso fallan todos los descifrados")

print(f"\n💡 SOLUCIONES POSIBLES:")
print(f"1. Implementar ASCON-128a desde cero en Python con el IV del firmware")
print(f"2. Modificar la librería 'ascon' para usar el IV personalizado")
print(f"3. Usar otra librería ASCON que permita IV personalizado")
print(f"4. Contactar con los desarrolladores de la librería 'ascon'")

print(f"\n🔧 PRÓXIMOS PASOS:")
print(f"Verificar si existe alguna librería ASCON más flexible...")