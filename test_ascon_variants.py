#!/usr/bin/env python3
"""
Test de variantes ASCON - Verificar compatibilidad con firmware
"""

import ascon

# Datos de prueba
key = bytes.fromhex('000102030405060708090A0B0C0D0E0F')
nonce = bytes.fromhex('887766554433221101019C0000000000')
aad = bytes.fromhex('02009C0101080100')
plaintext = b"Hello ASCON test!"

print("🔍 PROBANDO DIFERENTES VARIANTES DE ASCON:")
print(f"Key: {key.hex().upper()}")
print(f"Nonce: {nonce.hex().upper()}")
print(f"AAD: {aad.hex().upper()}")
print(f"Plaintext: {plaintext}")

# Test 1: ASCON default (probablemente ASCON-128)
print(f"\n1️⃣ ASCON default:")
try:
    ciphertext1 = ascon.encrypt(key, nonce, aad, plaintext)
    print(f"   Cifrado OK: {len(ciphertext1)} bytes")
    print(f"   Ciphertext: {ciphertext1.hex().upper()}")
    
    decrypted1 = ascon.decrypt(key, nonce, aad, ciphertext1)
    print(f"   Descifrado: {'✅ OK' if decrypted1 == plaintext else '❌ FAIL'}")
except Exception as e:
    print(f"   ❌ Error: {e}")

# Test 2: Verificar si hay variantes específicas
print(f"\n2️⃣ VERIFICAR VARIANTES DISPONIBLES:")
print(f"   Módulo ascon: {ascon}")
print(f"   Atributos: {dir(ascon)}")

# Test 3: Verificar documentación/versión
try:
    if hasattr(ascon, '__version__'):
        print(f"   Versión: {ascon.__version__}")
    if hasattr(ascon, '__doc__'):
        print(f"   Doc: {ascon.__doc__}")
except:
    pass

# Test 4: Probar si hay diferentes algoritmos
algorithms_to_test = ['encrypt', 'ascon128_encrypt', 'ascon128a_encrypt', 'aead_encrypt']
for algo in algorithms_to_test:
    if hasattr(ascon, algo):
        print(f"   ✅ Disponible: {algo}")
    else:
        print(f"   ❌ No disponible: {algo}")

print(f"\n🎯 RESULTADO:")
print(f"El firmware usa ASCON-128a (ASCON_128A_IV).")
print(f"Verificar que la librería Python use la misma variante.")