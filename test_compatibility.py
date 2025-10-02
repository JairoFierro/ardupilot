#!/usr/bin/env python3
"""
Test de compatibilidad cruzada - Firmware vs Python
Comparar el output exacto del firmware con Python para identificar diferencias
"""

import ascon
import struct

print("🔍 TEST DE COMPATIBILIDAD CRUZADA")
print("Comparando firmware ASCON-128a vs Python ASCON-128a")

# Datos exactos del firmware
key = bytes.fromhex('000102030405060708090A0B0C0D0E0F')
iv_boot = 0x1122334455667788

# Datos reales del log que falló
msgid = 129
seq = 148
sysid = 1
compid = 1
incompat_flags = 0x02
compat_flags = 0x00

def build_aad_exact(incompat_flags, compat_flags, seq, sysid, compid, msgid):
    aad = bytearray(8)
    aad[0] = incompat_flags
    aad[1] = compat_flags  
    aad[2] = seq
    aad[3] = sysid
    aad[4] = compid
    aad[5] = msgid & 0xFF
    aad[6] = (msgid >> 8) & 0xFF
    aad[7] = (msgid >> 16) & 0xFF
    return bytes(aad)

def build_nonce_exact(iv_boot, sysid, compid, seq):
    npub = bytearray(16)
    npub[0:8] = struct.pack('<Q', iv_boot)  
    npub[8] = sysid
    npub[9] = compid
    npub[10] = seq
    return bytes(npub)

aad = build_aad_exact(incompat_flags, compat_flags, seq, sysid, compid, msgid)
nonce = build_nonce_exact(iv_boot, sysid, compid, seq)

print(f"\n📋 DATOS DEL TEST:")
print(f"msgid={msgid}, seq={seq}, sysid={sysid}, compid={compid}")
print(f"Key: {key.hex().upper()}")
print(f"AAD: {aad.hex().upper()}")
print(f"Nonce: {nonce.hex().upper()}")

# Verificar que coinciden con el log
expected_aad = "0200940101810000"
expected_nonce = "88776655443322110101940000000000"

print(f"\n✅ Verificación con log:")
print(f"AAD calculado:  {aad.hex().upper()}")
print(f"AAD esperado:   {expected_aad.upper()}")
print(f"AAD coincide:   {'✅ SÍ' if aad.hex().upper() == expected_aad.upper() else '❌ NO'}")

print(f"Nonce calculado: {nonce.hex().upper()}")
print(f"Nonce esperado:  {expected_nonce.upper()}")
print(f"Nonce coincide:  {'✅ SÍ' if nonce.hex().upper() == expected_nonce.upper() else '❌ NO'}")

# Test con diferentes payloads para ver patrones
test_payloads = [
    b"A",                    # 1 byte
    b"AB",                   # 2 bytes  
    b"ABCD",                 # 4 bytes
    b"ABCDEFGH",             # 8 bytes
    b"ABCDEFGHIJKLMNOP",     # 16 bytes
    b"Hello World Test!",    # 18 bytes
    b"1234567890" * 2,       # 20 bytes
    b"Test MAVLink payload data for compatibility check"  # 47 bytes
]

print(f"\n🧪 PROBANDO DIFERENTES VARIANTES DE ASCON:")

variants = ["Ascon-128", "Ascon-128a", "Ascon-80pq"]
for variant in variants:
    print(f"\n🔧 Variante: {variant}")
    
    for i, payload in enumerate(test_payloads[:3]):  # Solo los primeros 3 para no saturar
        try:
            # Cifrar
            ciphertext = ascon.encrypt(key, nonce, aad, payload, variant=variant)
            
            # Descifrar
            decrypted = ascon.decrypt(key, nonce, aad, ciphertext, variant=variant)
            
            success = "✅" if decrypted == payload else "❌"
            print(f"   Payload {len(payload):2d}B: {success} Ciphertext: {ciphertext[:8].hex().upper()}...")
            
        except Exception as e:
            print(f"   Payload {len(payload):2d}B: ❌ Error: {e}")

# Test específico: reproducir el ciphertext del log
print(f"\n🎯 REPRODUCIR CIPHERTEXT DEL LOG:")
real_ciphertext_start = "F6445A0D1ACC2AC27FB4B119A80FF395"
print(f"Ciphertext del log (primeros 16 bytes): {real_ciphertext_start}")

# Probar con diferentes payloads para ver si alguno produce el mismo ciphertext
print(f"\n🔍 Buscando payload que produzca el mismo ciphertext...")

# El payload cifrado tenía longitud 38 bytes total (22 bytes de payload + 16 bytes de tag)
expected_payload_len = 38 - 16  # 22 bytes

test_payloads_22b = [
    b"A" * 22,
    b"1234567890123456789012",
    bytes(range(22)),
    b"TEST_MAVLINK_PAYLOAD_22",
    bytes([0x00] * 22),
    bytes([0xFF] * 22),
]

for variant in ["Ascon-128a"]:  # Solo probar con la variante del firmware
    print(f"\n🔬 Probando {variant} con payloads de 22 bytes:")
    
    for i, payload in enumerate(test_payloads_22b):
        try:
            ciphertext = ascon.encrypt(key, nonce, aad, payload, variant=variant)
            ciphertext_start = ciphertext[:16].hex().upper()
            
            match = "🎯 MATCH!" if ciphertext_start == real_ciphertext_start else ""
            print(f"   Test {i+1}: {ciphertext_start} {match}")
            
            if match:
                print(f"      ¡Payload encontrado!: {payload}")
                # Verificar descifrado
                decrypted = ascon.decrypt(key, nonce, aad, ciphertext, variant=variant)
                print(f"      Descifrado: {'✅ OK' if decrypted == payload else '❌ FAIL'}")
                
        except Exception as e:
            print(f"   Test {i+1}: ❌ Error: {e}")

print(f"\n🎉 CONCLUSIONES:")
print(f"1. Si ningún test produce el ciphertext del log → Hay diferencia en la implementación")
print(f"2. Si algún test coincide → Identificamos el payload original")
print(f"3. Verificar si el firmware usa parámetros diferentes (IV, padding, etc.)")