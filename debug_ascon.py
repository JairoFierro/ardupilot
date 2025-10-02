#!/usr/bin/env python3
"""
Script de debugging para ASCON - Comparar con firmware
"""

import struct
import os

try:
    import ascon
    print("✅ ascon importado correctamente")
except ImportError as e:
    print(f"❌ Error con ascon: {e}")
    exit(1)

# Configuración del firmware (exacta)
FIRMWARE_KEY = bytes.fromhex('000102030405060708090A0B0C0D0E0F')
FIRMWARE_IV_BOOT = 0x1122334455667788

print("🔧 CONFIGURACIÓN DEL FIRMWARE:")
print(f"   Key: {FIRMWARE_KEY.hex().upper()}")
print(f"   IV Boot: 0x{FIRMWARE_IV_BOOT:016X}")

# Datos de ejemplo del log (uno de los mensajes que falló)
# msgid=264, seq=156, sysid=1, compid=1
test_msgid = 264
test_seq = 156  
test_sysid = 1
test_compid = 1
test_incompat_flags = 0x02  # Con ENCRYPTED
test_compat_flags = 0x00

print(f"\n🧪 PROBANDO CON DATOS DEL LOG:")
print(f"   msgid={test_msgid}, seq={test_seq}, sysid={test_sysid}, compid={test_compid}")

# Función para construir AAD exactamente como el firmware
def build_aad_firmware(incompat_flags, compat_flags, seq, sysid, compid, msgid):
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

# Función para construir nonce exactamente como el firmware
def build_nonce_firmware(iv_boot, sysid, compid, seq):
    npub = bytearray(16)
    # iv_boot como little-endian (8 bytes) - IGUAL que en firmware
    npub[0:8] = struct.pack('<Q', iv_boot)  
    npub[8] = sysid
    npub[9] = compid
    npub[10] = seq
    # npub[11:16] quedan en 0
    return bytes(npub)

# Construir AAD y nonce
aad = build_aad_firmware(test_incompat_flags, test_compat_flags, test_seq, test_sysid, test_compid, test_msgid)
nonce = build_nonce_firmware(FIRMWARE_IV_BOOT, test_sysid, test_compid, test_seq)

print(f"\n🔧 AAD calculado: {aad.hex().upper()}")
print(f"🔧 Nonce calculado: {nonce.hex().upper()}")

# Comparar con el log
print(f"\n📋 COMPARACIÓN CON LOG:")
print(f"   AAD del log:      02009C0101080100")
print(f"   AAD calculado:    {aad.hex().upper()}")
print(f"   ¿Coinciden?       {'✅ SÍ' if aad.hex().upper() == '02009C0101080100' else '❌ NO'}")

print(f"   Nonce del log:    887766554433221101019C0000000000") 
print(f"   Nonce calculado:  {nonce.hex().upper()}")
print(f"   ¿Coinciden?       {'✅ SÍ' if nonce.hex().upper() == '887766554433221101019C0000000000' else '❌ NO'}")

# Test de cifrado/descifrado básico
test_plaintext = b"Hello World Test"
print(f"\n🧪 TEST DE CIFRADO/DESCIFRADO:")
print(f"   Plaintext: {test_plaintext}")

try:
    # Cifrar
    ciphertext_with_tag = ascon.encrypt(FIRMWARE_KEY, nonce, aad, test_plaintext)
    print(f"   Cifrado OK: {len(ciphertext_with_tag)} bytes")
    print(f"   Ciphertext+tag: {ciphertext_with_tag.hex().upper()}")
    
    # Descifrar
    decrypted = ascon.decrypt(FIRMWARE_KEY, nonce, aad, ciphertext_with_tag)
    print(f"   Descifrado OK: {decrypted}")
    print(f"   ¿Coincide? {'✅ SÍ' if decrypted == test_plaintext else '❌ NO'}")
    
except Exception as e:
    print(f"   ❌ Error: {e}")

# Probar con datos reales del log
print(f"\n🔍 PROBANDO CON CIPHERTEXT REAL DEL LOG:")
real_ciphertext = "36C911D0150DBBC258236811B74C03FE"  # Primeros 32 chars del log
print(f"   Ciphertext (parcial): {real_ciphertext}")

# Para descifrar necesitamos el ciphertext completo + tag
print(f"\n💡 NOTA: Para descifrar necesitamos el ciphertext COMPLETO (42 bytes)")
print(f"         El log solo muestra los primeros 16 bytes.")

print(f"\n🎯 CONCLUSIÓN:")
print(f"   1. Verificar que AAD y nonce coincidan exactamente")
print(f"   2. Asegurar que el ciphertext+tag esté completo") 
print(f"   3. Confirmar que la clave sea idéntica en ambos lados")