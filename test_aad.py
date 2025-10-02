#!/usr/bin/env python3
"""
Test de AAD con/sin bit ENCRYPTED
"""

import struct
import ascon

# Configuración
key = bytes.fromhex('000102030405060708090A0B0C0D0E0F')
iv_boot = 0x1122334455667788

# Datos del mensaje del log
msgid = 264
seq = 156  
sysid = 1
compid = 1
compat_flags = 0x00

print("🧪 TEST DE AAD CON/SIN BIT ENCRYPTED")
print(f"msgid={msgid}, seq={seq}, sysid={sysid}, compid={compid}")

def build_aad(incompat_flags, compat_flags, seq, sysid, compid, msgid):
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

def build_nonce(iv_boot, sysid, compid, seq):
    npub = bytearray(16)
    npub[0:8] = struct.pack('<Q', iv_boot)  
    npub[8] = sysid
    npub[9] = compid
    npub[10] = seq
    return bytes(npub)

# Test 1: AAD CON bit ENCRYPTED (como en TX)
incompat_flags_tx = 0x02  # CON ENCRYPTED
aad_tx = build_aad(incompat_flags_tx, compat_flags, seq, sysid, compid, msgid)
nonce = build_nonce(iv_boot, sysid, compid, seq)

print(f"\n1️⃣ AAD CON ENCRYPTED (TX): {aad_tx.hex().upper()}")

# Test 2: AAD SIN bit ENCRYPTED (posible RX)
incompat_flags_rx = 0x00  # SIN ENCRYPTED  
aad_rx = build_aad(incompat_flags_rx, compat_flags, seq, sysid, compid, msgid)

print(f"2️⃣ AAD SIN ENCRYPTED (RX): {aad_rx.hex().upper()}")
print(f"   AAD del log:            02009C0101080100")

print(f"\nCoincidencias:")
print(f"   TX coincide: {'✅ SÍ' if aad_tx.hex().upper() == '02009C0101080100' else '❌ NO'}")
print(f"   RX coincide: {'✅ SÍ' if aad_rx.hex().upper() == '02009C0101080100' else '❌ NO'}")

# Simular cifrado/descifrado con ambos AADs
plaintext = b"Test message 12345"
print(f"\n🔄 SIMULACIÓN CIFRADO/DESCIFRADO:")
print(f"Plaintext: {plaintext}")

# Cifrar con AAD_TX
ciphertext = ascon.encrypt(key, nonce, aad_tx, plaintext)
print(f"Cifrado con AAD_TX: {len(ciphertext)} bytes")

# Intentar descifrar con AAD_TX  
try:
    result1 = ascon.decrypt(key, nonce, aad_tx, ciphertext)
    print(f"✅ Descifrado con AAD_TX: {result1}")
except:
    print(f"❌ Descifrado con AAD_TX: FALLÓ")

# Intentar descifrar con AAD_RX
try:
    result2 = ascon.decrypt(key, nonce, aad_rx, ciphertext)
    print(f"✅ Descifrado con AAD_RX: {result2}")
except:
    print(f"❌ Descifrado con AAD_RX: FALLÓ")

print(f"\n🎯 CONCLUSIÓN:")
print(f"El firmware debe usar el MISMO AAD en cifrado y descifrado.")
print(f"Si cifra con ENCRYPTED=1, debe descifrar con ENCRYPTED=1.")