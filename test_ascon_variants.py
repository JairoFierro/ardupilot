#!/usr/bin/env python3
"""
Test con ascon 0.0.9 - Verificar si soporta variantes específicas como Ascon-128a
"""

try:
    import ascon
    print("✅ ascon importado correctamente")
    print(f"   Módulo: {ascon}")
    if hasattr(ascon, '__version__'):
        print(f"   Versión: {ascon.__version__}")
    if hasattr(ascon, '__file__'):
        print(f"   Ubicación: {ascon.__file__}")
except ImportError as e:
    print(f"❌ Error importando ascon: {e}")
    print("Instala con: pip install ascon")
    exit(1)

# Verificar qué funciones están disponibles
print(f"\n🔍 FUNCIONES DISPONIBLES:")
print(f"   Atributos: {dir(ascon)}")

# Datos de prueba exactos del firmware
key = bytes.fromhex('000102030405060708090A0B0C0D0E0F')
nonce = bytes.fromhex('887766554433221101019C0000000000')
aad = bytes.fromhex('02009C0101080100')
plaintext = b"Hello Ascon test!"

print(f"\n🧪 PROBANDO DIFERENTES VARIANTES:")
print(f"Key: {key.hex().upper()}")
print(f"Nonce: {nonce.hex().upper()}")
print(f"AAD: {aad.hex().upper()}")
print(f"Plaintext: {plaintext}")

# Test 1: Sin especificar variante (default)
print(f"\n1️⃣ Sin variante (default):")
try:
    ciphertext_default = ascon.encrypt(key, nonce, aad, plaintext)
    print(f"   ✅ Cifrado OK: {len(ciphertext_default)} bytes")
    print(f"   Ciphertext: {ciphertext_default[:16].hex().upper()}...")
    
    decrypted_default = ascon.decrypt(key, nonce, aad, ciphertext_default)
    if decrypted_default == plaintext:
        print(f"   ✅ Descifrado OK")
    else:
        print(f"   ❌ Descifrado FAIL")
        
except Exception as e:
    print(f"   ❌ Error: {e}")

# Test 2: Probar si soporta parámetro variant
print(f"\n2️⃣ Probando parámetro 'variant':")

# Verificar la signatura de la función encrypt
import inspect
try:
    sig = inspect.signature(ascon.encrypt)
    print(f"   Signatura encrypt: {sig}")
    
    # Verificar si tiene parámetro variant
    if 'variant' in sig.parameters:
        print(f"   ✅ Parámetro 'variant' disponible")
        
        # Probar diferentes variantes
        variants_to_test = ["Ascon-128", "Ascon-128a", "Ascon-80pq"]
        
        for variant in variants_to_test:
            print(f"\n   🔧 Probando {variant}:")
            try:
                ciphertext_var = ascon.encrypt(key, nonce, aad, plaintext, variant=variant)
                print(f"      ✅ Cifrado OK: {len(ciphertext_var)} bytes")
                print(f"      Ciphertext: {ciphertext_var[:16].hex().upper()}...")
                
                decrypted_var = ascon.decrypt(key, nonce, aad, ciphertext_var, variant=variant)
                if decrypted_var == plaintext:
                    print(f"      ✅ Descifrado OK")
                    
                    # Comparar con default
                    if variant == "Ascon-128a":
                        print(f"      🎯 ASCON-128a (firmware): {'✅ DISPONIBLE' if True else '❌ NO DISPONIBLE'}")
                else:
                    print(f"      ❌ Descifrado FAIL")
                    
            except Exception as e:
                print(f"      ❌ Error con {variant}: {e}")
    else:
        print(f"   ❌ Parámetro 'variant' NO disponible")
        print(f"   Esta versión no soporta variantes específicas")
        
except Exception as e:
    print(f"   ❌ Error inspeccionando función: {e}")

# Test 3: Verificar si hay diferentes funciones para variantes
print(f"\n3️⃣ Buscando funciones específicas de variantes:")
variant_functions = [
    'encrypt_ascon128', 'decrypt_ascon128',
    'encrypt_ascon128a', 'decrypt_ascon128a', 
    'ascon128_encrypt', 'ascon128_decrypt',
    'ascon128a_encrypt', 'ascon128a_decrypt'
]

for func_name in variant_functions:
    if hasattr(ascon, func_name):
        print(f"   ✅ Disponible: {func_name}")
    else:
        print(f"   ❌ No disponible: {func_name}")

# Test 4: Datos reales del log para validar compatibilidad
print(f"\n🎯 TEST CON DATOS REALES DEL LOG:")

# Reconstruir datos exactos del mensaje que falló
real_msgid = 264
real_seq = 156  
real_sysid = 1
real_compid = 1
real_incompat_flags = 0x02
real_compat_flags = 0x00

def build_aad_real(incompat_flags, compat_flags, seq, sysid, compid, msgid):
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

def build_nonce_real(iv_boot, sysid, compid, seq):
    import struct
    npub = bytearray(16)
    npub[0:8] = struct.pack('<Q', iv_boot)  
    npub[8] = sysid
    npub[9] = compid
    npub[10] = seq
    return bytes(npub)

real_aad = build_aad_real(real_incompat_flags, real_compat_flags, real_seq, real_sysid, real_compid, real_msgid)
real_nonce = build_nonce_real(0x1122334455667788, real_sysid, real_compid, real_seq)

print(f"AAD real: {real_aad.hex().upper()}")
print(f"Nonce real: {real_nonce.hex().upper()}")
print(f"¿Coincide con log? AAD: {'✅' if real_aad.hex().upper() == '02009C0101080100' else '❌'}")
print(f"¿Coincide con log? Nonce: {'✅' if real_nonce.hex().upper() == '887766554433221101019C0000000000' else '❌'}")

# Test final con datos reales
test_payload = b"Test MAVLink payload..."
print(f"\nPayload de prueba: {test_payload}")

try:
    # Probar con parámetro variant si está disponible
    if 'variant' in inspect.signature(ascon.encrypt).parameters:
        print(f"\n🔬 Probando Ascon-128a con datos reales:")
        real_ciphertext = ascon.encrypt(key, real_nonce, real_aad, test_payload, variant="Ascon-128a")
        print(f"   ✅ Cifrado OK: {real_ciphertext.hex().upper()}")
        
        real_decrypted = ascon.decrypt(key, real_nonce, real_aad, real_ciphertext, variant="Ascon-128a")
        print(f"   Descifrado: {'✅ PERFECTO' if real_decrypted == test_payload else '❌ FALLÓ'}")
    else:
        print(f"\n🔬 Probando con variante default:")
        real_ciphertext = ascon.encrypt(key, real_nonce, real_aad, test_payload)
        print(f"   ✅ Cifrado OK: {real_ciphertext.hex().upper()}")
        
        real_decrypted = ascon.decrypt(key, real_nonce, real_aad, real_ciphertext)
        print(f"   Descifrado: {'✅ OK' if real_decrypted == test_payload else '❌ FALLÓ'}")
        
except Exception as e:
    print(f"   ❌ Error: {e}")

print(f"\n🎉 RESUMEN:")
print(f"   - Si soporta variant='Ascon-128a': Usar esa variante en el bridge")
print(f"   - Si NO soporta variantes: Verificar si es compatible con firmware")
print(f"   - Si es incompatible: Usar implementación directa del firmware")