#!/usr/bin/env python3
"""
Test de endianness para iv_boot
"""

import struct

iv_boot = 0x1122334455667788

print("🔍 ANÁLISIS DE ENDIANNESS:")
print(f"iv_boot = 0x{iv_boot:016X}")

# Método 1: Little-endian (lo que estoy usando)
method1 = struct.pack('<Q', iv_boot)
print(f"Método 1 (little-endian): {method1.hex().upper()}")

# Método 2: Big-endian 
method2 = struct.pack('>Q', iv_boot)
print(f"Método 2 (big-endian):    {method2.hex().upper()}")

# Método 3: Native endianness (lo que hace el firmware con memcpy)
method3 = struct.pack('Q', iv_boot)
print(f"Método 3 (native):        {method3.hex().upper()}")

print(f"\nNonce esperado del log: 887766554433221101019C0000000000")
print(f"Primeros 8 bytes:       8877665544332211")

print(f"\n🎯 ANÁLISIS:")
print(f"Method 1 coincide: {'✅ SÍ' if method1.hex().upper() == '8877665544332211' else '❌ NO'}")
print(f"Method 2 coincide: {'✅ SÍ' if method2.hex().upper() == '8877665544332211' else '❌ NO'}")
print(f"Method 3 coincide: {'✅ SÍ' if method3.hex().upper() == '8877665544332211' else '❌ NO'}")

# Verificar la endianness del sistema
import sys
print(f"\nSistema: {sys.byteorder}-endian")