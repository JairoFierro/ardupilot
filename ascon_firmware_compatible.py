#!/usr/bin/env python3
"""
Implementación ASCON-128a compatible con ArduPilot firmware
Basada en el código C del firmware para garantizar 100% compatibilidad
"""

import struct

# Constantes del firmware ArduPilot (constants.h)
ASCON_AEAD_VARIANT = 1
ASCON_PA_ROUNDS = 12
ASCON_128A_PB_ROUNDS = 8
ASCON_TAG_SIZE = 16
ASCON_128A_RATE = 16
CRYPTO_KEYBYTES = 16
CRYPTO_NPUBBYTES = 16
CRYPTO_ABYTES = 16

# IV calculado del firmware
ASCON_128A_IV = 0x00001000808C0001

class AsconState:
    """Estado interno de ASCON (5 palabras de 64 bits)"""
    def __init__(self):
        self.x = [0] * 5

def loadbytes(data, offset, length):
    """Cargar bytes como uint64 little-endian"""
    if len(data) < offset + length:
        # Padding con ceros si no hay suficientes bytes
        padded = data[offset:] + b'\x00' * (length - (len(data) - offset))
        return struct.unpack('<Q', padded)[0]
    return struct.unpack('<Q', data[offset:offset+8])[0]

def storebytes(value, length):
    """Convertir uint64 a bytes little-endian"""
    return struct.pack('<Q', value)[:length]

def ror(value, n):
    """Rotate right de 64 bits"""
    value &= 0xFFFFFFFFFFFFFFFF
    return ((value >> n) | (value << (64 - n))) & 0xFFFFFFFFFFFFFFFF

def round_function(s, round_const):
    """Una ronda de la permutación ASCON"""
    # Addition of round constant
    s.x[2] ^= round_const
    
    # Substitution layer (S-box)
    s.x[0] ^= s.x[4]
    s.x[4] ^= s.x[3]
    s.x[2] ^= s.x[1]
    
    t = [0] * 5
    t[0] = s.x[0] ^ (~s.x[1] & s.x[2])
    t[1] = s.x[1] ^ (~s.x[2] & s.x[3])
    t[2] = s.x[2] ^ (~s.x[3] & s.x[4])
    t[3] = s.x[3] ^ (~s.x[4] & s.x[0])
    t[4] = s.x[4] ^ (~s.x[0] & s.x[1])
    
    t[1] ^= t[0]
    t[0] ^= t[4]
    t[3] ^= t[2]
    t[2] = ~t[2] & 0xFFFFFFFFFFFFFFFF
    
    s.x[0] = t[0]
    s.x[1] = t[1]
    s.x[2] = t[2] 
    s.x[3] = t[3]
    s.x[4] = t[4]
    
    # Linear diffusion layer
    s.x[0] ^= ror(s.x[0], 19) ^ ror(s.x[0], 28)
    s.x[1] ^= ror(s.x[1], 61) ^ ror(s.x[1], 39)
    s.x[2] ^= ror(s.x[2], 1) ^ ror(s.x[2], 6)
    s.x[3] ^= ror(s.x[3], 10) ^ ror(s.x[3], 17)
    s.x[4] ^= ror(s.x[4], 7) ^ ror(s.x[4], 41)

def permutation(s, rounds):
    """Permutación ASCON de n rondas"""
    round_constants = [
        0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87,
        0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f
    ]
    
    start = 12 - rounds
    for i in range(rounds):
        round_function(s, round_constants[start + i])

def P12(s):
    """Permutación de 12 rondas (PA)"""
    permutation(s, 12)

def P8(s):
    """Permutación de 8 rondas (PB para ASCON-128a)"""
    permutation(s, 8)

def ascon_128a_encrypt(key, nonce, associated_data, plaintext):
    """
    Cifrado ASCON-128a compatible con ArduPilot firmware
    """
    # Verificar tamaños
    if len(key) != CRYPTO_KEYBYTES:
        raise ValueError(f"Key debe tener {CRYPTO_KEYBYTES} bytes")
    if len(nonce) != CRYPTO_NPUBBYTES:
        raise ValueError(f"Nonce debe tener {CRYPTO_NPUBBYTES} bytes")
    
    # Cargar key y nonce
    K0 = loadbytes(key, 0, 8)
    K1 = loadbytes(key, 8, 8)
    N0 = loadbytes(nonce, 0, 8)
    N1 = loadbytes(nonce, 8, 8)
    
    # Inicialización
    s = AsconState()
    s.x[0] = ASCON_128A_IV
    s.x[1] = K0
    s.x[2] = K1
    s.x[3] = N0
    s.x[4] = N1
    
    P12(s)
    s.x[3] ^= K0
    s.x[4] ^= K1
    
    # Procesar associated data
    if associated_data:
        ad = associated_data
        while len(ad) >= ASCON_128A_RATE:
            s.x[0] ^= loadbytes(ad, 0, 8)
            s.x[1] ^= loadbytes(ad, 8, 8)
            P8(s)
            ad = ad[ASCON_128A_RATE:]
        
        # Último bloque de AD (con padding)
        if ad:
            ad_padded = ad + b'\x80' + b'\x00' * (ASCON_128A_RATE - len(ad) - 1)
            s.x[0] ^= loadbytes(ad_padded, 0, 8)
            s.x[1] ^= loadbytes(ad_padded, 8, 8)
            P8(s)
    
    # Separador AD/Plaintext
    s.x[4] ^= 1
    
    # Procesar plaintext
    ciphertext = bytearray()
    m = plaintext
    
    while len(m) >= ASCON_128A_RATE:
        s.x[0] ^= loadbytes(m, 0, 8)
        s.x[1] ^= loadbytes(m, 8, 8)
        ciphertext.extend(storebytes(s.x[0], 8))
        ciphertext.extend(storebytes(s.x[1], 8))
        P8(s)
        m = m[ASCON_128A_RATE:]
    
    # Último bloque de plaintext (con padding)
    if m:
        m_padded = m + b'\x80' + b'\x00' * (ASCON_128A_RATE - len(m) - 1)
        s.x[0] ^= loadbytes(m_padded, 0, 8)
        s.x[1] ^= loadbytes(m_padded, 8, 8)
        ciphertext.extend(storebytes(s.x[0], len(m)))
        if len(m) > 8:
            ciphertext.extend(storebytes(s.x[1], len(m) - 8))
    
    # Finalización
    s.x[1] ^= K0
    s.x[2] ^= K1
    P12(s)
    s.x[3] ^= K0
    s.x[4] ^= K1
    
    # Generar tag
    tag = storebytes(s.x[3], 8) + storebytes(s.x[4], 8)
    
    return bytes(ciphertext) + tag

def ascon_128a_decrypt(key, nonce, associated_data, ciphertext_with_tag):
    """
    Descifrado ASCON-128a compatible con ArduPilot firmware
    """
    # Verificar tamaños
    if len(key) != CRYPTO_KEYBYTES:
        raise ValueError(f"Key debe tener {CRYPTO_KEYBYTES} bytes")
    if len(nonce) != CRYPTO_NPUBBYTES:
        raise ValueError(f"Nonce debe tener {CRYPTO_NPUBBYTES} bytes")
    if len(ciphertext_with_tag) < CRYPTO_ABYTES:
        raise ValueError(f"Ciphertext+tag debe tener al menos {CRYPTO_ABYTES} bytes")
    
    # Separar ciphertext y tag
    ciphertext = ciphertext_with_tag[:-CRYPTO_ABYTES]
    tag = ciphertext_with_tag[-CRYPTO_ABYTES:]
    
    # Cargar key y nonce
    K0 = loadbytes(key, 0, 8)
    K1 = loadbytes(key, 8, 8)
    N0 = loadbytes(nonce, 0, 8)
    N1 = loadbytes(nonce, 8, 8)
    
    # Inicialización (igual que cifrado)
    s = AsconState()
    s.x[0] = ASCON_128A_IV
    s.x[1] = K0
    s.x[2] = K1
    s.x[3] = N0
    s.x[4] = N1
    
    P12(s)
    s.x[3] ^= K0
    s.x[4] ^= K1
    
    # Procesar associated data (igual que cifrado)
    if associated_data:
        ad = associated_data
        while len(ad) >= ASCON_128A_RATE:
            s.x[0] ^= loadbytes(ad, 0, 8)
            s.x[1] ^= loadbytes(ad, 8, 8)
            P8(s)
            ad = ad[ASCON_128A_RATE:]
        
        if ad:
            ad_padded = ad + b'\x80' + b'\x00' * (ASCON_128A_RATE - len(ad) - 1)
            s.x[0] ^= loadbytes(ad_padded, 0, 8)
            s.x[1] ^= loadbytes(ad_padded, 8, 8)
            P8(s)
    
    # Separador AD/Ciphertext
    s.x[4] ^= 1
    
    # Procesar ciphertext
    plaintext = bytearray()
    c = ciphertext
    
    while len(c) >= ASCON_128A_RATE:
        c0 = loadbytes(c, 0, 8)
        c1 = loadbytes(c, 8, 8)
        plaintext.extend(storebytes(s.x[0] ^ c0, 8))
        plaintext.extend(storebytes(s.x[1] ^ c1, 8))
        s.x[0] = c0
        s.x[1] = c1
        P8(s)
        c = c[ASCON_128A_RATE:]
    
    # Último bloque de ciphertext
    if c:
        # Descifrar parte disponible
        for i in range(len(c)):
            if i < 8:
                plaintext.append(((s.x[0] >> (8 * i)) & 0xFF) ^ c[i])
            else:
                plaintext.append(((s.x[1] >> (8 * (i - 8))) & 0xFF) ^ c[i])
        
        # Padding para el estado
        c_padded = c + b'\x80' + b'\x00' * (ASCON_128A_RATE - len(c) - 1)
        
        # Actualizar estado
        if len(c) <= 8:
            mask = (1 << (8 * len(c))) - 1
            s.x[0] = (s.x[0] & ~mask) | (loadbytes(c_padded, 0, 8) & mask)
        else:
            s.x[0] = loadbytes(c_padded, 0, 8)
            mask = (1 << (8 * (len(c) - 8))) - 1
            s.x[1] = (s.x[1] & ~mask) | (loadbytes(c_padded, 8, 8) & mask)
    
    # Finalización
    s.x[1] ^= K0
    s.x[2] ^= K1
    P12(s)
    s.x[3] ^= K0
    s.x[4] ^= K1
    
    # Verificar tag
    computed_tag = storebytes(s.x[3], 8) + storebytes(s.x[4], 8)
    
    if computed_tag != tag:
        return None  # Tag inválido
    
    return bytes(plaintext)

# Test de compatibilidad
if __name__ == "__main__":
    print("🧪 TESTING ASCON-128a ArduPilot compatible...")
    
    # Datos del firmware
    key = bytes.fromhex('000102030405060708090A0B0C0D0E0F')
    nonce = bytes.fromhex('88776655443322110101940000000000')
    aad = bytes.fromhex('0200940101810000')
    
    # Test con payload pequeño
    plaintext = b"Hello ASCON!"
    
    print(f"Key: {key.hex().upper()}")
    print(f"Nonce: {nonce.hex().upper()}")
    print(f"AAD: {aad.hex().upper()}")
    print(f"Plaintext: {plaintext}")
    
    try:
        # Cifrar
        ciphertext = ascon_128a_encrypt(key, nonce, aad, plaintext)
        print(f"Ciphertext+tag: {ciphertext.hex().upper()}")
        
        # Descifrar
        decrypted = ascon_128a_decrypt(key, nonce, aad, ciphertext)
        
        if decrypted == plaintext:
            print("✅ CIFRADO/DESCIFRADO EXITOSO")
        else:
            print("❌ ERROR: Descifrado no coincide")
            print(f"Expected: {plaintext}")
            print(f"Got: {decrypted}")
            
    except Exception as e:
        print(f"❌ ERROR: {e}")
        import traceback
        traceback.print_exc()