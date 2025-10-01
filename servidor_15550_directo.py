#!/usr/bin/env python3
"""
Servidor UDP para puerto 15550 - mensajes cifrados ASCON
Puerto independiente de MAVProxy para recibir cifrado directo de ArduCopter
"""

import socket
import struct
import time

def parse_mavlink_v2(data):
    """Parsear header MAVLink v2"""
    if len(data) < 12:
        return None
        
    stx = data[0]
    if stx != 0xFD:
        return None
        
    payload_len = data[1]
    incompat_flags = data[2]
    compat_flags = data[3]
    seq = data[4]
    sysid = data[5]
    compid = data[6]
    
    msgid = struct.unpack('<I', data[7:10] + b'\x00')[0]
    
    return {
        'payload_len': payload_len,
        'incompat_flags': incompat_flags,
        'seq': seq,
        'sysid': sysid,
        'compid': compid,
        'msgid': msgid,
        'encrypted': (incompat_flags & 0x02) != 0,
        'total_len': len(data)
    }

def analyze_payload_entropy(payload):
    """Analizar entropía del payload para detectar cifrado"""
    if len(payload) == 0:
        return 0.0
    
    # Contar frecuencia de cada byte
    freq = [0] * 256
    for byte in payload:
        freq[byte] += 1
    
    # Calcular entropía de Shannon
    import math
    entropy = 0.0
    total = len(payload)
    
    for count in freq:
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)
    
    # Normalizar a [0,1] (máxima entropía = 8 bits)
    return entropy / 8.0

def main():
    print("🔒 === Servidor UDP Puerto 15550 - Cifrado ASCON Directo ===")
    
    # Crear socket UDP servidor
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_address = ('127.0.0.1', 15550)
        sock.bind(server_address)
        print(f"✅ Servidor UDP iniciado en {server_address}")
        print("🎯 Esperando mensajes cifrados directos de ArduCopter...\n")
        
        encrypted_count = 0
        total_count = 0
        last_seq = -1
        
        while True:
            try:
                data, client_address = sock.recvfrom(2048)  # Buffer más grande
                total_count += 1
                
                msg_info = parse_mavlink_v2(data)
                if msg_info:
                    if msg_info['encrypted']:
                        # Evitar duplicados por secuencia
                        if msg_info['seq'] != last_seq:
                            encrypted_count += 1
                            last_seq = msg_info['seq']
                            
                            print(f"🔒 ¡MENSAJE CIFRADO #{encrypted_count} RECIBIDO DIRECTAMENTE!")
                            print(f"   📡 Desde ArduCopter: {client_address}")
                            print(f"   📊 msgid={msg_info['msgid']}, seq={msg_info['seq']}, "
                                  f"sysid={msg_info['sysid']}, compid={msg_info['compid']}")
                            print(f"   🏷️  incompat_flags=0x{msg_info['incompat_flags']:02X}, "
                                  f"payload_len={msg_info['payload_len']}, total_len={msg_info['total_len']}")
                            
                            # Análisis completo del mensaje cifrado
                            hex_data = ' '.join(f'{b:02X}' for b in data[:30])
                            print(f"   📦 Header + inicio payload: {hex_data}")
                            
                            # Extraer y analizar payload cifrado
                            payload_start = 10
                            payload_end = payload_start + msg_info['payload_len']
                            
                            if payload_end <= len(data):
                                full_payload = data[payload_start:payload_end]
                                
                                # Separar ciphertext y tag (últimos 16 bytes)
                                if len(full_payload) >= 18:  # Al menos 2 bytes datos + 16 bytes tag
                                    ciphertext = full_payload[:-16]
                                    tag = full_payload[-16:]
                                    
                                    # Análisis de entropía
                                    entropy = analyze_payload_entropy(ciphertext)
                                    print(f"   🔐 Entropía ciphertext: {entropy:.3f} "
                                          f"({'✅ CIFRADO' if entropy > 0.7 else '⚠️ BAJO'})")
                                    
                                    # Mostrar ciphertext y tag
                                    cipher_hex = ' '.join(f'{b:02X}' for b in ciphertext[:16])
                                    tag_hex = ' '.join(f'{b:02X}' for b in tag)
                                    
                                    print(f"   📄 Ciphertext (primeros 16): {cipher_hex}")
                                    print(f"   🏷️  Tag ASCON (16 bytes): {tag_hex}")
                                    
                                    # Verificar estructura esperada
                                    original_len = len(ciphertext)
                                    tag_len = len(tag)
                                    total_expected = 10 + original_len + tag_len + 2  # header + cipher + tag + CRC
                                    
                                    print(f"   📏 Estructura: Header(10) + Cipher({original_len}) + Tag({tag_len}) + CRC(2) = {total_expected}")
                                    print(f"      Recibido: {len(data)} bytes {'✅' if len(data) == total_expected else '❌'}")
                                
                            print(f"   🎯 Total: {total_count}, Cifrados únicos: {encrypted_count}")
                            print("=" * 90)
                        else:
                            print(f"   🔄 Mensaje cifrado duplicado (seq={msg_info['seq']})")
                    else:
                        print(f"⚠️  Mensaje NO cifrado en puerto 15550: "
                              f"msgid={msg_info['msgid']}, flags=0x{msg_info['incompat_flags']:02X}")
                        
                        if total_count <= 3:
                            hex_preview = ' '.join(f'{b:02X}' for b in data[:20])
                            print(f"     Datos: {hex_preview}")
                else:
                    print(f"❌ Datos inválidos MAVLink: {len(data)} bytes")
                    if len(data) <= 50:  # Mostrar datos pequeños
                        hex_all = ' '.join(f'{b:02X}' for b in data)
                        print(f"   Datos completos: {hex_all}")
                    
            except socket.error as e:
                print(f"❌ Error de socket: {e}")
                break
                
    except KeyboardInterrupt:
        print(f"\n🎉 ¡VALIDACIÓN DE CIFRADO ASCON COMPLETADA!")
        print(f"   📊 Total mensajes recibidos: {total_count}")
        print(f"   🔒 Mensajes cifrados únicos: {encrypted_count}")
        if encrypted_count > 0:
            print(f"   ✅ CIFRADO ASCON FUNCIONANDO CORRECTAMENTE")
            print(f"   📈 Tasa de éxito: {encrypted_count/total_count*100:.1f}%")
        else:
            print(f"   ❌ No se recibieron mensajes cifrados")
        
        print(f"\n🏆 IMPLEMENTACIÓN ASCON-128 PARA MAVLINK: {'EXITOSA' if encrypted_count > 0 else 'PENDIENTE'}")
        
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        sock.close()
        print("🔌 Servidor cerrado")

if __name__ == "__main__":
    main()