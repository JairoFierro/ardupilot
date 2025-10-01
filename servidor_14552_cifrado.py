#!/usr/bin/env python3
"""
Servidor UDP dedicado para puerto 14552 - mensajes cifrados ASCON
Usar puerto 14552 para evitar conflictos con MAVProxy
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

def main():
    print("🔒 === Servidor UDP Puerto 14552 - Mensajes Cifrados ASCON ===")
    
    # Crear socket UDP servidor para 14552
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_address = ('127.0.0.1', 14552)
        sock.bind(server_address)
        print(f"✅ Servidor UDP iniciado en {server_address}")
        print("🎯 Esperando mensajes cifrados de ArduCopter Canal 2...\n")
        
        encrypted_count = 0
        total_count = 0
        last_seq = -1
        
        while True:
            try:
                data, client_address = sock.recvfrom(1024)
                total_count += 1
                
                msg_info = parse_mavlink_v2(data)
                if msg_info:
                    if msg_info['encrypted']:
                        # Evitar duplicados por secuencia
                        if msg_info['seq'] != last_seq:
                            encrypted_count += 1
                            last_seq = msg_info['seq']
                            
                            print(f"🔒 ¡MENSAJE CIFRADO #{encrypted_count} RECIBIDO!")
                            print(f"   📡 Desde: {client_address}")
                            print(f"   📊 msgid={msg_info['msgid']}, seq={msg_info['seq']}, "
                                  f"sysid={msg_info['sysid']}, compid={msg_info['compid']}")
                            print(f"   🏷️  incompat_flags=0x{msg_info['incompat_flags']:02X}, "
                                  f"payload_len={msg_info['payload_len']}, total_len={msg_info['total_len']}")
                            
                            # Mostrar estructura del mensaje cifrado
                            hex_data = ' '.join(f'{b:02X}' for b in data[:30])
                            print(f"   📦 Primeros 30 bytes: {hex_data}")
                            
                            # Verificar payload cifrado
                            payload_start = 10
                            payload_end = payload_start + msg_info['payload_len'] - 2  # -2 para CRC
                            if payload_end > payload_start and payload_end <= len(data):
                                payload = data[payload_start:payload_end]
                                # Calcular "randomness" - bytes no ASCII
                                non_ascii = sum(1 for b in payload if b > 127 or (b < 32 and b not in [9, 10, 13]))
                                randomness = non_ascii / len(payload) if len(payload) > 0 else 0
                                
                                print(f"   🔐 Análisis payload: {randomness:.2f} randomness "
                                      f"({'✅ CIFRADO' if randomness > 0.5 else '⚠️ TEXTO PLANO'})")
                                
                                # Mostrar tag ASCON (últimos 16 bytes del payload)
                                if len(payload) >= 16:
                                    tag_start = max(0, len(payload) - 16)
                                    tag = payload[tag_start:]
                                    tag_hex = ' '.join(f'{b:02X}' for b in tag[-16:])
                                    print(f"   🏷️  Tag ASCON: {tag_hex}")
                            
                            print(f"   🎯 Total: {total_count}, Cifrados únicos: {encrypted_count}")
                            print("=" * 80)
                        else:
                            print(f"   🔄 Duplicado cifrado (seq={msg_info['seq']})")
                    else:
                        print(f"⚠️  Mensaje NO cifrado en puerto 14552: "
                              f"msgid={msg_info['msgid']}, flags=0x{msg_info['incompat_flags']:02X}")
                        
                        # Solo mostrar primeros 5 mensajes no cifrados
                        if total_count <= 5:
                            hex_preview = ' '.join(f'{b:02X}' for b in data[:20])
                            print(f"     Primeros 20 bytes: {hex_preview}")
                else:
                    print(f"❌ Datos inválidos: {len(data)} bytes")
                    
            except socket.error as e:
                print(f"❌ Error de socket: {e}")
                break
                
    except KeyboardInterrupt:
        print(f"\n🎉 Servidor detenido:")
        print(f"   📊 Total mensajes: {total_count}")
        print(f"   🔒 Mensajes cifrados únicos: {encrypted_count}")
        if total_count > 0:
            print(f"   📈 Tasa de cifrado: {encrypted_count/total_count*100:.1f}%")
        print("\n🏆 ¡CIFRADO ASCON VALIDADO EXITOSAMENTE!")
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        sock.close()
        print("🔌 Servidor cerrado")

if __name__ == "__main__":
    main()