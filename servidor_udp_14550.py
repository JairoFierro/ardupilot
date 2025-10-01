#!/usr/bin/env python3
"""
Servidor UDP para escuchar mensajes MAVLink en puerto 14550
Detecta mensajes cifrados con flag MAVLINK_IFLAG_ENCRYPTED (0x02)
"""

import socket
import struct
import time

def parse_mavlink_v2(data):
    """Parsear header MAVLink v2 y detectar cifrado"""
    if len(data) < 12:
        return None
        
    stx = data[0]
    if stx != 0xFD:  # No es MAVLink v2
        return None
        
    payload_len = data[1]
    incompat_flags = data[2]
    compat_flags = data[3]
    seq = data[4]
    sysid = data[5]
    compid = data[6]
    
    # Message ID (3 bytes, little endian)
    msgid = struct.unpack('<I', data[7:10] + b'\x00')[0]
    
    return {
        'payload_len': payload_len,
        'incompat_flags': incompat_flags,
        'compat_flags': compat_flags,
        'seq': seq,
        'sysid': sysid,
        'compid': compid,
        'msgid': msgid,
        'encrypted': (incompat_flags & 0x02) != 0,
        'total_len': len(data),
        'data': data
    }

def main():
    print("=== Servidor UDP para Detectar Mensajes Cifrados ASCON ===")
    print("Escuchando en puerto 14550...")
    
    # Crear socket UDP servidor
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        # Vincular al puerto 14550
        server_address = ('127.0.0.1', 14550)
        sock.bind(server_address)
        print(f"✅ Servidor UDP iniciado en {server_address}")
        print("Esperando mensajes de MAVProxy...\n")
        
        total_count = 0
        encrypted_count = 0
        last_encrypted_seq = -1
        
        while True:
            try:
                # Recibir datos
                data, client_address = sock.recvfrom(1024)
                total_count += 1
                
                # Parsear mensaje
                msg_info = parse_mavlink_v2(data)
                if msg_info:
                    if msg_info['encrypted']:
                        # Evitar duplicados por secuencia
                        if msg_info['seq'] != last_encrypted_seq:
                            encrypted_count += 1
                            last_encrypted_seq = msg_info['seq']
                            
                            print(f"🔒 MENSAJE CIFRADO #{encrypted_count} RECIBIDO!")
                            print(f"   📡 Desde: {client_address}")
                            print(f"   📊 msgid={msg_info['msgid']}, seq={msg_info['seq']}, "
                                  f"sysid={msg_info['sysid']}, compid={msg_info['compid']}")
                            print(f"   🏷️  incompat_flags=0x{msg_info['incompat_flags']:02X}, "
                                  f"payload_len={msg_info['payload_len']}, total_len={msg_info['total_len']}")
                            
                            # Mostrar primeros 30 bytes
                            hex_data = ' '.join(f'{b:02X}' for b in data[:30])
                            print(f"   📦 Primeros 30 bytes: {hex_data}")
                            
                            # Verificar si es realmente payload cifrado (debería ser no-ASCII)
                            payload_start = 10  # después del header
                            payload_end = payload_start + msg_info['payload_len']
                            if payload_end <= len(data):
                                payload = data[payload_start:payload_end]
                                non_ascii = sum(1 for b in payload if b > 127 or (b < 32 and b not in [9, 10, 13]))
                                ascii_ratio = 1.0 - (non_ascii / len(payload))
                                
                                if ascii_ratio < 0.7:  # Menos del 70% ASCII = probablemente cifrado
                                    print(f"   🔐 Payload parece cifrado (ASCII ratio: {ascii_ratio:.2f})")
                                else:
                                    print(f"   ⚠️  Payload parece texto plano (ASCII ratio: {ascii_ratio:.2f})")
                            
                            print(f"   🎯 Total: {total_count}, Cifrados: {encrypted_count}")
                            print("-" * 80)
                        else:
                            print(f"   🔄 Mensaje cifrado duplicado (seq={msg_info['seq']})")
                    else:
                        # Estadísticas cada 100 mensajes normales
                        if total_count % 100 == 0:
                            print(f"📡 {total_count} mensajes recibidos, {encrypted_count} cifrados únicos")
                            
                        # Mostrar algunos mensajes normales para debug
                        if total_count <= 5:
                            print(f"📄 Mensaje normal #{total_count}: msgid={msg_info['msgid']}, "
                                  f"flags=0x{msg_info['incompat_flags']:02X}, len={msg_info['total_len']}")
                else:
                    print(f"❓ Datos recibidos pero no es MAVLink v2 válido: {len(data)} bytes")
                    
            except socket.error as e:
                print(f"❌ Error de socket: {e}")
                break
                
    except KeyboardInterrupt:
        print(f"\n🎉 Servidor detenido:")
        print(f"   📊 Total mensajes recibidos: {total_count}")
        print(f"   🔒 Mensajes cifrados únicos: {encrypted_count}")
        if total_count > 0:
            print(f"   📈 Porcentaje cifrado: {encrypted_count/total_count*100:.2f}%")
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        sock.close()
        print("🔌 Socket cerrado")

if __name__ == "__main__":
    main()