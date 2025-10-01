#!/usr/bin/env python3
"""
Cliente para capturar mensajes cifrados en puerto 14550
Detecta mensajes con flag MAVLINK_IFLAG_ENCRYPTED (0x02)
"""

import socket
import struct
import time

def parse_mavlink_v2(data):
    """Parsear header MAVLink v2 y detectar cifrado"""
    if len(data) < 12:
        return None
        
    # Header: STX LEN IFLAGS CFLAGS SEQ SYS COMP MSGID[3]
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
    print("=== Detector de Mensajes Cifrados ASCON en Puerto 14550 ===")
    
    # Conectar a SITL
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)
    
    sitl_address = ('127.0.0.1', 14550)
    print(f"Conectando a SITL en {sitl_address}...")
    
    # Enviar heartbeat para activar conexión
    heartbeat = bytes([
        0xFD, 0x09, 0x00, 0x00, 0x00, 0xFF, 0xBE, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x06, 0x08, 0x00, 0x03, 0x03,
        0x50, 0xC6
    ])
    
    sock.sendto(heartbeat, sitl_address)
    print("¡Conexión activada! Detectando mensajes cifrados...\n")
    
    total_count = 0
    encrypted_count = 0
    seq_heartbeat = 0
    
    try:
        while True:
            try:
                # Recibir datos
                data, addr = sock.recvfrom(1024)
                total_count += 1
                
                # Parsear mensaje
                msg_info = parse_mavlink_v2(data)
                if msg_info:
                    if msg_info['encrypted']:
                        encrypted_count += 1
                        print(f"🔒 MENSAJE CIFRADO #{encrypted_count} DETECTADO!")
                        print(f"   📊 msgid={msg_info['msgid']}, seq={msg_info['seq']}, "
                              f"sysid={msg_info['sysid']}, compid={msg_info['compid']}")
                        print(f"   🏷️  incompat_flags=0x{msg_info['incompat_flags']:02X}, "
                              f"payload_len={msg_info['payload_len']}, total_len={msg_info['total_len']}")
                        
                        # Mostrar primeros 30 bytes en hexadecimal
                        hex_data = ' '.join(f'{b:02X}' for b in data[:30])
                        print(f"   📦 Primeros 30 bytes: {hex_data}")
                        
                        # Verificar estructura: header + payload cifrado + CRC
                        expected_total = 10 + msg_info['payload_len'] + 2  # header + payload + CRC
                        if msg_info['total_len'] == expected_total:
                            print(f"   ✅ Estructura correcta: {expected_total} bytes")
                        else:
                            print(f"   ⚠️  Estructura inesperada: {msg_info['total_len']} vs {expected_total}")
                        
                        print(f"   🎯 Total mensajes: {total_count}, Cifrados: {encrypted_count}")
                        print("-" * 80)
                    else:
                        # Mostrar estadísticas cada 100 mensajes normales
                        if total_count % 100 == 0:
                            print(f"📡 {total_count} mensajes procesados, {encrypted_count} cifrados detectados")
                
                # Enviar heartbeat cada 200 mensajes para mantener conexión
                if total_count % 200 == 0:
                    seq_heartbeat = (seq_heartbeat + 1) % 256
                    heartbeat_seq = bytes([
                        0xFD, 0x09, 0x00, 0x00, seq_heartbeat, 0xFF, 0xBE, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x06, 0x08, 0x00, 0x03, 0x03,
                        0x50, 0xC6
                    ])
                    sock.sendto(heartbeat_seq, sitl_address)
                    
            except socket.timeout:
                # Timeout - enviar heartbeat periódico
                seq_heartbeat = (seq_heartbeat + 1) % 256
                heartbeat_seq = bytes([
                    0xFD, 0x09, 0x00, 0x00, seq_heartbeat, 0xFF, 0xBE, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x06, 0x08, 0x00, 0x03, 0x03,
                    0x50, 0xC6
                ])
                sock.sendto(heartbeat_seq, sitl_address)
                print(f"💓 Heartbeat #{seq_heartbeat} enviado. Total: {total_count}, Cifrados: {encrypted_count}")
                
    except KeyboardInterrupt:
        print(f"\n🎉 Finalizando detección:")
        print(f"   📊 Total mensajes procesados: {total_count}")
        print(f"   🔒 Mensajes cifrados detectados: {encrypted_count}")
        print(f"   📈 Porcentaje cifrado: {encrypted_count/total_count*100:.2f}%" if total_count > 0 else "   📈 Sin datos")
    finally:
        sock.close()

if __name__ == "__main__":
    main()