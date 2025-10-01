#!/usr/bin/env python3
"""
Cliente simple que envía PING a ArduPilot
"""

import socket
import time

def crc16_ccitt(data):
    """Calcular CRC16-CCITT para MAVLink"""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ 0x1021
            else:
                crc = crc << 1
            crc &= 0xFFFF
    return crc

def main():
    print("=== Cliente PING - Prueba Simple ===")
    
    # Conectar al canal cifrado (puerto 14552)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = ('127.0.0.1', 14552)
    
    print(f"Conectando a {server_address}")
    
    seq = 1
    while True:
        try:
            # Crear mensaje PING (más simple)
            # PING msgid = 4, payload = 8 bytes
            timestamp = int(time.time() * 1000000)  # microsegundos
            
            payload = bytearray()
            payload.extend(timestamp.to_bytes(8, 'little'))  # time_usec (8 bytes)
            
            ping_msg = bytearray([
                0xFD,  # STX 
                0x08,  # LEN (8 bytes payload)
                0x00,  # INCOMPAT FLAGS
                0x00,  # COMPAT FLAGS  
                seq & 0xFF,  # SEQ
                0xFF,  # SYSID (255 = GCS)
                0xBE,  # COMPID (190 = GCS)
                0x04,  # MSGID LO (PING = 4)
                0x00,  # MSGID MID
                0x00,  # MSGID HI
            ])
            
            # Agregar payload
            ping_msg.extend(payload)
            
            # Calcular CRC
            crc_data = ping_msg[1:]  # Todo excepto STX
            crc_data.append(0x3C)  # CRC_EXTRA para PING
            crc = crc16_ccitt(crc_data)
            
            # Agregar CRC
            ping_msg.append(crc & 0xFF)
            ping_msg.append((crc >> 8) & 0xFF)
            
            print(f"\n[{time.strftime('%H:%M:%S')}] Enviando PING seq={seq}")
            print(f"Mensaje: {' '.join([f'{b:02X}' for b in ping_msg[:20]])}")
            
            sock.sendto(ping_msg, server_address)
            
            # Intentar recibir respuesta
            sock.settimeout(3.0)
            try:
                data, addr = sock.recvfrom(1024)
                print(f"✅ Recibido {len(data)} bytes de {addr}")
                
                if len(data) >= 10:
                    stx = data[0]
                    length = data[1]
                    incompat = data[2]
                    msgid = data[7] | (data[8] << 8) | (data[9] << 16)
                    
                    print(f"  STX: 0x{stx:02X}, LEN: {length}, MSGID: {msgid}")
                    
                    if incompat & 0x02:
                        print(f"  🔐 MENSAJE CIFRADO! incompat=0x{incompat:02X}")
                    else:
                        print(f"  ⚠️  Sin cifrar incompat=0x{incompat:02X}")
                        
                    # Mostrar datos
                    hex_data = ' '.join([f'{b:02X}' for b in data[:min(len(data), 30)]])
                    print(f"  Datos: {hex_data}")
                        
            except socket.timeout:
                print("  ❌ Timeout - sin respuesta")
                
        except KeyboardInterrupt:
            print("\nDeteniendo...")
            break
        except Exception as e:
            print(f"Error: {e}")
            
        seq += 1
        time.sleep(3)
    
    sock.close()

if __name__ == "__main__":
    main()