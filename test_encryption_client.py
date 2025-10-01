#!/usr/bin/env python3
"""
Cliente de prueba para canal cifrado ASCON
Se conecta al puerto 14552 (canal 2) que debe estar cifrado
"""

import socket
import time
import struct

def main():
    print("=== Cliente de Prueba - Canal Cifrado ASCON ===")
    
    # Conectar al canal cifrado (puerto 14552)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = ('127.0.0.1', 14552)
    
    print(f"Conectando a {server_address}")
    
    # Solicitar HEARTBEAT cada 5 segundos
    while True:
        try:
            # Enviar REQUEST_MESSAGE para HEARTBEAT (msgid=0)
            # MAVLink v2: STX, LEN, INCOMPAT, COMPAT, SEQ, SYSID, COMPID, MSGID(3 bytes), PAYLOAD, CRC
            request_msg = bytearray([
                0xFD,  # STX (MAVLink v2)
                0x03,  # LEN (3 bytes payload)
                0x00,  # INCOMPAT FLAGS
                0x00,  # COMPAT FLAGS  
                0x01,  # SEQ
                0xFF,  # SYSID (255 = GCS)
                0xBE,  # COMPID (190 = GCS)
                0x28,  # MSGID LO (REQUEST_MESSAGE = 512 = 0x0200)
                0x02,  # MSGID MID
                0x00,  # MSGID HI
                # PAYLOAD (3 bytes):
                0x00,  # HEARTBEAT msgid LO
                0x00,  # HEARTBEAT msgid MID  
                0x00,  # HEARTBEAT msgid HI
            ])
            
            # Calcular CRC (simplificado para prueba)
            request_msg.extend([0x00, 0x00])  # CRC placeholder
            
            print(f"\n[{time.strftime('%H:%M:%S')}] Enviando REQUEST_MESSAGE para HEARTBEAT...")
            sock.sendto(request_msg, server_address)
            
            # Intentar recibir respuesta
            sock.settimeout(2.0)
            try:
                data, addr = sock.recvfrom(1024)
                print(f"Recibido {len(data)} bytes de {addr}")
                
                # Analizar cabecera MAVLink
                if len(data) >= 10:
                    stx = data[0]
                    length = data[1]
                    incompat = data[2]
                    
                    print(f"  STX: 0x{stx:02X}")
                    print(f"  LEN: {length}")
                    print(f"  INCOMPAT: 0x{incompat:02X}")
                    
                    if incompat & 0x02:  # MAVLINK_IFLAG_ENCRYPTED
                        print("  🔐 MENSAJE CIFRADO DETECTADO! ✅")
                    else:
                        print("  ⚠️  Mensaje sin cifrar")
                        
                    # Mostrar primeros bytes del payload
                    if len(data) > 10:
                        payload_preview = ' '.join([f'{b:02X}' for b in data[10:min(len(data), 20)]])
                        print(f"  Payload: {payload_preview}...")
                        
            except socket.timeout:
                print("  Timeout - sin respuesta")
                
        except KeyboardInterrupt:
            print("\nDeteniendo cliente...")
            break
        except Exception as e:
            print(f"Error: {e}")
            
        time.sleep(5)
    
    sock.close()
    print("Cliente cerrado.")

if __name__ == "__main__":
    main()