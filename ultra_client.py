#!/usr/bin/env python3
"""
Cliente ultra-agresivo para capturar TODOS los mensajes MAVLink
"""

import socket
import time
import select

def main():
    print("=== Cliente Ultra-Agresivo MAVLink ===")
    
    # Crear socket UDP no bloqueante
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', 14550))  # Bind a CUALQUIER interfaz
    sock.setblocking(False)
    
    print("Escuchando en puerto 14550 (modo no bloqueante)...")
    
    encrypted_count = 0
    total_count = 0
    
    while True:
        try:
            # Usar select para timeout
            ready = select.select([sock], [], [], 0.1)
            if ready[0]:
                data, addr = sock.recvfrom(2048)
                total_count += 1
                
                if len(data) >= 3:
                    stx = data[0]
                    length = data[1] 
                    incompat = data[2]
                    
                    timestamp = time.strftime('%H:%M:%S.%f')[:-3]
                    
                    if stx == 0xFD and (incompat & 0x02):  # MAVLink v2 cifrado
                        encrypted_count += 1
                        print(f"\n🔐🔐🔐 [{timestamp}] MENSAJE CIFRADO #{encrypted_count} 🔐🔐🔐")
                        print(f"    Tamaño: {len(data)} bytes de {addr}")
                        print(f"    STX: 0x{stx:02X}, LEN: {length}, INCOMPAT: 0x{incompat:02X}")
                        
                        # Mostrar hex completo del mensaje cifrado
                        hex_data = ' '.join([f'{b:02X}' for b in data])
                        print(f"    Hex completo: {hex_data}")
                        
                        # Analizar estructura
                        if len(data) >= 10:
                            seq = data[4]
                            sysid = data[5]
                            compid = data[6]
                            msgid = data[7] | (data[8] << 8) | (data[9] << 16)
                            print(f"    SEQ: {seq}, SYSID: {sysid}, COMPID: {compid}, MSGID: {msgid}")
                        
                        print("🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐\n")
                        
                    else:
                        # Mostrar estadísticas cada 100 mensajes
                        if total_count % 100 == 0:
                            print(f"[{timestamp}] Stats: {total_count} total, {encrypted_count} cifrados")
            
            time.sleep(0.001)  # 1ms delay
            
        except socket.error:
            pass  # No hay datos disponibles
        except KeyboardInterrupt:
            print(f"\nEstadísticas finales:")
            print(f"Total mensajes: {total_count}")
            print(f"Mensajes cifrados: {encrypted_count}")
            break

if __name__ == "__main__":
    main()