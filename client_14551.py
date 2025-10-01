#!/usr/bin/env python3
"""
Cliente dedicado para puerto 14551 (mensajes cifrados)
"""

import socket
import time
import select

def main():
    print("=== Cliente Puerto 14551 (Mensajes Cifrados) ===")
    
    # Crear socket UDP para puerto 14551
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        sock.bind(('127.0.0.1', 14551))
        print("✅ Conectado exitosamente al puerto 14551")
    except Exception as e:
        print(f"❌ Error conectando al puerto 14551: {e}")
        return
    
    sock.setblocking(False)
    
    encrypted_count = 0
    total_count = 0
    
    print("🔍 Buscando mensajes cifrados...")
    
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
                    
                    timestamp = time.strftime('%H:%M:%S')
                    
                    if stx == 0xFD:  # MAVLink v2
                        if incompat & 0x02:  # Cifrado
                            encrypted_count += 1
                            print(f"\n🎉🔐 [{timestamp}] ¡MENSAJE CIFRADO ENCONTRADO! #{encrypted_count} 🔐🎉")
                            print(f"    📦 Tamaño: {len(data)} bytes de {addr}")
                            print(f"    📋 STX: 0x{stx:02X}, LEN: {length}, INCOMPAT: 0x{incompat:02X}")
                            
                            # Mostrar hex completo
                            hex_data = ' '.join([f'{b:02X}' for b in data])
                            print(f"    🔢 Hex: {hex_data}")
                            
                            # Analizar estructura
                            if len(data) >= 10:
                                seq = data[4]
                                sysid = data[5]
                                compid = data[6]
                                msgid = data[7] | (data[8] << 8) | (data[9] << 16)
                                print(f"    📊 SEQ: {seq}, SYSID: {sysid}, COMPID: {compid}, MSGID: {msgid}")
                            
                            print("🎉🔐🎉🔐🎉🔐🎉🔐🎉🔐🎉🔐🎉🔐🎉🔐🎉🔐🎉\n")
                            
                        else:
                            # Mensaje sin cifrar
                            if total_count % 50 == 0:
                                print(f"[{timestamp}] Puerto 14551 - Sin cifrar: {total_count} total, {encrypted_count} cifrados")
                    else:
                        print(f"[{timestamp}] Mensaje no MAVLink v2: STX=0x{stx:02X}")
            
            time.sleep(0.001)  # 1ms delay
            
        except socket.error:
            pass  # No hay datos disponibles
        except KeyboardInterrupt:
            print(f"\n📊 Estadísticas finales del puerto 14551:")
            print(f"   Total mensajes: {total_count}")
            print(f"   Mensajes cifrados: {encrypted_count}")
            if total_count > 0:
                percentage = (encrypted_count / total_count) * 100
                print(f"   Porcentaje cifrado: {percentage:.1f}%")
            break

if __name__ == "__main__":
    main()