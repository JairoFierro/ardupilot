#!/usr/bin/env python3
"""
Cliente mejorado que escucha en múltiples puertos MAVLink
"""

import socket
import threading
import time

def listen_port(port):
    """Escuchar en un puerto específico"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('127.0.0.1', port))
        print(f"✅ Escuchando en puerto {port}")
        
        while True:
            try:
                data, addr = sock.recvfrom(1024)
                
                if len(data) >= 3:
                    stx = data[0]
                    length = data[1] 
                    incompat = data[2]
                    
                    timestamp = time.strftime('%H:%M:%S')
                    
                    if incompat & 0x02:
                        print(f"🔐 [{timestamp}] CIFRADO Puerto {port}: {len(data)} bytes de {addr}")
                        print(f"    STX: 0x{stx:02X}, LEN: {length}, INCOMPAT: 0x{incompat:02X}")
                        hex_data = data.hex()
                        print(f"    Hex: {hex_data[:60]}...")
                    else:
                        # Solo mostrar mensajes sin cifrar ocasionalmente
                        if (int(time.time()) % 10) == 0:  # Cada 10 segundos
                            print(f"⚠️  [{timestamp}] SIN CIFRAR Puerto {port}: {len(data)} bytes")
                            
            except Exception as e:
                print(f"Error en puerto {port}: {e}")
                break
                
    except Exception as e:
        print(f"No se pudo abrir puerto {port}: {e}")

def main():
    print("=== Cliente Multi-Puerto MAVLink ===")
    print("Buscando mensajes cifrados en puertos 14550, 14551, 14552...")
    
    # Crear hilos para escuchar múltiples puertos
    ports = [14550, 14551, 14552]
    threads = []
    
    for port in ports:
        thread = threading.Thread(target=listen_port, args=(port,))
        thread.daemon = True
        thread.start()
        threads.append(thread)
    
    try:
        # Mantener el programa vivo
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nDeteniendo cliente...")

if __name__ == "__main__":
    main()