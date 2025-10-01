#!/usr/bin/env python3
"""
Cliente simple para activar el puerto 14551 en SITL
Se conecta y envía heartbeats para mantener la conexión activa
"""

import socket
import struct
import time
import threading

def create_heartbeat(seq=0):
    """Crear mensaje HEARTBEAT MAVLink v2"""
    # MAVLink v2 HEARTBEAT
    return bytes([
        0xFD,  # STX (MAVLink v2)
        0x09,  # Payload length (9 bytes)
        0x00,  # Incompat flags
        0x00,  # Compat flags
        seq & 0xFF,  # Sequence
        0xFF,  # System ID (GCS)
        0xBE,  # Component ID (GCS)
        0x00, 0x00, 0x00,  # Message ID (HEARTBEAT = 0) - 3 bytes little endian
        # Payload (9 bytes)
        0x00, 0x00, 0x00, 0x00,  # custom_mode (uint32)
        0x06,  # type (MAV_TYPE_GCS)
        0x08,  # autopilot (MAV_AUTOPILOT_INVALID)
        0x00,  # base_mode
        0x03,  # system_status (MAV_STATE_STANDBY)
        0x03,  # mavlink_version
        # CRC16 (placeholder - SITL no valida CRC en este contexto)
        0x50, 0xC6  # CRC for HEARTBEAT
    ])

def client_14551():
    """Cliente para puerto 14551 (mensajes cifrados)"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        
        sitl_addr = ('127.0.0.1', 14551)
        print(f"[14551] Conectando a SITL en {sitl_addr}...")
        
        # Enviar heartbeat inicial para activar la conexión
        heartbeat = create_heartbeat(0)
        sock.sendto(heartbeat, sitl_addr)
        print(f"[14551] ¡Conexión activada! Esperando mensajes cifrados...")
        
        seq = 0
        encrypted_count = 0
        total_count = 0
        
        while True:
            try:
                # Recibir datos
                data, addr = sock.recvfrom(1024)
                total_count += 1
                
                if len(data) >= 3:
                    stx = data[0]
                    payload_len = data[1]
                    incompat_flags = data[2]
                    
                    if stx == 0xFD:  # MAVLink v2
                        is_encrypted = (incompat_flags & 0x02) != 0
                        if is_encrypted:
                            encrypted_count += 1
                            print(f"[14551] ¡MENSAJE CIFRADO #{encrypted_count}! "
                                  f"incompat_flags=0x{incompat_flags:02X}, len={len(data)}")
                            # Mostrar primeros bytes
                            hex_data = ' '.join(f'{b:02X}' for b in data[:20])
                            print(f"        Primeros 20 bytes: {hex_data}")
                        else:
                            if total_count % 50 == 0:  # Mostrar cada 50 mensajes normales
                                print(f"[14551] Mensaje normal #{total_count}, flags=0x{incompat_flags:02X}")
                
                # Enviar heartbeat cada 100 mensajes recibidos
                if total_count % 100 == 0:
                    seq += 1
                    heartbeat = create_heartbeat(seq)
                    sock.sendto(heartbeat, sitl_addr)
                    
            except socket.timeout:
                # Enviar heartbeat periódico para mantener conexión
                seq += 1
                heartbeat = create_heartbeat(seq)
                sock.sendto(heartbeat, sitl_addr)
                print(f"[14551] Heartbeat enviado (seq={seq}). Total: {total_count}, Cifrados: {encrypted_count}")
                
    except KeyboardInterrupt:
        print(f"\n[14551] Detenido. Total: {total_count}, Cifrados: {encrypted_count}")
    except Exception as e:
        print(f"[14551] Error: {e}")
    finally:
        if 'sock' in locals():
            sock.close()

def client_14550():
    """Cliente para puerto 14550 (referencia - mensajes normales)"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        
        sitl_addr = ('127.0.0.1', 14550)
        print(f"[14550] Conectando a SITL en {sitl_addr}...")
        
        heartbeat = create_heartbeat(0)
        sock.sendto(heartbeat, sitl_addr)
        print(f"[14550] Conexión de referencia activa")
        
        seq = 0
        count = 0
        
        while True:
            try:
                data, addr = sock.recvfrom(1024)
                count += 1
                
                if count % 100 == 0:
                    print(f"[14550] {count} mensajes recibidos (puerto normal)")
                
                if count % 200 == 0:
                    seq += 1
                    heartbeat = create_heartbeat(seq)
                    sock.sendto(heartbeat, sitl_addr)
                    
            except socket.timeout:
                seq += 1
                heartbeat = create_heartbeat(seq)
                sock.sendto(heartbeat, sitl_addr)
                
    except Exception as e:
        print(f"[14550] Error: {e}")
    finally:
        if 'sock' in locals():
            sock.close()

if __name__ == "__main__":
    print("=== Cliente MAVLink para activar puertos 14550 y 14551 ===")
    print("Presiona Ctrl+C para detener")
    
    # Crear hilos para ambos puertos
    thread_14550 = threading.Thread(target=client_14550, daemon=True)
    thread_14551 = threading.Thread(target=client_14551, daemon=True)
    
    # Iniciar hilos
    thread_14550.start()
    time.sleep(0.5)  # Pequeño delay
    thread_14551.start()
    
    try:
        # Mantener programa ejecutándose
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n=== Finalizando clientes ===")