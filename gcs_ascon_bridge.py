#!/usr/bin/env python3
"""
Mini-GCS ASCON Bridge - Compatible con implementación ArduPilot
Descifra mensajes del puerto 15550 y los retransmite en claro al puerto 14555

Autor: Compatible con implementación de @JairoFierro
"""

import socket
import struct
import os
import sys
import time
import threading
from typing import Optional, Tuple, List

# === Dependencias ===
try:
    from pymavlink import mavutil
    from pymavlink.dialects.v20 import ardupilotmega as mavlink_dialect
    # Importar MAVLink desde el dialecto, no desde pymavlink directamente
    from pymavlink.dialects.v20.ardupilotmega import MAVLink
    print("✅ pymavlink importado correctamente")
except ImportError as e:
    print(f"❌ Error importando pymavlink: {e}")
    print("pip install pymavlink")
    sys.exit(1)

try:
    # Usar la misma biblioteca ASCON que el firmware
    import ascon
    print("✅ ascon importado correctamente")
except ImportError as e:
    print(f"❌ Error importando ascon: {e}")
    print("pip install ascon")
    sys.exit(1)

# === Constantes (exactas del firmware) ===
MAVLINK_V2_STX = 0xFD
MAVLINK_V2_HDR_LEN = 10
MAVLINK_IFLAG_ENCRYPTED = 0x02    # Flag en incompat_flags para cifrado ASCON
MAVLINK_IFLAG_SIGNED = 0x01       # NO usar cuando está cifrado
CRYPTO_ABYTES = 16                # Tag ASCON = 16 bytes
CRYPTO_NPUBBYTES = 16             # Nonce = 16 bytes
CRYPTO_KEYBYTES = 16              # Key = 16 bytes

# === Configuración ===
RX_PORT = 15550        # Puerto donde escucha mensajes cifrados (SERIAL3)
TX_PORT = 14555        # Puerto donde envía mensajes en claro (QGC/MAVProxy)
RX_ADDR = ('127.0.0.1', RX_PORT)
TX_ADDR = ('127.0.0.1', TX_PORT)

class ASCONConfig:
    """Configuración ASCON (debe coincidir con firmware)"""
    def __init__(self):
        # Leer de variables de entorno o usar valores de prueba
        key_hex = os.getenv('ASCON_KEY_HEX', '000102030405060708090A0B0C0D0E0F')
        iv_boot_hex = os.getenv('ASCON_IV_BOOT_HEX', '1122334455667788')
        
        if len(key_hex) != 32:  # 16 bytes = 32 hex chars
            raise ValueError(f"ASCON_KEY_HEX debe ser 32 caracteres hex, recibido: {len(key_hex)}")
        if len(iv_boot_hex) != 16:  # 8 bytes = 16 hex chars
            raise ValueError(f"ASCON_IV_BOOT_HEX debe ser 16 caracteres hex, recibido: {len(iv_boot_hex)}")
            
        self.key = bytes.fromhex(key_hex)
        self.iv_boot = int(iv_boot_hex, 16)
        
        print(f"🔑 ASCON Key: {key_hex}")
        print(f"🔢 IV Boot: {iv_boot_hex} (0x{self.iv_boot:016X})")

def parse_v2_header(frame: bytes) -> Optional[Tuple[int, int, int, int, int, int, int]]:
    """
    Parsear header MAVLink v2
    Retorna: (payload_len, incompat_flags, compat_flags, seq, sysid, compid, msgid)
    """
    if len(frame) < MAVLINK_V2_HDR_LEN or frame[0] != MAVLINK_V2_STX:
        return None
        
    payload_len = frame[1]
    incompat_flags = frame[2]
    compat_flags = frame[3]
    seq = frame[4]
    sysid = frame[5]
    compid = frame[6]
    msgid = struct.unpack('<I', frame[7:10] + b'\\x00')[0]  # 3 bytes little-endian
    
    return payload_len, incompat_flags, compat_flags, seq, sysid, compid, msgid

def build_aad(incompat_flags: int, compat_flags: int, seq: int, 
              sysid: int, compid: int, msgid: int) -> bytes:
    """
    Construir AAD exactamente como en el firmware
    [incompat|compat|seq|sysid|compid|msgid(3)] = 8 bytes
    """
    aad = bytearray(8)
    aad[0] = incompat_flags
    aad[1] = compat_flags
    aad[2] = seq
    aad[3] = sysid
    aad[4] = compid
    aad[5] = msgid & 0xFF
    aad[6] = (msgid >> 8) & 0xFF
    aad[7] = (msgid >> 16) & 0xFF
    return bytes(aad)

def build_nonce(iv_boot: int, sysid: int, compid: int, seq: int) -> bytes:
    """
    Construir nonce exactamente como en el firmware
    [ iv_boot(8) | sysid(1) | compid(1) | seq(1) | pad(5) ] = 16 bytes
    """
    npub = bytearray(CRYPTO_NPUBBYTES)
    # iv_boot como little-endian (8 bytes)
    npub[0:8] = struct.pack('<Q', iv_boot)
    npub[8] = sysid
    npub[9] = compid
    npub[10] = seq
    # npub[11:16] ya están en 0
    return bytes(npub)

def mavlink_crc16(data: bytes, crc_extra: int) -> int:
    """
    Calcular CRC16 MAVLink (X.25) sobre payload + crc_extra
    """
    crc = 0xFFFF
    
    # Procesar data
    for byte in data:
        byte ^= (crc & 0xFF)
        byte ^= (byte << 4)
        crc = ((crc >> 8) ^ (byte << 8) ^ (byte << 3) ^ (byte >> 4)) & 0xFFFF
    
    # Agregar crc_extra
    byte = crc_extra
    byte ^= (crc & 0xFF)
    byte ^= (byte << 4)
    crc = ((crc >> 8) ^ (byte << 8) ^ (byte << 3) ^ (byte >> 4)) & 0xFFFF
    
    return crc

def get_crc_extra(msgid: int) -> int:
    """Obtener crc_extra del dialecto ardupilotmega"""
    try:
        msg_map = mavlink_dialect.MAVLink_message_map
        if msgid in msg_map:
            return msg_map[msgid].crc_extra
        return 0
    except:
        return 0

class ASCONBridge:
    """Mini-GCS para puente ASCON"""
    
    def __init__(self):
        self.config = ASCONConfig()
        self.rx_socket = None
        self.tx_socket = None
        self.running = False
        
        # Estadísticas
        self.stats = {
            'rx_total': 0,
            'rx_encrypted': 0,
            'rx_decrypted_ok': 0,
            'rx_decrypt_failed': 0,
            'tx_forwarded': 0
        }
    
    def setup_sockets(self):
        """Configurar sockets UDP"""
        try:
            # Socket RX (escuchar mensajes cifrados)
            self.rx_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.rx_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.rx_socket.bind(RX_ADDR)
            print(f"🔧 Socket RX configurado en {RX_ADDR}")
            
            # Socket TX (enviar mensajes en claro)
            self.tx_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            print(f"🔧 Socket TX configurado para {TX_ADDR}")
            
        except Exception as e:
            print(f"❌ Error configurando sockets: {e}")
            sys.exit(1)
    
    def decrypt_and_forward(self, frame: bytes) -> bool:
        """
        Descifrar frame y retransmitir en claro
        Retorna True si se procesó correctamente
        """
        self.stats['rx_total'] += 1
        
        # Parsear header
        header_data = parse_v2_header(frame)
        if not header_data:
            print(f"⚠️  Frame no MAVLink v2, ignorando ({len(frame)} bytes)")
            return False
            
        payload_len, incompat_flags, compat_flags, seq, sysid, compid, msgid = header_data
        
        # Verificar si está cifrado
        if not (incompat_flags & MAVLINK_IFLAG_ENCRYPTED):
            print(f"📦 Mensaje normal msgid={msgid}, seq={seq} (no cifrado)")
            return True
            
        self.stats['rx_encrypted'] += 1
        print(f"🔒 RX cifrado: msgid={msgid}, seq={seq}, sysid={sysid}, compid={compid}, len={payload_len}")
        
        # Verificar tamaño mínimo (header + tag + crc)
        expected_frame_len = MAVLINK_V2_HDR_LEN + payload_len + 2
        if len(frame) < expected_frame_len:
            print(f"❌ Frame truncado: {len(frame)} < {expected_frame_len}")
            self.stats['rx_decrypt_failed'] += 1
            return False
            
        # Verificar que hay suficientes datos para el tag
        if payload_len < CRYPTO_ABYTES:
            print(f"❌ Payload muy pequeño para tag: {payload_len} < {CRYPTO_ABYTES}")
            self.stats['rx_decrypt_failed'] += 1
            return False
        
        try:
            # Extraer ciphertext + tag
            ciphertext_with_tag = frame[MAVLINK_V2_HDR_LEN:MAVLINK_V2_HDR_LEN + payload_len]
            
            # Construir AAD y nonce exactamente como el firmware
            aad = build_aad(incompat_flags, compat_flags, seq, sysid, compid, msgid)
            nonce = build_nonce(self.config.iv_boot, sysid, compid, seq)
            
            print(f"🔧 AAD ({len(aad)} bytes): {aad.hex().upper()}")
            print(f"🔧 Nonce ({len(nonce)} bytes): {nonce.hex().upper()}")
            print(f"🔧 Ciphertext+tag ({len(ciphertext_with_tag)} bytes): {ciphertext_with_tag[:16].hex().upper()}...")
            
            # Descifrar con ASCON
            try:
                plaintext = ascon.decrypt(self.config.key, nonce, aad, ciphertext_with_tag)
            except Exception as e:
                print(f"❌ DESCIFRADO FALLÓ: {e}")
                print(f"   Posibles causas: clave incorrecta, nonce diferente, AAD diferente, tag inválido")
                self.stats['rx_decrypt_failed'] += 1
                return False
            
            print(f"✅ Descifrado exitoso! Plaintext ({len(plaintext)} bytes): {plaintext[:16].hex().upper()}...")
            self.stats['rx_decrypted_ok'] += 1
            
            # Construir frame en claro
            clear_frame = bytearray(frame)
            
            # Actualizar header
            clear_frame[1] = len(plaintext)  # Nueva longitud del payload
            clear_frame[2] &= ~MAVLINK_IFLAG_ENCRYPTED  # Quitar flag de cifrado
            
            # Reemplazar payload
            clear_frame[MAVLINK_V2_HDR_LEN:MAVLINK_V2_HDR_LEN + payload_len] = plaintext
            
            # Recalcular CRC sobre nuevo payload
            crc_extra = get_crc_extra(msgid)
            new_crc = mavlink_crc16(plaintext, crc_extra)
            
            # Actualizar frame length y CRC
            new_frame_len = MAVLINK_V2_HDR_LEN + len(plaintext) + 2
            clear_frame = clear_frame[:MAVLINK_V2_HDR_LEN + len(plaintext)]
            clear_frame.extend(struct.pack('<H', new_crc))
            
            print(f"🔧 CRC recalculado: 0x{new_crc:04X} (crc_extra=0x{crc_extra:02X})")
            print(f"📤 Reenviando mensaje en claro ({len(clear_frame)} bytes) a {TX_ADDR}")
            
            # Enviar mensaje en claro
            self.tx_socket.sendto(bytes(clear_frame), TX_ADDR)
            self.stats['tx_forwarded'] += 1
            
            print(f"✅ RX cifrado OK → reenviado en claro (msgid={msgid})")
            return True
            
        except Exception as e:
            print(f"❌ Error procesando mensaje cifrado: {e}")
            self.stats['rx_decrypt_failed'] += 1
            return False
    
    def rx_loop(self):
        """Loop principal de recepción"""
        print(f"🎯 Iniciando loop RX en {RX_ADDR}...")
        
        while self.running:
            try:
                # Recibir datagrama
                data, addr = self.rx_socket.recvfrom(512)
                
                if not data:
                    continue
                
                print(f"\\n📥 RX de {addr}: {len(data)} bytes")
                
                # Puede haber múltiples frames MAVLink en un datagrama
                offset = 0
                while offset < len(data):
                    # Buscar próximo frame MAVLink v2
                    if offset >= len(data) or data[offset] != MAVLINK_V2_STX:
                        print(f"⚠️  No encontrado STX en offset {offset}")
                        break
                    
                    if offset + MAVLINK_V2_HDR_LEN > len(data):
                        print(f"⚠️  Header incompleto en offset {offset}")
                        break
                    
                    # Leer longitud del payload
                    payload_len = data[offset + 1]
                    frame_len = MAVLINK_V2_HDR_LEN + payload_len + 2  # +2 para CRC
                    
                    if offset + frame_len > len(data):
                        print(f"⚠️  Frame incompleto: necesita {frame_len}, disponible {len(data) - offset}")
                        break
                    
                    # Extraer frame completo
                    frame = data[offset:offset + frame_len]
                    
                    # Procesar frame
                    self.decrypt_and_forward(frame)
                    
                    # Avanzar al próximo frame
                    offset += frame_len
                
            except socket.timeout:
                continue
            except Exception as e:
                print(f"❌ Error en RX loop: {e}")
                continue
    
    def send_encrypted_command_set_interval(self, target_system: int = 1, target_component: int = 1,
                                          msg_id: int = 33, interval_us: int = 1000000):
        """
        [OPCIONAL] Enviar comando cifrado COMMAND_LONG para SET_MESSAGE_INTERVAL
        """
        print(f"\\n📤 Enviando comando cifrado SET_MESSAGE_INTERVAL...")
        
        try:
            # Crear mensaje COMMAND_LONG con pymavlink
            mav = MAVLink(None)
            msg = mav.command_long_encode(
                target_system,           # target_system
                target_component,        # target_component
                mavlink_dialect.MAV_CMD_SET_MESSAGE_INTERVAL,  # command
                0,                       # confirmation
                msg_id,                  # param1: message ID
                interval_us,             # param2: interval in microseconds
                0, 0, 0, 0, 0           # param3-7
            )
            
            # Empaquetar mensaje
            packed = msg.pack(mav)
            
            # Parsear frame para obtener header
            header_data = parse_v2_header(packed)
            if not header_data:
                print("❌ Error: No se pudo parsear mensaje generado")
                return False
            
            payload_len, incompat_flags, compat_flags, seq, sysid, compid, msgid = header_data
            
            # Extraer payload original
            original_payload = packed[MAVLINK_V2_HDR_LEN:MAVLINK_V2_HDR_LEN + payload_len]
            
            print(f"🔧 Comando original: msgid={msgid}, payload_len={payload_len}")
            print(f"🔧 Payload original: {original_payload.hex().upper()}")
            
            # Modificar flags para cifrado
            new_incompat_flags = (incompat_flags | MAVLINK_IFLAG_ENCRYPTED) & ~MAVLINK_IFLAG_SIGNED
            new_compat_flags = compat_flags  # Sin cambios en compat
            
            # Construir AAD y nonce
            aad = build_aad(new_incompat_flags, new_compat_flags, seq, sysid, compid, msgid)
            nonce = build_nonce(self.config.iv_boot, sysid, compid, seq)
            
            print(f"🔧 AAD cifrado: {aad.hex().upper()}")
            print(f"🔧 Nonce cifrado: {nonce.hex().upper()}")
            
            # Cifrar con ASCON
            ciphertext_with_tag = ascon.encrypt(self.config.key, nonce, aad, original_payload)
            
            print(f"🔧 Ciphertext+tag ({len(ciphertext_with_tag)} bytes): {ciphertext_with_tag.hex().upper()}")
            
            # Construir frame cifrado
            encrypted_frame = bytearray(packed)
            encrypted_frame[1] = len(ciphertext_with_tag)  # Nueva longitud
            encrypted_frame[2] = new_incompat_flags        # Flags actualizados
            
            # Reemplazar payload
            encrypted_frame[MAVLINK_V2_HDR_LEN:MAVLINK_V2_HDR_LEN + payload_len] = ciphertext_with_tag
            
            # Recalcular CRC
            crc_extra = get_crc_extra(msgid)
            new_crc = mavlink_crc16(ciphertext_with_tag, crc_extra)
            
            # Ajustar tamaño y CRC
            new_frame_len = MAVLINK_V2_HDR_LEN + len(ciphertext_with_tag) + 2
            encrypted_frame = encrypted_frame[:MAVLINK_V2_HDR_LEN + len(ciphertext_with_tag)]
            encrypted_frame.extend(struct.pack('<H', new_crc))
            
            print(f"🔧 CRC cifrado: 0x{new_crc:04X}")
            print(f"📤 Enviando comando cifrado ({len(encrypted_frame)} bytes) a puerto {RX_PORT}")
            
            # Enviar por socket directo al puerto del firmware
            tx_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            tx_sock.sendto(bytes(encrypted_frame), ('127.0.0.1', RX_PORT))
            tx_sock.close()
            
            print("✅ Comando cifrado enviado!")
            return True
            
        except Exception as e:
            print(f"❌ Error enviando comando cifrado: {e}")
            return False
    
    def print_stats(self):
        """Imprimir estadísticas"""
        print(f"\\n📊 ESTADÍSTICAS:")
        print(f"   RX Total: {self.stats['rx_total']}")
        print(f"   RX Cifrados: {self.stats['rx_encrypted']}")
        print(f"   Descifrados OK: {self.stats['rx_decrypted_ok']}")
        print(f"   Descifrados FAIL: {self.stats['rx_decrypt_failed']}")
        print(f"   TX Reenviados: {self.stats['tx_forwarded']}")
        if self.stats['rx_encrypted'] > 0:
            success_rate = (self.stats['rx_decrypted_ok'] / self.stats['rx_encrypted']) * 100
            print(f"   Tasa éxito: {success_rate:.1f}%")
    
    def run(self):
        """Ejecutar bridge"""
        print("🚀 === Mini-GCS ASCON Bridge ===")
        print(f"🔧 Puerto RX (cifrado): {RX_PORT}")
        print(f"🔧 Puerto TX (claro): {TX_PORT}")
        print(f"🔧 Flag cifrado: 0x{MAVLINK_IFLAG_ENCRYPTED:02X}")
        print(f"🔧 Tag ASCON: {CRYPTO_ABYTES} bytes")
        print(f"🔧 Nonce ASCON: {CRYPTO_NPUBBYTES} bytes")
        
        try:
            self.setup_sockets()
            self.running = True
            
            # Configurar timeout para el socket RX
            self.rx_socket.settimeout(1.0)
            
            # Iniciar thread de estadísticas
            def stats_thread():
                while self.running:
                    time.sleep(10)
                    if self.running:
                        self.print_stats()
            
            stats_t = threading.Thread(target=stats_thread, daemon=True)
            stats_t.start()
            
            print("\\n🎯 Bridge iniciado. Presiona Ctrl+C para detener.")
            print("🔍 Esperando mensajes cifrados...")
            
            # [OPCIONAL] Enviar comando de prueba después de 5 segundos
            def test_command():
                time.sleep(5)
                if self.running:
                    print("\\n🧪 Enviando comando de prueba...")
                    self.send_encrypted_command_set_interval(1, 1, 33, 1000000)
            
            test_t = threading.Thread(target=test_command, daemon=True)
            test_t.start()
            
            # Loop principal
            self.rx_loop()
            
        except KeyboardInterrupt:
            print("\\n🛑 Deteniendo bridge...")
        except Exception as e:
            print(f"❌ Error fatal: {e}")
        finally:
            self.running = False
            self.print_stats()
            
            if self.rx_socket:
                self.rx_socket.close()
            if self.tx_socket:
                self.tx_socket.close()
            
            print("👋 Bridge detenido.")

if __name__ == '__main__':
    bridge = ASCONBridge()
    bridge.run()