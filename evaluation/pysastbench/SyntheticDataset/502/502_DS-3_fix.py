import socket
import json
import sys
import threading
from cryptography.fernet import Fernet

class DeviceConfigManager:
    def __init__(self):
        self.devices = {}
        self.config_versions = {}
        self.cipher = Fernet(Fernet.generate_key())

    def _validate_config(self, config):
        required_fields = ['hostname', 'ip', 'config']
        return all(field in config for field in required_fields)

    def store_config(self, device_id, config_data):
        try:
            # Replace pickle with JSON for safe deserialization
            config = json.loads(config_data.decode('utf-8'))
            if not self._validate_config(config):
                return False
            
            # Encrypt the config (as JSON string) before storing
            encrypted_config = self.cipher.encrypt(
                json.dumps(config['config']).encode('utf-8')
            )
            self.devices[device_id] = {
                'hostname': config['hostname'],
                'ip': config['ip'],
                'config': encrypted_config
            }
            self.config_versions[device_id] = self.config_versions.get(device_id, 0) + 1
            return True
        except Exception as e:
            print(f"Config storage failed: {e}")
            return False

    def get_config(self, device_id):
        if device_id not in self.devices:
            return None
        
        try:
            decrypted = self.cipher.decrypt(self.devices[device_id]['config'])
            return json.loads(decrypted.decode('utf-8'))
        except Exception as e:
            print(f"Config retrieval failed: {e}")
            return None

class ConfigServer:
    def __init__(self, host='0.0.0.0', port=65432):
        self.host = host
        self.port = port
        self.manager = DeviceConfigManager()
        self.running = False

    def handle_client(self, conn, addr):
        try:
            data = conn.recv(4096)
            if not data:
                return

            header = data[:4]
            if header == b'STOR':
                device_id = data[4:36].decode()
                config_data = data[36:]
                success = self.manager.store_config(device_id, config_data)
                conn.sendall(b'SUCC' if success else b'FAIL')
            elif header == b'GETC':
                device_id = data[4:36].decode()
                config = self.manager.get_config(device_id)
                if config:
                    conn.sendall(b'DATA' + json.dumps(config).encode('utf-8'))
                else:
                    conn.sendall(b'FAIL')
            else:
                conn.sendall(b'INVD')
        except Exception as e:
            print(f"Client handling error: {e}")
        finally:
            conn.close()

    def start(self):
        self.running = True
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen()
            print(f"Server started on {self.host}:{self.port}")

            while self.running:
                try:
                    conn, addr = s.accept()
                    threading.Thread(
                        target=self.handle_client,
                        args=(conn, addr)
                    ).start()
                except KeyboardInterrupt:
                    self.running = False
                except Exception as e:
                    print(f"Server error: {e}")

    def stop(self):
        self.running = False

if __name__ == '__main__':
    server = ConfigServer()
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()
        sys.exit(0)