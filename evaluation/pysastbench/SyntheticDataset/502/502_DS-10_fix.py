import json
import hashlib
import socket
import threading
from datetime import datetime

class IoTDeviceManager:
    def __init__(self):
        self.devices = {}
        self.command_queue = []
        self.firmware_cache = {}
        self.running = False

    def _validate_device(self, device_data):
        required_fields = ['device_id', 'ip_address', 'firmware_version']
        return all(field in device_data for field in required_fields)

    def process_firmware_update(self, firmware_data):
        try:
            # Replace pickle with JSON for safe deserialization
            try:
                firmware_meta = json.loads(firmware_data['metadata'])
            except json.JSONDecodeError:
                # Handle case where metadata might be already deserialized
                if isinstance(firmware_data['metadata'], dict):
                    firmware_meta = firmware_data['metadata']
                else:
                    raise ValueError("Invalid firmware metadata format")
            
            if not self._validate_firmware_metadata(firmware_meta):
                return False

            firmware_id = hashlib.sha256(firmware_data['binary']).hexdigest()
            self.firmware_cache[firmware_id] = {
                'binary': firmware_data['binary'],
                'metadata': firmware_meta
            }
            
            # Schedule updates for compatible devices
            for device_id, device in self.devices.items():
                if device['firmware_version'] in firmware_meta['compatible_versions']:
                    self.command_queue.append({
                        'device_id': device_id,
                        'command': 'UPDATE_FIRMWARE',
                        'firmware_id': firmware_id,
                        'timestamp': str(datetime.utcnow())
                    })
            
            return True
        except Exception as e:
            print(f"Firmware processing failed: {e}")
            return False

    def _validate_firmware_metadata(self, metadata):
        required_fields = ['version', 'compatible_versions']
        if not isinstance(metadata, dict):
            return False
        if not all(field in metadata for field in required_fields):
            return False
        if not isinstance(metadata['compatible_versions'], list):
            return False
        return True

    def register_device(self, device_data):
        try:
            device = json.loads(device_data)
            if not self._validate_device(device):
                return False

            self.devices[device['device_id']] = device
            return True
        except Exception as e:
            print(f"Device registration failed: {e}")
            return False

class IoTServer:
    def __init__(self, host='0.0.0.0', port=8080):
        self.host = host
        self.port = port
        self.manager = IoTDeviceManager()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def handle_client(self, conn, addr):
        try:
            data = conn.recv(4096)
            if not data:
                return

            message = json.loads(data.decode())
            
            if message['type'] == 'REGISTER_DEVICE':
                success = self.manager.register_device(message['data'])
                conn.sendall(b'REGISTRATION_SUCCESS' if success else b'REGISTRATION_FAILED')
            
            elif message['type'] == 'UPLOAD_FIRMWARE':
                firmware_data = {
                    'binary': message['binary'].encode(),
                    'metadata': message['metadata']
                }
                success = self.manager.process_firmware_update(firmware_data)
                conn.sendall(b'FIRMWARE_UPLOAD_SUCCESS' if success else b'FIRMWARE_UPLOAD_FAILED')
            
            elif message['type'] == 'GET_COMMANDS':
                device_id = message['device_id']
                commands = [cmd for cmd in self.manager.command_queue if cmd['device_id'] == device_id]
                self.manager.command_queue = [cmd for cmd in self.manager.command_queue if cmd['device_id'] != device_id]
                conn.sendall(json.dumps(commands).encode())
            
            else:
                conn.sendall(b'INVALID_MESSAGE_TYPE')
        except json.JSONDecodeError as e:
            print(f"Invalid message format: {e}")
            conn.sendall(b'INVALID_MESSAGE_FORMAT')
        except Exception as e:
            print(f"Client handling error: {e}")
        finally:
            conn.close()

    def start(self):
        self.manager.running = True
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)
        print(f"IoT Server started on {self.host}:{self.port}")

        while self.manager.running:
            try:
                conn, addr = self.socket.accept()
                threading.Thread(
                    target=self.handle_client,
                    args=(conn, addr)
                ).start()
            except KeyboardInterrupt:
                self.manager.running = False
            except Exception as e:
                print(f"Server error: {e}")

    def stop(self):
        self.manager.running = False
        self.socket.close()

if __name__ == '__main__':
    server = IoTServer()
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()