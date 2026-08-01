import pickle
import socket
import sys
import hashlib
from datetime import datetime

class DeviceConfig:
    def __init__(self):
        self.hostname = "unknown"
        self.interfaces = {}
        self.routing_table = []
        self.credentials = {}
        self.last_backup = None

class NetworkManager:
    def __init__(self):
        self.devices = {}
        self.config_history = []
        self.audit_log = []

    def load_config_from_network(self, host, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((host, port))
                data = s.recv(4096)
                return self._process_remote_config(data)
        except Exception as e:
            self._log_audit(f"Error loading config from {host}:{port} - {str(e)}")
            return False

    def _process_remote_config(self, data):
        try:
            # Vulnerable deserialization point
            config = pickle.loads(data)
            return self._apply_network_config(config)
        except Exception as e:
            self._log_audit(f"Config processing error: {str(e)}")
            return False

    def _apply_network_config(self, config):
        # This is the vulnerable function
        device_id = config.get('device_id', 'unknown')
        if device_id not in self.devices:
            self.devices[device_id] = DeviceConfig()

        device = self.devices[device_id]
        device.hostname = config.get('hostname', device.hostname)
        device.interfaces = config.get('interfaces', device.interfaces)
        device.routing_table = config.get('routing_table', device.routing_table)
        
        # Critical vulnerability: blindly accepting credentials from untrusted source
        if 'credentials' in config:
            device.credentials.update(config['credentials'])

        device.last_backup = datetime.now()
        self._log_config_change(device_id, "remote_update")
        return True

    def save_config_to_file(self, device_id, filename):
        if device_id not in self.devices:
            return False

        config = {
            'device_id': device_id,
            'hostname': self.devices[device_id].hostname,
            'interfaces': self.devices[device_id].interfaces,
            'routing_table': self.devices[device_id].routing_table,
            'credentials': self.devices[device_id].credentials,
            'timestamp': datetime.now().isoformat()
        }

        try:
            with open(filename, 'wb') as f:
                pickle.dump(config, f)
            self._log_audit(f"Saved config for {device_id} to {filename}")
            return True
        except Exception as e:
            self._log_audit(f"Failed to save config: {str(e)}")
            return False

    def _log_config_change(self, device_id, action):
        entry = {
            'timestamp': datetime.now(),
            'device': device_id,
            'action': action,
            'hash': hashlib.sha256(str(self.devices[device_id].__dict__).encode()).hexdigest()
        }
        self.config_history.append(entry)

    def _log_audit(self, message):
        entry = {
            'timestamp': datetime.now(),
            'message': message
        }
        self.audit_log.append(entry)

    def get_audit_log(self, limit=10):
        return self.audit_log[-limit:]

    def get_config_history(self, device_id, limit=5):
        return [entry for entry in self.config_history if entry['device'] == device_id][-limit:]

def main():
    manager = NetworkManager()
    print("Network Configuration Manager started")

    while True:
        print("\n1. Load config from network")
        print("2. Save config to file")
        print("3. View audit log")
        print("4. Exit")
        choice = input("Select option: ")

        if choice == "1":
            host = input("Enter host: ")
            port = int(input("Enter port: "))
            if manager.load_config_from_network(host, port):
                print("Configuration loaded successfully")
            else:
                print("Failed to load configuration")
        elif choice == "2":
            device_id = input("Enter device ID: ")
            filename = input("Enter filename: ")
            if manager.save_config_to_file(device_id, filename):
                print("Configuration saved successfully")
            else:
                print("Failed to save configuration")
        elif choice == "3":
            entries = manager.get_audit_log()
            for entry in entries:
                print(f"{entry['timestamp']}: {entry['message']}")
        elif choice == "4":
            sys.exit(0)
        else:
            print("Invalid option")

if __name__ == "__main__":
    main()