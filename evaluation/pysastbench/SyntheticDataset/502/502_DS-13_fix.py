import json
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
        self.trusted_sources = ['192.168.1.0/24']  # Example trusted network

    def _is_trusted_source(self, host):
        # Implement proper network range checking in production
        return any(host.startswith(source.split('/')[0]) for source in self.trusted_sources)

    def load_config_from_network(self, host, port):
        try:
            if not self._is_trusted_source(host):
                raise ValueError(f"Untrusted source: {host}")
                
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)  # Add timeout
                s.connect((host, port))
                data = s.recv(4096)
                return self._process_remote_config(data, host)
        except Exception as e:
            self._log_audit(f"Error loading config from {host}:{port} - {str(e)}")
            return False

    def _process_remote_config(self, data, source_host):
        try:
            # Use JSON instead of pickle for safe deserialization
            config = json.loads(data.decode('utf-8'))
            return self._apply_network_config(config, source_host)
        except json.JSONDecodeError as e:
            self._log_audit(f"Invalid config format from {source_host}: {str(e)}")
            return False
        except Exception as e:
            self._log_audit(f"Config processing error from {source_host}: {str(e)}")
            return False

    def _apply_network_config(self, config, source_host):
        # Validate config structure
        if not isinstance(config, dict):
            raise ValueError("Invalid config format")
            
        device_id = config.get('device_id', 'unknown')
        if not isinstance(device_id, str):
            raise ValueError("Invalid device ID")
            
        if device_id not in self.devices:
            self.devices[device_id] = DeviceConfig()

        device = self.devices[device_id]
        
        # Validate and apply hostname
        if 'hostname' in config:
            if isinstance(config['hostname'], str):
                device.hostname = config['hostname']
        
        # Validate and apply interfaces
        if 'interfaces' in config:
            if isinstance(config['interfaces'], dict):
                device.interfaces = config['interfaces']
        
        # Validate and apply routing table
        if 'routing_table' in config:
            if isinstance(config['routing_table'], list):
                device.routing_table = config['routing_table']
        
        # Never accept credentials from network
        if 'credentials' in config:
            self._log_audit(f"Warning: Credentials update attempted from {source_host} - rejected")
        
        device.last_backup = datetime.now()
        self._log_config_change(device_id, f"remote_update from {source_host}")
        return True

    def save_config_to_file(self, device_id, filename):
        if device_id not in self.devices:
            return False

        # Validate filename
        if not isinstance(filename, str) or not filename.endswith('.json'):
            raise ValueError("Only .json files are allowed")

        config = {
            'device_id': device_id,
            'hostname': self.devices[device_id].hostname,
            'interfaces': self.devices[device_id].interfaces,
            'routing_table': self.devices[device_id].routing_table,
            # Never store credentials in files
            'timestamp': datetime.now().isoformat()
        }

        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)
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
        choice = input("Select option: ").strip()

        if choice == "1":
            try:
                host = input("Enter host: ").strip()
                port = int(input("Enter port: ").strip())
                if manager.load_config_from_network(host, port):
                    print("Configuration loaded successfully")
                else:
                    print("Failed to load configuration")
            except ValueError as e:
                print(f"Invalid input: {e}")
        elif choice == "2":
            try:
                device_id = input("Enter device ID: ").strip()
                filename = input("Enter filename: ").strip()
                if manager.save_config_to_file(device_id, filename):
                    print("Configuration saved successfully")
                else:
                    print("Failed to save configuration")
            except ValueError as e:
                print(f"Invalid input: {e}")
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