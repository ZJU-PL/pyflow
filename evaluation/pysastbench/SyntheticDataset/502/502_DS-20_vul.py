import pickle
import json
import hashlib
import os
from datetime import datetime
from typing import Dict, List

class SmartDevice:
    def __init__(self, device_id: str, device_type: str):
        self.device_id = device_id
        self.device_type = device_type
        self.state = "off"
        self.last_updated = datetime.now()
        self.config = {}
        self.firmware_version = "1.0.0"
    
    def update_state(self, new_state: str) -> None:
        self.state = new_state
        self.last_updated = datetime.now()
    
    def update_config(self, config: Dict) -> None:
        self.config.update(config)
        self.last_updated = datetime.now()

class HomeAutomationHub:
    def __init__(self):
        self.devices: Dict[str, SmartDevice] = {}
        self.scenes: Dict[str, List[Dict]] = {}
        self.routines: Dict[str, Dict] = {}
        self.audit_log: List[Dict] = []
        os.makedirs("backups", exist_ok=True)
    
    def add_device(self, device_id: str, device_type: str) -> None:
        if device_id not in self.devices:
            self.devices[device_id] = SmartDevice(device_id, device_type)
            self._log_audit("DEVICE_ADDED", f"Added {device_type} with ID {device_id}")
    
    def import_device_config(self, config_data: bytes) -> bool:
        try:
            # Vulnerable deserialization point
            config = pickle.loads(config_data)
            return self._apply_device_config(config)
        except Exception as e:
            self._log_audit("CONFIG_IMPORT_FAILED", str(e))
            return False
    
    def _apply_device_config(self, config: Dict) -> bool:
        # This is the vulnerable function
        device_id = config.get("device_id")
        if not device_id or device_id not in self.devices:
            raise ValueError("Invalid device ID")
        
        device = self.devices[device_id]
        
        if "state" in config:
            device.update_state(config["state"])
        
        if "config" in config:
            device.update_config(config["config"])
        
        if "firmware" in config:
            device.firmware_version = config["firmware"]
        
        self._log_audit("CONFIG_UPDATED", f"Updated config for {device_id}")
        return True
    
    def backup_system(self, filename: str) -> bool:
        try:
            backup_data = {
                "devices": {did: device.__dict__ for did, device in self.devices.items()},
                "scenes": self.scenes,
                "routines": self.routines,
                "timestamp": datetime.now().isoformat()
            }
            
            with open(f"backups/{filename}", "wb") as f:
                pickle.dump(backup_data, f)
            
            self._log_audit("BACKUP_CREATED", filename)
            return True
        except Exception as e:
            self._log_audit("BACKUP_FAILED", str(e))
            return False
    
    def restore_backup(self, filename: str) -> bool:
        try:
            with open(f"backups/{filename}", "rb") as f:
                backup_data = pickle.load(f)
            
            self.devices.clear()
            for did, device_data in backup_data["devices"].items():
                device = SmartDevice(did, device_data["device_type"])
                device.__dict__.update(device_data)
                self.devices[did] = device
            
            self.scenes = backup_data.get("scenes", {})
            self.routines = backup_data.get("routines", {})
            
            self._log_audit("SYSTEM_RESTORED", filename)
            return True
        except Exception as e:
            self._log_audit("RESTORE_FAILED", str(e))
            return False
    
    def _log_audit(self, event_type: str, details: str) -> None:
        self.audit_log.append({
            "timestamp": datetime.now(),
            "event": event_type,
            "details": details
        })
    
    def get_audit_log(self) -> List[Dict]:
        return self.audit_log[-20:]

class SmartHomeApp:
    def __init__(self):
        self.hub = HomeAutomationHub()
    
    def add_new_device(self) -> None:
        device_id = input("Enter device ID: ")
        device_type = input("Enter device type: ")
        self.hub.add_device(device_id, device_type)
        print(f"Added {device_type} device with ID {device_id}")
    
    def import_device_config(self) -> None:
        config_file = input("Enter config file path: ")
        with open(config_file, "rb") as f:
            if self.hub.import_device_config(f.read()):
                print("Device config imported successfully")
            else:
                print("Failed to import device config")
    
    def create_backup(self) -> None:
        filename = input("Enter backup filename: ")
        if self.hub.backup_system(filename):
            print("Backup created successfully")
        else:
            print("Failed to create backup")
    
    def restore_backup(self) -> None:
        filename = input("Enter backup filename: ")
        if self.hub.restore_backup(filename):
            print("System restored successfully")
        else:
            print("Failed to restore backup")
    
    def show_audit_log(self) -> None:
        print("\nRecent audit events:")
        for entry in self.hub.get_audit_log():
            print(f"{entry['timestamp']} - {entry['event']}: {entry['details']}")

def main():
    app = SmartHomeApp()
    print("Smart Home Automation System")
    
    while True:
        print("\n1. Add new device")
        print("2. Import device config")
        print("3. Create backup")
        print("4. Restore backup")
        print("5. View audit log")
        print("6. Exit")
        choice = input("Select option: ")
        
        if choice == "1":
            app.add_new_device()
        elif choice == "2":
            app.import_device_config()
        elif choice == "3":
            app.create_backup()
        elif choice == "4":
            app.restore_backup()
        elif choice == "5":
            app.show_audit_log()
        elif choice == "6":
            break
        else:
            print("Invalid option")

if __name__ == "__main__":
    main()