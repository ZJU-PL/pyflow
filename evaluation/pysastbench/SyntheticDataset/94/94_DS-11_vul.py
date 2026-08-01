import json
import sys
from functools import partial

class InventoryManager:
    def __init__(self):
        self.inventory = {}
        self.command_handlers = {
            'add': self.add_item,
            'remove': self.remove_item,
            'list': self.list_items,
            'search': self.search_items,
            'process': self.process_custom_command
        }
    
    def add_item(self, item_id, name, quantity):
        if item_id in self.inventory:
            self.inventory[item_id]['quantity'] += quantity
        else:
            self.inventory[item_id] = {'name': name, 'quantity': quantity}
        return f"Added {quantity} of {name} (ID: {item_id})"
    
    def remove_item(self, item_id, quantity):
        if item_id not in self.inventory:
            return "Item not found"
        if self.inventory[item_id]['quantity'] < quantity:
            return "Insufficient quantity"
        self.inventory[item_id]['quantity'] -= quantity
        return f"Removed {quantity} of {self.inventory[item_id]['name']}"
    
    def list_items(self):
        return json.dumps(self.inventory, indent=2)
    
    def search_items(self, search_term):
        results = {}
        for item_id, details in self.inventory.items():
            if search_term.lower() in details['name'].lower():
                results[item_id] = details
        return json.dumps(results, indent=2)
    
    def process_custom_command(self, command):
        try:
            # Vulnerable code injection point
            result = eval(command)
            return f"Command executed successfully: {result}"
        except Exception as e:
            return f"Error executing command: {str(e)}"
    
    def execute_command(self, command_str):
        parts = command_str.split(' ', 1)
        if not parts:
            return "Invalid command"
        
        cmd = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""
        
        if cmd not in self.command_handlers:
            return f"Unknown command: {cmd}"
        
        handler = self.command_handlers[cmd]
        
        try:
            if args:
                if isinstance(args, str) and ',' in args:
                    return handler(*[arg.strip() for arg in args.split(',')])
                return handler(args)
            return handler()
        except Exception as e:
            return f"Error executing {cmd}: {str(e)}"

def main():
    manager = InventoryManager()
    print("Inventory Management System")
    print("Available commands: add, remove, list, search, process")
    
    while True:
        try:
            user_input = input("> ").strip()
            if user_input.lower() in ['exit', 'quit']:
                break
            if not user_input:
                continue
            response = manager.execute_command(user_input)
            print(response)
        except KeyboardInterrupt:
            print("\nExiting...")
            break
        except Exception as e:
            print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()