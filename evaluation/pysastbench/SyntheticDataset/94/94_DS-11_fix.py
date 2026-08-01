import json
import sys
from functools import partial
from enum import Enum, auto

class CommandType(Enum):
    ADD = auto()
    REMOVE = auto()
    LIST = auto()
    SEARCH = auto()
    CUSTOM = auto()

class InventoryManager:
    def __init__(self):
        self.inventory = {}
        self.command_handlers = {
            'add': (CommandType.ADD, self.add_item),
            'remove': (CommandType.REMOVE, self.remove_item),
            'list': (CommandType.LIST, self.list_items),
            'search': (CommandType.SEARCH, self.search_items),
            'custom': (CommandType.CUSTOM, self.safe_custom_command)
        }
        self.safe_operations = {
            'count': lambda: len(self.inventory),
            'total_items': lambda: sum(item['quantity'] for item in self.inventory.values())
        }
    
    def add_item(self, item_id, name, quantity):
        try:
            quantity = int(quantity)
            if quantity <= 0:
                return "Quantity must be positive"
                
            if item_id in self.inventory:
                self.inventory[item_id]['quantity'] += quantity
            else:
                self.inventory[item_id] = {'name': name, 'quantity': quantity}
            return f"Added {quantity} of {name} (ID: {item_id})"
        except ValueError:
            return "Quantity must be a number"

    def remove_item(self, item_id, quantity):
        try:
            quantity = int(quantity)
            if quantity <= 0:
                return "Quantity must be positive"
                
            if item_id not in self.inventory:
                return "Item not found"
            if self.inventory[item_id]['quantity'] < quantity:
                return "Insufficient quantity"
            self.inventory[item_id]['quantity'] -= quantity
            return f"Removed {quantity} of {self.inventory[item_id]['name']}"
        except ValueError:
            return "Quantity must be a number"
    
    def list_items(self):
        return json.dumps(self.inventory, indent=2)
    
    def search_items(self, search_term):
        results = {}
        for item_id, details in self.inventory.items():
            if search_term.lower() in details['name'].lower():
                results[item_id] = details
        return json.dumps(results, indent=2)
    
    def safe_custom_command(self, operation):
        if operation not in self.safe_operations:
            return f"Unknown operation: {operation}. Available: {', '.join(self.safe_operations.keys())}"
        try:
            result = self.safe_operations[operation]()
            return f"Operation '{operation}' result: {result}"
        except Exception as e:
            return f"Error executing operation: {str(e)}"
    
    def execute_command(self, command_str):
        parts = command_str.split(' ', 1)
        if not parts:
            return "Invalid command"
        
        cmd = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""
        
        if cmd not in self.command_handlers:
            return f"Unknown command: {cmd}. Available: {', '.join(self.command_handlers.keys())}"
        
        cmd_type, handler = self.command_handlers[cmd]
        
        try:
            if cmd_type == CommandType.CUSTOM:
                return handler(args)
            elif args:
                if ',' in args:
                    return handler(*[arg.strip() for arg in args.split(',')])
                return handler(args)
            return handler()
        except Exception as e:
            return f"Error executing {cmd}: {str(e)}"

def main():
    manager = InventoryManager()
    print("Inventory Management System")
    print("Available commands: add, remove, list, search, custom")
    print("Available custom operations: " + ", ".join(manager.safe_operations.keys()))
    
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