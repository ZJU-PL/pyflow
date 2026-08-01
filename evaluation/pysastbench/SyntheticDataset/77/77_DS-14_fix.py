import os
import subprocess
import sys
import platform
from datetime import datetime

class NetworkDiagnosticTool:
    def __init__(self, output_dir="diagnostics"):
        self.output_dir = output_dir
        self.supported_commands = ['ping', 'traceroute', 'nslookup']
        self.create_output_dir()

    def create_output_dir(self):
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def validate_command(self, command):
        if command.lower() not in self.supported_commands:
            raise ValueError(f"Unsupported diagnostic command: {command}")

    def validate_target(self, target):
        """Basic validation for target host/domain"""
        if not target or any(char in target for char in ";&|<>$()"):
            raise ValueError("Invalid target specified")

    def generate_filename(self, command, target):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = "".join(c for c in target if c.isalnum() or c in '.-_')
        return f"{command}_{safe_target}_{timestamp}.txt"

    def run_diagnostic(self, command, target, count=4):
        self.validate_command(command)
        self.validate_target(target)
        output_file = os.path.join(self.output_dir, self.generate_filename(command, target))

        try:
            if command == 'ping':
                count = max(1, min(int(count), 20))
                if platform.system().lower() == "windows":
                    args = ['ping', '-n', str(count), target]
                else:
                    args = ['ping', '-c', str(count), target]
            elif command == 'traceroute':
                if platform.system().lower() == "windows":
                    args = ['tracert', target]
                else:
                    args = ['traceroute', target]
            else:  # nslookup
                args = ['nslookup', target]

            # Securely execute command and capture output
            with open(output_file, 'w') as f:
                result = subprocess.run(
                    args,
                    stdout=f,
                    stderr=subprocess.PIPE,
                    text=True
                )

            if result.returncode != 0:
                raise RuntimeError(f"Command failed: {result.stderr.strip()}")

            print(f"Diagnostic results saved to {output_file}")
            return output_file
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Diagnostic failed: {e.stderr.strip()}")
        except Exception as e:
            raise RuntimeError(f"Error during diagnostic: {str(e)}")

    def list_diagnostics(self):
        return sorted([f for f in os.listdir(self.output_dir) if f.endswith('.txt')])

    def view_diagnostic(self, filename):
        # Prevent directory traversal
        if not filename.endswith('.txt') or '/' in filename or '\\' in filename:
            raise ValueError("Invalid filename")
            
        filepath = os.path.join(self.output_dir, filename)
        if not os.path.exists(filepath):
            raise FileNotFoundError("Diagnostic file not found")
            
        with open(filepath, 'r') as f:
            return f.read()

def print_menu():
    print("\nNetwork Diagnostic Tool:")
    print("1. Run diagnostic")
    print("2. List previous diagnostics")
    print("3. View diagnostic results")
    print("4. Exit")
    print("Available commands: ping, traceroute, nslookup")

def main():
    diagnostic_tool = NetworkDiagnosticTool()
    
    while True:
        print_menu()
        choice = input("Enter your choice: ")
        
        if choice == "1":
            command = input("Diagnostic command (ping/traceroute/nslookup): ")
            target = input("Target host or domain: ")
            if command == 'ping':
                count = input("Ping count (1-20, default 4): ") or "4"
            try:
                if command == 'ping':
                    diagnostic_tool.run_diagnostic(command, target, count)
                else:
                    diagnostic_tool.run_diagnostic(command, target)
            except Exception as e:
                print(f"Error: {e}")
        
        elif choice == "2":
            diagnostics = diagnostic_tool.list_diagnostics()
            print("Available diagnostics:")
            for diag in diagnostics:
                print(f"- {diag}")
        
        elif choice == "3":
            filename = input("Enter diagnostic filename: ")
            try:
                print(diagnostic_tool.view_diagnostic(filename))
            except Exception as e:
                print(f"Error: {e}")
        
        elif choice == "4":
            print("Exiting...")
            break
        
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()