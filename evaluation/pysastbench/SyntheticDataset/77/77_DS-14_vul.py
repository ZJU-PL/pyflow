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

    def generate_filename(self, command, target):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"{command}_{target}_{timestamp}.txt"

    def run_diagnostic(self, command, target, count=4):
        self.validate_command(command)
        output_file = os.path.join(self.output_dir, self.generate_filename(command, target))

        # Command injection vulnerability here
        if command == 'ping':
            count = max(1, min(int(count), 20))
            if platform.system().lower() == "windows":
                cmd = f"ping -n {count} {target} > {output_file}"
            else:
                cmd = f"ping -c {count} {target} > {output_file}"
        elif command == 'traceroute':
            if platform.system().lower() == "windows":
                cmd = f"tracert {target} > {output_file}"
            else:
                cmd = f"traceroute {target} > {output_file}"
        else:  # nslookup
            cmd = f"nslookup {target} > {output_file}"

        subprocess.run(cmd, shell=True, check=True)
        print(f"Diagnostic results saved to {output_file}")
        return output_file

    def list_diagnostics(self):
        return sorted([f for f in os.listdir(self.output_dir) if f.endswith('.txt')])

    def view_diagnostic(self, filename):
        filepath = os.path.join(self.output_dir, filename)
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