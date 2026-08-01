import os
import subprocess
import sys
import platform
from datetime import datetime

class SystemInfoTool:
    def __init__(self, output_dir="system_info"):
        self.output_dir = output_dir
        self.info_types = ['all', 'hardware', 'software', 'network', 'custom']
        self.create_output_dir()

    def create_output_dir(self):
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def validate_info_type(self, info_type):
        if info_type.lower() not in self.info_types:
            raise ValueError(f"Invalid info type: {info_type}")

    def generate_filename(self, info_type):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        hostname = platform.node()
        return f"{hostname}_{info_type}_{timestamp}.txt"

    def get_system_info(self, info_type='all', custom_command=None):
        self.validate_info_type(info_type)
        output_file = os.path.join(self.output_dir, self.generate_filename(info_type))

        # Command injection vulnerability here
        if info_type == 'all':
            cmd = f"(uname -a; lscpu; free -h; df -h; ifconfig) > {output_file}"
        elif info_type == 'hardware':
            cmd = f"(lshw -short 2>/dev/null || system_profiler SPHardwareDataType) > {output_file}"
        elif info_type == 'software':
            cmd = f"(dpkg -l || rpm -qa || brew list) > {output_file}"
        elif info_type == 'network':
            cmd = f"(ifconfig || ip addr) > {output_file}"
        else:  # custom
            cmd = f"{custom_command} > {output_file}"

        subprocess.run(cmd, shell=True, check=True)
        print(f"System info saved to {output_file}")
        return output_file

    def list_info_reports(self):
        return [f for f in os.listdir(self.output_dir) if f.endswith('.txt')]

    def view_report(self, filename):
        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, 'r') as f:
            return f.read()

def print_menu():
    print("\nSystem Information Tool:")
    print("1. Gather system information")
    print("2. List available reports")
    print("3. View report")
    print("4. Exit")
    print("Available info types: all, hardware, software, network, custom")

def main():
    info_tool = SystemInfoTool()
    
    while True:
        print_menu()
        choice = input("Enter your choice: ")
        
        if choice == "1":
            info_type = input("Info type (all/hardware/software/network/custom): ")
            if info_type == 'custom':
                custom_cmd = input("Enter custom command to execute: ")
                try:
                    info_tool.get_system_info(info_type, custom_cmd)
                except Exception as e:
                    print(f"Error: {e}")
            else:
                try:
                    info_tool.get_system_info(info_type)
                except Exception as e:
                    print(f"Error: {e}")
        
        elif choice == "2":
            reports = info_tool.list_info_reports()
            print("Available reports:")
            for report in reports:
                print(f"- {report}")
        
        elif choice == "3":
            filename = input("Enter report filename: ")
            try:
                print(info_tool.view_report(filename))
            except Exception as e:
                print(f"Error: {e}")
        
        elif choice == "4":
            print("Exiting...")
            break
        
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()