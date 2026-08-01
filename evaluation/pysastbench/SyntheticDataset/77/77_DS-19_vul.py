import os
import subprocess
import sys
from datetime import datetime

class DNSLookupTool:
    def __init__(self, output_dir="dns_results"):
        self.output_dir = output_dir
        self.supported_lookups = ['A', 'MX', 'NS', 'TXT', 'CNAME', 'custom']
        self.create_output_dir()

    def create_output_dir(self):
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def validate_domain(self, domain):
        if not domain or '.' not in domain:
            raise ValueError("Invalid domain format")

    def generate_filename(self, domain, lookup_type):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"{domain}_{lookup_type}_{timestamp}.txt"

    def perform_lookup(self, domain, lookup_type='A', custom_type=None):
        self.validate_domain(domain)
        output_file = os.path.join(self.output_dir, self.generate_filename(domain, lookup_type))

        # Command injection vulnerability here
        if lookup_type == 'custom':
            if not custom_type:
                raise ValueError("Custom type required")
            cmd = f"dig {domain} {custom_type} +short > {output_file}"
        else:
            cmd = f"dig {domain} {lookup_type} +short > {output_file}"

        subprocess.run(cmd, shell=True, check=True)
        print(f"Results saved to {output_file}")
        return output_file

    def list_lookup_results(self):
        return [f for f in os.listdir(self.output_dir) if f.endswith('.txt')]

    def view_results(self, filename):
        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, 'r') as f:
            return f.read()

def print_menu():
    print("\nDNS Lookup Tool:")
    print("1. Perform DNS lookup")
    print("2. List previous lookups")
    print("3. View lookup results")
    print("4. Exit")
    print("Supported record types: A, MX, NS, TXT, CNAME, custom")

def main():
    dns_tool = DNSLookupTool()
    
    while True:
        print_menu()
        choice = input("Enter your choice: ")
        
        if choice == "1":
            domain = input("Domain to lookup: ")
            lookup_type = input("Record type (A/MX/NS/TXT/CNAME/custom): ")
            if lookup_type == 'custom':
                custom_type = input("Enter custom record type: ")
                try:
                    dns_tool.perform_lookup(domain, lookup_type, custom_type)
                except Exception as e:
                    print(f"Error: {e}")
            else:
                try:
                    dns_tool.perform_lookup(domain, lookup_type)
                except Exception as e:
                    print(f"Error: {e}")
        
        elif choice == "2":
            results = dns_tool.list_lookup_results()
            print("Available results:")
            for result in results:
                print(f"- {result}")
        
        elif choice == "3":
            filename = input("Enter result filename: ")
            try:
                print(dns_tool.view_results(filename))
            except Exception as e:
                print(f"Error: {e}")
        
        elif choice == "4":
            print("Exiting...")
            break
        
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()