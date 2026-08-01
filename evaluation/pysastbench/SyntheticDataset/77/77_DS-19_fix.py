import os
import subprocess
import sys
from datetime import datetime

class DNSLookupTool:
    def __init__(self, output_dir="dns_results"):
        self.output_dir = output_dir
        self.supported_lookups = ['A', 'MX', 'NS', 'TXT', 'CNAME']
        self.create_output_dir()

    def create_output_dir(self):
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def validate_domain(self, domain):
        if not domain or '.' not in domain:
            raise ValueError("Invalid domain format")
        # Basic validation to prevent command injection
        if any(char in domain for char in ";&|<>$()"):
            raise ValueError("Invalid characters in domain")

    def validate_record_type(self, record_type):
        if record_type not in self.supported_lookups:
            raise ValueError(f"Unsupported record type: {record_type}")

    def generate_filename(self, domain, lookup_type):
        safe_domain = "".join(c for c in domain if c.isalnum() or c in '.-')
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"{safe_domain}_{lookup_type}_{timestamp}.txt"

    def perform_lookup(self, domain, lookup_type='A'):
        self.validate_domain(domain)
        self.validate_record_type(lookup_type)
        output_file = os.path.join(self.output_dir, self.generate_filename(domain, lookup_type))

        try:
            with open(output_file, 'w') as f:
                subprocess.run(
                    ['dig', domain, lookup_type, '+short'],
                    stdout=f,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=True
                )
            print(f"Results saved to {output_file}")
            return output_file
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"DNS lookup failed: {e.stderr.strip()}")
        except Exception as e:
            raise RuntimeError(f"Error during DNS lookup: {str(e)}")

    def list_lookup_results(self):
        return [f for f in os.listdir(self.output_dir) if f.endswith('.txt')]

    def view_results(self, filename):
        # Prevent path traversal
        if not filename.endswith('.txt') or '/' in filename or '\\' in filename:
            raise ValueError("Invalid filename")
            
        filepath = os.path.join(self.output_dir, filename)
        if not os.path.exists(filepath):
            raise FileNotFoundError("Result file not found")
            
        with open(filepath, 'r') as f:
            return f.read()

def print_menu():
    print("\nDNS Lookup Tool:")
    print("1. Perform DNS lookup")
    print("2. List previous lookups")
    print("3. View lookup results")
    print("4. Exit")
    print(f"Supported record types: {', '.join(DNSLookupTool().supported_lookups)}")

def main():
    dns_tool = DNSLookupTool()
    
    while True:
        print_menu()
        choice = input("Enter your choice: ")
        
        if choice == "1":
            domain = input("Domain to lookup: ")
            lookup_type = input("Record type (A/MX/NS/TXT/CNAME): ").upper()
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