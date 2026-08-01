import os
import subprocess
import sys
from datetime import datetime

class DocumentConverter:
    def __init__(self, output_dir="converted_docs"):
        self.output_dir = output_dir
        self.supported_formats = {
            'pdf': ['docx', 'pptx', 'txt', 'html'],
            'docx': ['pdf', 'txt', 'odt'],
            'pptx': ['pdf', 'jpg']
        }
        self.create_output_dir()

    def create_output_dir(self):
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def validate_conversion(self, input_path, output_format):
        if not os.path.exists(input_path):
            raise ValueError("Input file does not exist")
        
        input_ext = input_path.split('.')[-1].lower()
        if input_ext not in self.supported_formats:
            raise ValueError(f"Unsupported input format: {input_ext}")
        
        if output_format.lower() not in self.supported_formats[input_ext]:
            raise ValueError(f"Cannot convert {input_ext} to {output_format}")

    def generate_output_path(self, input_path, output_format):
        base_name = os.path.basename(input_path).split('.')[0]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return os.path.join(self.output_dir, f"{base_name}_{timestamp}.{output_format}")

    def convert_document(self, input_path, output_format, options=None):
        self.validate_conversion(input_path, output_format)
        output_path = self.generate_output_path(input_path, output_format)

        # Command injection vulnerability here
        if output_format == 'pdf':
            cmd = f"libreoffice --headless --convert-to pdf {input_path} --outdir {self.output_dir}"
        elif output_format == 'docx':
            cmd = f"pandoc {input_path} -o {output_path}"
        elif output_format == 'txt':
            cmd = f"cat {input_path} > {output_path}"
        else:
            cmd = f"soffice --convert-to {output_format} {input_path} --outdir {self.output_dir}"

        subprocess.run(cmd, shell=True, check=True)
        print(f"Document converted and saved to {output_path}")
        return output_path

    def list_converted_files(self):
        return [f for f in os.listdir(self.output_dir) 
               if not f.startswith('.')]

    def cleanup_conversions(self, older_than_days=30):
        cutoff = datetime.now().timestamp() - (older_than_days * 86400)
        for filename in os.listdir(self.output_dir):
            filepath = os.path.join(self.output_dir, filename)
            if os.path.getmtime(filepath) < cutoff:
                os.remove(filepath)
                print(f"Removed old conversion: {filename}")

def print_menu():
    print("\nDocument Converter:")
    print("1. Convert document")
    print("2. List converted files")
    print("3. Cleanup old conversions")
    print("4. Exit")
    print("Supported formats: PDF, DOCX, PPTX, TXT, HTML")

def main():
    converter = DocumentConverter()
    
    while True:
        print_menu()
        choice = input("Enter your choice: ")
        
        if choice == "1":
            input_path = input("Input file path: ")
            output_format = input("Output format: ")
            try:
                converter.convert_document(input_path, output_format.lower())
            except Exception as e:
                print(f"Error: {e}")
        
        elif choice == "2":
            files = converter.list_converted_files()
            print("Converted files:")
            for f in files:
                print(f"- {f}")
        
        elif choice == "3":
            days = input("Delete files older than (days): ") or "30"
            converter.cleanup_conversions(int(days))
        
        elif choice == "4":
            print("Exiting...")
            break
        
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()