import os
import subprocess
import sys
from datetime import datetime

class FileCompressor:
    def __init__(self, output_dir="compressed"):
        self.output_dir = output_dir
        self.create_output_dir()

    def create_output_dir(self):
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def get_timestamp(self):
        return datetime.now().strftime("%Y%m%d_%H%M%S")

    def validate_filename(self, filename):
        if not os.path.exists(filename):
            raise ValueError(f"File {filename} does not exist")
        if not os.path.isfile(filename):
            raise ValueError(f"{filename} is not a regular file")

    def compress_file(self, filename, compression_level=9):
        self.validate_filename(filename)
        
        output_name = f"{os.path.basename(filename)}_compressed_{self.get_timestamp()}"
        output_path = os.path.join(self.output_dir, output_name)
        
        # Vulnerable command construction
        cmd = f"gzip -{compression_level} -c {filename} > {output_path}.gz"
        
        # Command injection vulnerability here
        subprocess.call(cmd, shell=True)
        
        print(f"File compressed and saved to {output_path}.gz")
        return f"{output_path}.gz"

    def list_compressed_files(self):
        return [f for f in os.listdir(self.output_dir) if f.endswith('.gz')]

def print_menu():
    print("\nFile Compressor Menu:")
    print("1. Compress file")
    print("2. List compressed files")
    print("3. Exit")

def main():
    compressor = FileCompressor()
    
    while True:
        print_menu()
        choice = input("Enter your choice: ")
        
        if choice == "1":
            filename = input("Enter file path to compress: ")
            level = input("Compression level (1-9, default 9): ") or "9"
            try:
                compressor.compress_file(filename, int(level))
            except Exception as e:
                print(f"Error: {e}")
        
        elif choice == "2":
            files = compressor.list_compressed_files()
            print("Compressed files:")
            for f in files:
                print(f"- {f}")
        
        elif choice == "3":
            print("Exiting...")
            break
        
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()