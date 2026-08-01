import os
import subprocess
import sys
from PIL import Image

class ImageProcessor:
    def __init__(self, output_dir="processed_images"):
        self.output_dir = output_dir
        self.supported_formats = ['jpg', 'jpeg', 'png', 'bmp']
        self.supported_filters = ['blur', 'sharpen', 'grayscale', 'edge']
        self.create_output_dir()

    def create_output_dir(self):
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def validate_image(self, image_path):
        if not os.path.exists(image_path):
            raise ValueError("Image file does not exist")
        if not any(image_path.lower().endswith(ext) for ext in self.supported_formats):
            raise ValueError("Unsupported image format")
        try:
            Image.open(image_path).verify()
        except:
            raise ValueError("Invalid image file")

    def apply_filter(self, image_path, filter_type, output_name=None):
        self.validate_image(image_path)
        
        # Validate filter type
        if filter_type not in self.supported_filters:
            raise ValueError(f"Unsupported filter type. Supported filters: {', '.join(self.supported_filters)}")
        
        if not output_name:
            base_name = os.path.splitext(os.path.basename(image_path))[0]
            output_name = f"{base_name}_{filter_type}.png"
        
        output_path = os.path.join(self.output_dir, output_name)

        # Fixed command execution - no shell injection
        try:
            subprocess.run(
                ['convert', image_path, f'-{filter_type}', output_path],
                check=True,
                stderr=subprocess.PIPE
            )
            print(f"Filter applied and saved to {output_path}")
            return output_path
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to apply filter: {e.stderr.decode().strip()}")
        except Exception as e:
            raise RuntimeError(f"Error during image processing: {str(e)}")

    def list_processed_images(self):
        return [f for f in os.listdir(self.output_dir) 
               if any(f.lower().endswith(ext) for ext in self.supported_formats)]

def print_menu():
    print("\nImage Processor Menu:")
    print("1. Apply filter to image")
    print("2. List processed images")
    print("3. Exit")
    print(f"Available filters: {', '.join(ImageProcessor().supported_filters)}")

def main():
    processor = ImageProcessor()
    
    while True:
        print_menu()
        choice = input("Enter your choice: ")
        
        if choice == "1":
            image_path = input("Enter image path: ")
            filter_type = input("Enter filter type: ")
            try:
                processor.apply_filter(image_path, filter_type)
            except Exception as e:
                print(f"Error: {e}")
        
        elif choice == "2":
            images = processor.list_processed_images()
            print("Processed images:")
            for img in images:
                print(f"- {img}")
        
        elif choice == "3":
            print("Exiting...")
            break
        
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()