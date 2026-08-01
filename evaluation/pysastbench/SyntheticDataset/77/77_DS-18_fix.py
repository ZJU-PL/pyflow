import os
import subprocess
import sys
from datetime import datetime

class VideoProcessor:
    def __init__(self, output_dir="processed_videos"):
        self.output_dir = output_dir
        self.supported_formats = ['mp4', 'avi', 'mov', 'mkv']
        self.supported_operations = ['trim', 'resize', 'convert']
        self.create_output_dir()

    def create_output_dir(self):
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def validate_video(self, video_path):
        if not os.path.exists(video_path):
            raise ValueError("Video file does not exist")
        if not any(video_path.lower().endswith(ext) for ext in self.supported_formats):
            raise ValueError("Unsupported video format")

    def validate_time_format(self, time_str):
        parts = time_str.split(':')
        if len(parts) != 3:
            return False
        try:
            return all(0 <= int(part) < 60 for part in parts[-2:]) and int(parts[0]) >= 0
        except ValueError:
            return False

    def validate_dimension(self, dim):
        try:
            return 100 <= int(dim) <= 7680  # Reasonable video dimension limits
        except ValueError:
            return False

    def generate_output_name(self, video_path, operation):
        base_name = os.path.splitext(os.path.basename(video_path))[0]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"{base_name}_{operation}_{timestamp}.mp4"

    def process_video(self, video_path, operation, params=None):
        self.validate_video(video_path)
        if operation not in self.supported_operations:
            raise ValueError("Unsupported operation")
            
        output_name = self.generate_output_name(video_path, operation)
        output_path = os.path.join(self.output_dir, output_name)

        try:
            args = ['ffmpeg', '-i', video_path]
            
            if operation == "trim":
                start = params.get("start", "00:00:00")
                end = params.get("end", "00:01:00")
                if not (self.validate_time_format(start) and self.validate_time_format(end)):
                    raise ValueError("Invalid time format (use HH:MM:SS)")
                args.extend(['-ss', start, '-to', end, '-c', 'copy'])
            
            elif operation == "resize":
                width = params.get("width", "640")
                height = params.get("height", "480")
                if not (self.validate_dimension(width) and self.validate_dimension(height)):
                    raise ValueError("Invalid dimensions (100-7680)")
                args.extend(['-vf', f'scale={width}:{height}'])
            
            elif operation == "convert":
                pass  # Just basic conversion with default args
            
            args.append(output_path)
            
            result = subprocess.run(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            if result.returncode != 0:
                raise RuntimeError(f"FFmpeg failed: {result.stderr.strip()}")

            print(f"Video processed and saved to {output_path}")
            return output_path
            
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Video processing failed: {e.stderr.strip()}")
        except Exception as e:
            raise RuntimeError(f"Error during video processing: {str(e)}")

    def list_processed_videos(self):
        return [f for f in os.listdir(self.output_dir) if f.endswith('.mp4')]

def print_menu():
    print("\nVideo Processing Tool:")
    print("1. Trim video")
    print("2. Resize video")
    print("3. Convert format")
    print("4. List processed videos")
    print("5. Exit")
    print("Note: Custom filters are disabled for security reasons")

def main():
    processor = VideoProcessor()
    
    while True:
        print_menu()
        choice = input("Enter your choice: ")
        
        if choice == "1":
            video_path = input("Video file path: ")
            start = input("Start time (HH:MM:SS): ") or "00:00:00"
            end = input("End time (HH:MM:SS): ") or "00:01:00"
            try:
                processor.process_video(video_path, "trim", {"start": start, "end": end})
            except Exception as e:
                print(f"Error: {e}")
        
        elif choice == "2":
            video_path = input("Video file path: ")
            width = input("Width (100-7680): ") or "640"
            height = input("Height (100-7680): ") or "480"
            try:
                processor.process_video(video_path, "resize", {"width": width, "height": height})
            except Exception as e:
                print(f"Error: {e}")
        
        elif choice == "3":
            video_path = input("Video file path: ")
            try:
                processor.process_video(video_path, "convert")
            except Exception as e:
                print(f"Error: {e}")
        
        elif choice == "4":
            videos = processor.list_processed_videos()
            print("Processed videos:")
            for video in videos:
                print(f"- {video}")
        
        elif choice == "5":
            print("Exiting...")
            break
        
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()