import subprocess
import argparse
import os
import sys
import shlex
from pathlib import Path
from typing import Optional, List

class VideoProcessor:
    def __init__(self, output_dir: str = "processed"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

    def _generate_output_path(self, input_path: Path, suffix: str) -> Path:
        return self.output_dir / f"{input_path.stem}_{suffix}{input_path.suffix}"

    def _validate_timestamp(self, timestamp: str) -> bool:
        try:
            parts = list(map(int, timestamp.split(':')))
            if len(parts) != 3:
                return False
            if parts[0] < 0 or parts[1] < 0 or parts[1] > 59 or parts[2] < 0 or parts[2] > 59:
                return False
            return True
        except ValueError:
            return False

    def extract_audio(self, video_path: str) -> Optional[str]:
        input_path = Path(video_path)
        if not input_path.exists():
            print(f"Error: Input file {video_path} not found", file=sys.stderr)
            return None

        output_path = self._generate_output_path(input_path, "audio")
        try:
            cmd = [
                "ffmpeg",
                "-i", str(input_path),
                "-vn",
                "-acodec", "copy",
                str(output_path)
            ]
            subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return str(output_path)
        except subprocess.CalledProcessError as e:
            print(f"Error extracting audio: {e.stderr.decode()}", file=sys.stderr)
            return None

    def create_thumbnail(self, video_path: str, timestamp: str = "00:00:01") -> Optional[str]:
        input_path = Path(video_path)
        if not input_path.exists():
            print(f"Error: Input file {video_path} not found", file=sys.stderr)
            return None

        if not self._validate_timestamp(timestamp):
            print(f"Error: Invalid timestamp format {timestamp}", file=sys.stderr)
            return None

        output_path = self.output_dir / f"{input_path.stem}_thumbnail.jpg"
        try:
            cmd = [
                "ffmpeg",
                "-ss", timestamp,
                "-i", str(input_path),
                "-vframes", "1",
                "-q:v", "2",
                str(output_path)
            ]
            subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return str(output_path)
        except subprocess.CalledProcessError as e:
            print(f"Error creating thumbnail: {e.stderr.decode()}", file=sys.stderr)
            return None

    def process_video(self, video_path: str, operations: List[str]) -> bool:
        try:
            input_path = Path(video_path)
            if not input_path.exists():
                print(f"Error: Input file {video_path} not found", file=sys.stderr)
                return False

            # Validate operations to prevent injection
            valid_operations = []
            for op in operations:
                # Basic validation - allow only alphanumeric and safe filter characters
                if all(c.isalnum() or c in ['=', ':', ',', '-', '_', ' ', "'", '"'] for c in op):
                    valid_operations.append(op)
                else:
                    print(f"Warning: Skipping potentially unsafe operation: {op}", file=sys.stderr)

            if not valid_operations:
                print("Error: No valid operations provided", file=sys.stderr)
                return False

            output_path = self._generate_output_path(input_path, "processed")
            cmd = [
                "ffmpeg",
                "-i", str(input_path),
                "-vf", ",".join(valid_operations),
                str(output_path)
            ]
            subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return True
        except subprocess.CalledProcessError as e:
            print(f"Error processing video: {e.stderr.decode()}", file=sys.stderr)
            return False

def main():
    parser = argparse.ArgumentParser(description="Video Processing Utility")
    subparsers = parser.add_subparsers(dest="command", required=True)

    audio_parser = subparsers.add_parser("audio", help="Extract audio from video")
    audio_parser.add_argument("video_file", help="Path to video file")

    thumb_parser = subparsers.add_parser("thumbnail", help="Create video thumbnail")
    thumb_parser.add_argument("video_file", help="Path to video file")
    thumb_parser.add_argument("--time", default="00:00:01", help="Timestamp for thumbnail")

    process_parser = subparsers.add_parser("process", help="Process video with filters")
    process_parser.add_argument("video_file", help="Path to video file")
    process_parser.add_argument("operations", nargs="+", help="FFmpeg filter operations")

    args = parser.parse_args()
    processor = VideoProcessor()

    if args.command == "audio":
        result = processor.extract_audio(args.video_file)
        if result:
            print(f"Audio extracted to: {result}")
    elif args.command == "thumbnail":
        result = processor.create_thumbnail(args.video_file, args.time)
        if result:
            print(f"Thumbnail created at: {result}")
    elif args.command == "process":
        success = processor.process_video(args.video_file, args.operations)
        if success:
            print("Video processed successfully")

if __name__ == "__main__":
    main()