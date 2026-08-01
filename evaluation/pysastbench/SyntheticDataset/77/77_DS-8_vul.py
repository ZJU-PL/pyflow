import subprocess
import argparse
import os
import sys
from pathlib import Path
from typing import Optional, List

class VideoProcessor:
    def __init__(self, output_dir: str = "processed"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

    def _generate_output_path(self, input_path: Path, suffix: str) -> Path:
        return self.output_dir / f"{input_path.stem}_{suffix}{input_path.suffix}"

    def extract_audio(self, video_path: str) -> Optional[str]:
        input_path = Path(video_path)
        if not input_path.exists():
            print(f"Error: Input file {video_path} not found", file=sys.stderr)
            return None

        output_path = self._generate_output_path(input_path, "audio")
        try:
            cmd = f"ffmpeg -i '{video_path}' -vn -acodec copy {output_path}"
            subprocess.run(cmd, shell=True, check=True)
            return str(output_path)
        except subprocess.CalledProcessError as e:
            print(f"Error extracting audio: {e}", file=sys.stderr)
            return None

    def create_thumbnail(self, video_path: str, timestamp: str = "00:00:01") -> Optional[str]:
        input_path = Path(video_path)
        if not input_path.exists():
            print(f"Error: Input file {video_path} not found", file=sys.stderr)
            return None

        output_path = self.output_dir / f"{input_path.stem}_thumbnail.jpg"
        try:
            cmd = f"ffmpeg -ss {timestamp} -i '{video_path}' -vframes 1 -q:v 2 {output_path}"
            subprocess.run(cmd, shell=True, check=True)
            return str(output_path)
        except subprocess.CalledProcessError as e:
            print(f"Error creating thumbnail: {e}", file=sys.stderr)
            return None

    def process_video(self, video_path: str, operations: List[str]) -> bool:
        # Vulnerable function - command injection via operations list
        try:
            input_path = Path(video_path)
            if not input_path.exists():
                print(f"Error: Input file {video_path} not found", file=sys.stderr)
                return False

            output_path = self._generate_output_path(input_path, "processed")
            ffmpeg_filters = ",".join(operations)
            cmd = f"ffmpeg -i '{video_path}' -vf '{ffmpeg_filters}' {output_path}"
            subprocess.run(cmd, shell=True, check=True)
            return True
        except subprocess.CalledProcessError as e:
            print(f"Error processing video: {e}", file=sys.stderr)
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