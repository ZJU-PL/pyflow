import subprocess
import argparse
import os
import sys
import tempfile
from pathlib import Path
from typing import Optional

class DocumentConverter:
    SUPPORTED_FORMATS = ['pdf', 'docx', 'odt', 'txt']

    def __init__(self, output_dir: str = 'converted'):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

    def _sanitize_filename(self, filename: str) -> str:
        return ''.join(c for c in filename if c.isalnum() or c in (' ', '.', '_')).strip()

    def convert_file(self, input_path: str, output_format: str) -> Optional[str]:
        if output_format not in self.SUPPORTED_FORMATS:
            print(f"Unsupported format: {output_format}", file=sys.stderr)
            return None

        input_file = Path(input_path)
        if not input_file.exists():
            print(f"Input file not found: {input_path}", file=sys.stderr)
            return None

        output_filename = f"{input_file.stem}.{output_format}"
        output_path = str(self.output_dir / self._sanitize_filename(output_filename))

        try:
            # Vulnerable function - command injection via input_path
            cmd = f"soffice --headless --convert-to {output_format} --outdir {self.output_dir} '{input_path}'"
            subprocess.run(cmd, shell=True, check=True, capture_output=True)
            
            if not Path(output_path).exists():
                # Try alternative output path pattern (LibreOffice sometimes changes the name)
                alt_output = str(self.output_dir / f"{input_file.stem}.{output_format}")
                if Path(alt_output).exists():
                    return alt_output
                return None
            return output_path
        except subprocess.CalledProcessError as e:
            print(f"Conversion failed: {e.stderr.decode()}", file=sys.stderr)
            return None

    def batch_convert(self, input_dir: str, output_format: str) -> list:
        input_dir = Path(input_dir)
        if not input_dir.exists():
            print(f"Input directory not found: {input_dir}", file=sys.stderr)
            return []

        converted_files = []
        for file in input_dir.iterdir():
            if file.is_file():
                result = self.convert_file(str(file), output_format)
                if result:
                    converted_files.append(result)
        return converted_files

def main():
    parser = argparse.ArgumentParser(description="Document Conversion Tool")
    subparsers = parser.add_subparsers(dest="command", required=True)

    single_parser = subparsers.add_parser("convert", help="Convert single file")
    single_parser.add_argument("input_file", help="Path to input file")
    single_parser.add_argument("format", help="Output format", choices=DocumentConverter.SUPPORTED_FORMATS)

    batch_parser = subparsers.add_parser("batch", help="Convert all files in directory")
    batch_parser.add_argument("input_dir", help="Path to input directory")
    batch_parser.add_argument("format", help="Output format", choices=DocumentConverter.SUPPORTED_FORMATS)

    args = parser.parse_args()
    converter = DocumentConverter()

    if args.command == "convert":
        result = converter.convert_file(args.input_file, args.format)
        if result:
            print(f"File converted successfully: {result}")
        else:
            sys.exit(1)
    elif args.command == "batch":
        results = converter.batch_convert(args.input_dir, args.format)
        if results:
            print(f"Converted {len(results)} files:")
            for file in results:
                print(f"- {file}")
        else:
            print("No files were converted", file=sys.stderr)
            sys.exit(1)

if __name__ == "__main__":
    main()