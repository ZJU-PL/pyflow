"""
FP Regression Test: argparse path arguments.

This pattern is COMMON in CLI tools and should NOT be flagged as PATH_INJECTION.
The user who runs the CLI is the same person providing the path - this is 
intentional, not an attack.

Expected: NO FINDINGS (or LOW confidence if any)
"""
import argparse
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="A CLI tool")
    parser.add_argument("--config", type=str, default="config.yaml",
                        help="Path to configuration file")
    parser.add_argument("--input", type=Path, help="Input file path")
    parser.add_argument("--output", type=str, help="Output directory")
    
    args = parser.parse_args()
    
    # These should NOT be flagged as PATH_INJECTION
    # The user controls both the CLI and the paths
    config_path = Path(args.config)
    if config_path.exists():
        with open(args.config, 'r') as f:  # Should NOT flag
            config = f.read()
    
    if args.input:
        with open(args.input, 'r') as f:  # Should NOT flag
            data = f.read()
    
    if args.output:
        output_path = Path(args.output)
        output_path.mkdir(parents=True, exist_ok=True)  # Should NOT flag
        
        
if __name__ == "__main__":
    main()
