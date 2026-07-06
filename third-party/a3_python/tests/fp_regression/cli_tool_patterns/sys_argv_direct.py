"""
FP Regression Test: Direct sys.argv usage.

Simple CLI tools that use sys.argv directly should NOT be flagged for
PATH_INJECTION when the user provides file paths.

Expected: NO FINDINGS (or LOW confidence if any)
"""
import sys
import os


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <input_file> [output_file]")
        sys.exit(1)
    
    input_file = sys.argv[1]  # User-provided path - should NOT flag
    output_file = sys.argv[2] if len(sys.argv) > 2 else "output.txt"
    
    # These are intentional - user controls both CLI and paths
    with open(input_file, 'r') as f:  # Should NOT flag PATH_INJECTION
        content = f.read()
    
    with open(output_file, 'w') as f:  # Should NOT flag PATH_INJECTION
        f.write(content.upper())
    
    # Even os.path operations should not flag
    dirname = os.path.dirname(input_file)  # Should NOT flag
    if dirname:
        os.makedirs(dirname, exist_ok=True)  # Should NOT flag


if __name__ == "__main__":
    main()
