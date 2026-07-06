#!/usr/bin/env python3
"""Test Qlib known bugs using full Analyzer (includes interprocedural analysis)"""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent))

from a3_python.analyzer import Analyzer

def main():
    print("Testing Qlib files with full Analyzer")
    print("=" * 60)
    
    # Files with known bugs
    files = [
        ("backtest/position.py", "DIV_ZERO at line 343"),
        ("backtest/report.py", "DIV_ZERO at line 533"),
        ("contrib/model/pytorch_tra.py", "CODE_INJECTION at line 140"),
        ("contrib/online/utils.py", "PICKLE_INJECTION at line 33"),
    ]
    
    qlib_dir = Path("external_tools/Qlib/qlib")
    analyzer = Analyzer(verbose=False, max_depth=50)
    
    for rel_path, expected_bug in files:
        filepath = qlib_dir / rel_path
        print(f"\n{rel_path}")
        print(f"  Expected: {expected_bug}")
        
        if not filepath.exists():
            print(f"  Status: FILE NOT FOUND")
            continue
        
        try:
            result = analyzer.analyze_file(filepath)
            print(f"  Verdict: {result.verdict}")
            if result.verdict == "BUG":
                print(f"  Bug Type: {result.bug_type}")
                if result.message:
                    print(f"  Message: {result.message[:80]}")
            elif result.barrier:
                print(f"  Barrier: {result.barrier.name}")
                
        except Exception as e:
            print(f"  Error: {str(e)[:60]}")


if __name__ == "__main__":
    main()
