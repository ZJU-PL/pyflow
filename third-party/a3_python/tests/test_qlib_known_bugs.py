#!/usr/bin/env python3
"""Test the specific Qlib files that have known true positives from Qlib_true_positives.md"""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent))

from a3_python.frontend.loader import load_python_file
from a3_python.semantics.symbolic_vm import SymbolicVM
from a3_python.unsafe.registry import check_unsafe_regions

def analyze(code, max_steps=150):
    vm = SymbolicVM()
    path = vm.load_code(code)
    bugs = []
    steps = 0
    active = [path]
    
    while active and steps < max_steps:
        current = active.pop(0)
        steps += 1
        if current.state.halted:
            continue
        result = check_unsafe_regions(current.state, [])
        if result:
            bugs.append(result)
            continue
        try:
            active.extend(vm.step(current))
        except:
            pass
    return bugs, steps


def main():
    print("Testing Qlib files with known true positives")
    print("=" * 60)
    
    # Files with known bugs from Qlib_true_positives.md
    files = [
        ("backtest/position.py", "DIV_ZERO at line 343"),
        ("backtest/report.py", "DIV_ZERO at line 533"),
        ("contrib/model/pytorch_tra.py", "CODE_INJECTION at line 140"),
        ("contrib/online/utils.py", "PICKLE_INJECTION at line 33"),
        ("data/data.py", "CODE_INJECTION at line 397 (mitigated)"),
    ]
    
    qlib_dir = Path("external_tools/Qlib/qlib")
    
    for rel_path, expected_bug in files:
        filepath = qlib_dir / rel_path
        print(f"\n{rel_path}")
        print(f"  Expected: {expected_bug}")
        
        if not filepath.exists():
            print(f"  Status: FILE NOT FOUND")
            continue
        
        try:
            code = load_python_file(filepath)
            bugs, steps = analyze(code, max_steps=200)
            
            if bugs:
                bug_types = [b.get("bug_type", "?") for b in bugs]
                print(f"  Found: {len(bugs)} bugs - {bug_types}")
            else:
                print(f"  Found: No bugs ({steps} steps explored)")
                
        except Exception as e:
            print(f"  Error: {str(e)[:50]}")


if __name__ == "__main__":
    main()
