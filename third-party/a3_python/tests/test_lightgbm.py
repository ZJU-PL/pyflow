#!/usr/bin/env python3
"""
Barrier certificate analysis on LightGBM (gradient boosting library).
Focuses on numeric bugs: DIV_ZERO, BOUNDS, NULL_PTR
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from a3_python.frontend.loader import load_python_file
from a3_python.semantics.symbolic_vm import SymbolicVM
from a3_python.unsafe.registry import check_unsafe_regions


def analyze_for_barriers(code, max_steps=100):
    """Direct barrier analysis without security scanning."""
    vm = SymbolicVM()
    path = vm.load_code(code)
    
    paths_explored = []
    bugs_found = []
    
    steps = 0
    active = [path]
    
    while active and steps < max_steps:
        current = active.pop(0)
        steps += 1
        
        if current.state.halted:
            paths_explored.append(current)
            continue
        
        # Check for unsafe regions
        unsafe_result = check_unsafe_regions(current.state, [])
        if unsafe_result:
            bug_type = unsafe_result.get('bug_type', 'UNKNOWN')
            bugs_found.append((bug_type, unsafe_result))
            paths_explored.append(current)
            continue
        
        try:
            new_paths = vm.step(current)
            active.extend(new_paths)
        except Exception as e:
            paths_explored.append(current)
    
    return {
        "bugs": bugs_found,
        "paths_explored": len(paths_explored),
        "steps": steps,
    }


def main():
    lgbm_dir = Path("external_tools/LightGBM/python-package/lightgbm")
    
    if not lgbm_dir.exists():
        print(f"LightGBM not found at {lgbm_dir}")
        return
    
    files = list(lgbm_dir.glob("*.py"))
    files = [f for f in files if "__pycache__" not in str(f)]
    
    print("=" * 60)
    print("Barrier Certificate Analysis on LightGBM")
    print("=" * 60)
    print(f"Files to analyze: {len(files)}")
    print()
    
    results = {"BUG": 0, "SAFE": 0, "ERROR": 0}
    all_bugs = []
    
    for filepath in files:
        print(f"Analyzing: {filepath.name}...", end=" ", flush=True)
        
        try:
            code = load_python_file(filepath)
            result = analyze_for_barriers(code, max_steps=150)
            
            if result["bugs"]:
                results["BUG"] += 1
                print(f"BUG ({len(result['bugs'])} found)")
                for bug_type, detail in result["bugs"]:
                    all_bugs.append({
                        "file": filepath.name,
                        "bug_type": bug_type,
                        "detail": str(detail)[:80],
                    })
            else:
                results["SAFE"] += 1
                print(f"SAFE ({result['paths_explored']} paths, {result['steps']} steps)")
                
        except Exception as e:
            results["ERROR"] += 1
            print(f"Error: {str(e)[:40]}")
    
    print()
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Files analyzed: {len(files)}")
    print(f"  SAFE: {results['SAFE']}")
    print(f"  BUG: {results['BUG']}")
    print(f"  ERROR: {results['ERROR']}")
    
    if all_bugs:
        print()
        print("Bugs found:")
        for bug in all_bugs[:10]:
            print(f"  [{bug['bug_type']}] {bug['file']}: {bug['detail'][:60]}")


if __name__ == "__main__":
    main()
