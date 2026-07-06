#!/usr/bin/env python3
"""
Barrier certificate analysis on FLAML (AutoML library).
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from a3_python.frontend.loader import load_python_file
from a3_python.semantics.symbolic_vm import SymbolicVM
from a3_python.unsafe.registry import check_unsafe_regions


def analyze_for_barriers(code, max_steps=100):
    """Direct barrier analysis."""
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
    flaml_dir = Path("external_tools/FLAML/flaml")
    
    if not flaml_dir.exists():
        print(f"FLAML not found at {flaml_dir}")
        return
    
    # Focus on automl and tune (has numeric optimization)
    target_dirs = ["automl", "tune", "default"]
    
    files = []
    for subdir in target_dirs:
        subpath = flaml_dir / subdir
        if subpath.exists():
            files.extend(list(subpath.rglob("*.py"))[:8])
    
    files = [f for f in files if "__pycache__" not in str(f)][:25]
    
    print("=" * 60)
    print("Barrier Certificate Analysis on FLAML")
    print("=" * 60)
    print(f"Files to analyze: {len(files)}")
    print()
    
    results = {"BUG": 0, "SAFE": 0, "ERROR": 0}
    all_bugs = []
    
    for filepath in files:
        rel_path = filepath.relative_to(flaml_dir)
        print(f"{rel_path}...", end=" ", flush=True)
        
        try:
            code = load_python_file(filepath)
            result = analyze_for_barriers(code, max_steps=100)
            
            if result["bugs"]:
                results["BUG"] += 1
                print(f"BUG ({len(result['bugs'])})")
                for bug_type, detail in result["bugs"]:
                    all_bugs.append({
                        "file": str(rel_path),
                        "bug_type": bug_type,
                    })
            else:
                results["SAFE"] += 1
                print(f"SAFE ({result['steps']} steps)")
                
        except Exception as e:
            results["ERROR"] += 1
            print(f"Error: {str(e)[:30]}")
    
    print()
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"  SAFE: {results['SAFE']}")
    print(f"  BUG: {results['BUG']}")
    print(f"  ERROR: {results['ERROR']}")
    
    if all_bugs:
        print()
        print("Bugs found:")
        for bug in all_bugs:
            print(f"  [{bug['bug_type']}] {bug['file']}")


if __name__ == "__main__":
    main()
