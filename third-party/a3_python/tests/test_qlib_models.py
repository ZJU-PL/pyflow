#!/usr/bin/env python3
"""
Test barrier certificate analysis on Qlib model files.
Focus on finding barrier-appropriate bugs (DIV_ZERO, BOUNDS, etc.)
"""

import sys
import subprocess
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from a3_python.analyzer import Analyzer

def main():
    qlib_dir = Path("external_tools/Qlib")
    
    # Find files in the model contrib directory
    model_dir = qlib_dir / "qlib" / "contrib" / "model"
    
    if not model_dir.exists():
        print(f"Model dir not found: {model_dir}")
        return
    
    files = list(model_dir.rglob("*.py"))
    files = [f for f in files if "__pycache__" not in str(f)][:10]
    
    print(f"Testing {len(files)} model files:")
    print("=" * 60)
    
    analyzer = Analyzer(verbose=False, max_depth=50)
    
    results_summary = {
        "BUG": 0,
        "SAFE": 0,
        "UNKNOWN": 0,
    }
    bug_details = []
    
    for filepath in files:
        rel_path = filepath.relative_to(qlib_dir)
        print(f"\nAnalyzing: {rel_path}")
        
        try:
            result = analyzer.analyze_file(filepath)
            results_summary[result.verdict] = results_summary.get(result.verdict, 0) + 1
            
            print(f"  Verdict: {result.verdict}")
            
            if result.verdict == "BUG":
                print(f"  Bug Type: {result.bug_type}")
                if result.message:
                    print(f"  Message: {result.message[:80]}")
                bug_details.append({
                    "file": str(rel_path),
                    "bug_type": result.bug_type,
                    "message": result.message,
                })
            elif result.verdict == "SAFE" and result.barrier:
                print(f"  Barrier: {result.barrier.name}")
            
            if hasattr(result, 'paths_explored'):
                print(f"  Paths explored: {result.paths_explored}")
                
        except Exception as e:
            print(f"  Error: {str(e)[:60]}")
    
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    for verdict, count in results_summary.items():
        print(f"  {verdict}: {count}")
    
    if bug_details:
        print("\nBugs found:")
        for bug in bug_details:
            print(f"  [{bug['bug_type']}] {bug['file']}")


if __name__ == "__main__":
    main()
