#!/usr/bin/env python3
"""
Test SOTA barrier certificate analysis on Qlib (quantitative finance library).

Qlib is ideal for barrier certificates because it has:
- Numeric computations with potential division by zero
- Array indexing that could go out of bounds
- Complex loops that need termination/invariant proofs
- Potential null/None dereferences

This script focuses on barrier-appropriate bugs:
- DIV_ZERO: Division by zero
- BOUNDS: Array/index out of bounds  
- NULL_PTR: None dereference
- LOOP bugs: Infinite loops, non-termination
"""

import sys
import time
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict, Any, Optional
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).parent))

from a3_python.analyzer import Analyzer, AnalysisResult


# Barrier-appropriate bug types (not security/taint based)
BARRIER_BUG_TYPES = {
    "DIV_ZERO",
    "BOUNDS", 
    "INDEX_ERROR",
    "NULL_PTR",
    "NONE_DEREF",
    "ATTRIBUTE_ERROR",
    "TYPE_ERROR",
    "ASSERTION_ERROR",
    "LOOP_INFINITE",
    "NON_TERMINATION",
}


@dataclass
class BarrierResult:
    """Result of barrier analysis on a file."""
    file: str
    bugs: List[Dict[str, Any]]
    safe_proofs: List[Dict[str, Any]]
    barrier_certificates: List[str]
    analysis_time_ms: float
    error: Optional[str] = None


def analyze_file_for_barriers(filepath: Path, analyzer: Analyzer) -> BarrierResult:
    """Analyze a file specifically for barrier-provable properties."""
    start = time.time()
    bugs = []
    safe_proofs = []
    barrier_certs = []
    error = None
    
    try:
        result = analyzer.analyze_file(filepath)
        
        if result.verdict == "BUG":
            bug_type = result.bug_type or "UNKNOWN"
            # Only count barrier-appropriate bugs
            if any(bt in bug_type for bt in BARRIER_BUG_TYPES):
                bugs.append({
                    "bug_type": bug_type,
                    "location": str(result.counterexample.get("location")) if result.counterexample else None,
                    "message": result.message,
                    "counterexample": result.counterexample,
                })
        elif result.verdict == "SAFE":
            if result.barrier:
                barrier_certs.append(str(result.barrier))
                safe_proofs.append({
                    "barrier": str(result.barrier),
                    "message": result.message,
                })
            else:
                safe_proofs.append({
                    "barrier": None,
                    "message": result.message,
                })
                
    except Exception as e:
        error = str(e)
    
    elapsed_ms = (time.time() - start) * 1000
    
    return BarrierResult(
        file=str(filepath),
        bugs=bugs,
        safe_proofs=safe_proofs,
        barrier_certificates=barrier_certs,
        analysis_time_ms=elapsed_ms,
        error=error,
    )


def scan_qlib():
    """Scan Qlib for barrier-appropriate bugs."""
    
    qlib_dir = Path("external_tools/Qlib")
    if not qlib_dir.exists():
        print(f"Qlib not found at {qlib_dir}")
        return
    
    # Focus on numeric/algorithmic files
    target_dirs = [
        "qlib/contrib/eva",      # Evaluation metrics (lots of divisions)
        "qlib/contrib/rolling",  # Rolling computations
        "qlib/utils",            # Utility functions
        "qlib/data",             # Data processing
        "qlib/model",            # ML models
    ]
    
    python_files = []
    for subdir in target_dirs:
        subpath = qlib_dir / subdir
        if subpath.exists():
            python_files.extend(subpath.rglob("*.py"))
    
    # Filter out tests and __pycache__
    python_files = [
        f for f in python_files
        if "__pycache__" not in str(f)
        and "test" not in f.stem.lower()
    ]
    
    # Limit to reasonable number
    python_files = python_files[:50]
    
    print(f"=" * 70)
    print("Barrier Certificate Analysis on Qlib")
    print(f"=" * 70)
    print(f"Files to analyze: {len(python_files)}")
    print()
    
    analyzer = Analyzer(verbose=False)
    
    all_bugs = []
    all_safe_proofs = []
    all_barriers = []
    bug_type_counts = defaultdict(int)
    files_with_bugs = 0
    files_with_proofs = 0
    
    for i, filepath in enumerate(python_files):
        rel_path = filepath.relative_to(qlib_dir)
        print(f"[{i+1}/{len(python_files)}] {rel_path}...", end=" ", flush=True)
        
        result = analyze_file_for_barriers(filepath, analyzer)
        
        if result.bugs:
            files_with_bugs += 1
            print(f"BUG ({len(result.bugs)})")
            for bug in result.bugs:
                all_bugs.append({**bug, "file": str(rel_path)})
                bug_type_counts[bug["bug_type"]] += 1
        elif result.barrier_certificates:
            files_with_proofs += 1
            print(f"SAFE (barrier: {result.barrier_certificates[0][:40]}...)")
            all_barriers.extend(result.barrier_certificates)
            all_safe_proofs.extend(result.safe_proofs)
        elif result.safe_proofs:
            files_with_proofs += 1
            print("SAFE")
            all_safe_proofs.extend(result.safe_proofs)
        elif result.error:
            print(f"Error: {result.error[:40]}...")
        else:
            print("OK (no findings)")
    
    print()
    print(f"=" * 70)
    print("RESULTS SUMMARY")
    print(f"=" * 70)
    print(f"Files analyzed: {len(python_files)}")
    print(f"Files with bugs: {files_with_bugs}")
    print(f"Files with SAFE proofs: {files_with_proofs}")
    print(f"Total barrier-type bugs: {len(all_bugs)}")
    print(f"Total barrier certificates: {len(all_barriers)}")
    print()
    
    if bug_type_counts:
        print("Bug type breakdown:")
        for bt, count in sorted(bug_type_counts.items(), key=lambda x: -x[1]):
            print(f"  {bt}: {count}")
    
    if all_bugs:
        print()
        print("Sample bugs found:")
        for bug in all_bugs[:10]:
            print(f"  [{bug['bug_type']}] {bug['file']}")
            if bug.get('message'):
                print(f"    {bug['message'][:80]}")
    
    if all_barriers:
        print()
        print("Sample barrier certificates:")
        for bc in all_barriers[:5]:
            print(f"  {bc[:100]}...")
    
    return {
        "files_analyzed": len(python_files),
        "bugs": all_bugs,
        "safe_proofs": all_safe_proofs,
        "barrier_certificates": all_barriers,
        "bug_type_counts": dict(bug_type_counts),
    }


if __name__ == "__main__":
    scan_qlib()
