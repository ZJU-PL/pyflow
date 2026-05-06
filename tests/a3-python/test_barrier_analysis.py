#!/usr/bin/env python3
"""
Test script for barrier-enhanced interprocedural analysis on Qlib.

This tests the interprocedural crash summary analysis which properly
handles class methods through call sites.
"""

import os
import sys

from pathlib import Path
from pyflow.a3_python.semantics.interprocedural_bugs import InterproceduralBugTracker
from pyflow.a3_python.semantics.interprocedural_barriers import FunctionBarrierSynthesizer, SafetyProperty, FunctionBarrier

def main():
    print("=" * 70)
    print("INTERPROCEDURAL BARRIER ANALYSIS: position.py DIV_ZERO detection")
    print("Known DIV_ZERO locations: lines 343, 353, 471")
    print("=" * 70)
    print()
    
    # Allow callers to point at a local Qlib checkout without hardcoding a home dir.
    backtest_dir_env = os.environ.get("A3_QLIB_BACKTEST_DIR")
    if not backtest_dir_env:
        print("ERROR: set A3_QLIB_BACKTEST_DIR to a Qlib backtest directory")
        return 1

    # Focus on backtest directory which contains position.py
    backtest_dir = Path(backtest_dir_env)
    
    if not backtest_dir.exists():
        print(f"ERROR: {backtest_dir} does not exist")
        return 1
    
    print(f"Analyzing: {backtest_dir}")
    print()
    
    # Build interprocedural tracker
    print("Building interprocedural analysis context...")
    tracker = InterproceduralBugTracker.from_project(backtest_dir)
    
    print(f"Found {len(tracker.crash_summaries)} crash summaries")
    print(f"Found {len(tracker.call_graph.functions)} functions in call graph")
    print()
    
    # Find all functions with DIV_ZERO in may_trigger
    print("=" * 70)
    print("FUNCTIONS WITH DIV_ZERO POTENTIAL:")
    print("=" * 70)
    
    div_zero_functions = []
    for func_name, summary in tracker.crash_summaries.items():
        if 'DIV_ZERO' in summary.may_trigger:
            div_zero_functions.append((func_name, summary))
            print(f"  {func_name}")
            print(f"    divisor_params: {summary.divisor_params}")
            print(f"    may_trigger: {summary.may_trigger}")
            print()
    
    # Now synthesize barriers
    print("=" * 70)
    print("BARRIER SYNTHESIS:")
    print("=" * 70)
    
    synthesizer = FunctionBarrierSynthesizer(timeout_ms=5000, verbose=False)
    
    for func_name, summary in div_zero_functions:
        print(f"\n{func_name}:")
        
        for divisor_param in summary.divisor_params:
            barrier = synthesizer.synthesize_div_zero_barrier(func_name, divisor_param)
            if barrier:
                print(f"  Barrier: {barrier.barrier_expr}")
                print(f"  Preconditions: {[p.description for p in barrier.preconditions]}")
                print(f"  Verified: {barrier.verified}")
            else:
                print(f"  Failed to synthesize barrier for param {divisor_param}")
    
    # Find interprocedural bugs
    print()
    print("=" * 70)
    print("INTERPROCEDURAL BUGS (via call chains):")
    print("=" * 70)
    
    bugs = tracker.find_all_bugs()
    crash_bugs = [b for b in bugs if b.bug_type in ('DIV_ZERO', 'NULL_PTR', 'BOUNDS', 'INDEX_ERROR')]
    
    print(f"\nFound {len(crash_bugs)} crash bugs:")
    for bug in crash_bugs[:20]:  # Show first 20
        print(f"  {bug.bug_type} in {bug.crash_function}")
        print(f"    Location: {bug.crash_location}")
        print(f"    Reason: {bug.reason}")
        if bug.call_chain:
            print(f"    Call chain: {' -> '.join(bug.call_chain[:3])}...")
        print()
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
