#!/usr/bin/env python3
"""Debug to see what crash_location values look like before and after FP reduction."""

from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from a3_python.semantics.interprocedural_bugs import InterproceduralBugTracker

file_path = Path('tests/fp_regression/cli_tool_patterns/argparse_path.py')

# Without FP reduction
tracker = InterproceduralBugTracker.from_project(file_path.parent)
bugs_raw = tracker.find_all_bugs(apply_fp_reduction=False)

print(f"File: {file_path}")
print(f"\nFound {len(bugs_raw)} bugs (before FP reduction):")
for bug in bugs_raw[:5]:  # Show first 5
    print(f"  {bug.bug_type}: crash_location='{bug.crash_location}'")
    print(f"    confidence={bug.confidence}")

# With FP reduction
tracker2 = InterproceduralBugTracker.from_project(file_path.parent)
bugs_filtered = tracker2.find_all_bugs(apply_fp_reduction=True)

print(f"\nFound {len(bugs_filtered)} bugs (after FP reduction):")
