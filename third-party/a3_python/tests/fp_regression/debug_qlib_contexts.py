#!/usr/bin/env python3
"""Debug FP context detection on real repo bugs."""
import sys
from pathlib import Path
from collections import Counter

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from a3_python.semantics.interprocedural_bugs import InterproceduralBugTracker
from a3_python.fp_context import FPContextDetector, FPContext

repo = Path('external_tools/qlib')
if not repo.exists():
    print("Qlib not found")
    sys.exit(1)

print(f"Analyzing {repo}...")
tracker = InterproceduralBugTracker.from_project(repo)
bugs = tracker.find_all_bugs(apply_fp_reduction=False)

print(f"Found {len(bugs)} bugs")
print(f"\nTypes: {dict(Counter(b.bug_type for b in bugs))}")

# Analyze guarded bugs
print(f"\n" + "=" * 60)
print("Bug analysis")
print("=" * 60)

for bug in bugs[:10]:  # First 10
    print(f"\n{bug.bug_type} @ {bug.crash_location}")
    print(f"  confidence={bug.confidence:.2f}")
    print(f"  reason={bug.reason}")
    
    # Check if "guarded" in reason
    if 'guarded' in bug.reason.lower():
        print(f"  ** GUARDED **")
