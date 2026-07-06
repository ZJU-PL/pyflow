#!/usr/bin/env python3
"""Debug FP context detection for JINJA2_INJECTION bugs."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from a3_python.semantics.interprocedural_bugs import InterproceduralBugTracker
from a3_python.fp_context import FPContextDetector

tracker = InterproceduralBugTracker.from_project(Path('external_tools/graphrag'))
bugs = tracker.find_all_bugs(apply_fp_reduction=False)

detector = FPContextDetector()

# Find JINJA2_INJECTION bugs and apply context
print("JINJA2_INJECTION bugs analysis:")
print("=" * 60)

for b in bugs:
    if b.bug_type == 'JINJA2_INJECTION':
        file_path = b.crash_location.rsplit(':', 1)[0] if ':' in b.crash_location else None
        
        result = detector.detect_contexts(
            bug_type=b.bug_type,
            tainted_sources=list(b.tainted_sources) if b.tainted_sources else [],
            file_path=file_path,
            call_chain=b.call_chain,
            sink_function=b.crash_function,
        )
        
        adjusted = b.confidence * result.confidence_multiplier
        
        print(f"Bug: {b.bug_type} @ {b.crash_location}")
        print(f"  file_path extracted: {file_path}")
        print(f"  contexts: {[c.name for c in result.contexts]}")
        print(f"  multiplier: {result.confidence_multiplier}")
        print(f"  original: {b.confidence:.3f}, adjusted: {adjusted:.3f}")
        print(f"  would be filtered: {adjusted < 0.40}")
        print()
