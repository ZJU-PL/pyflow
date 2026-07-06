#!/usr/bin/env python3
"""Debug script for FP context detection."""

from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from a3_python.fp_context import FPContextDetector, FPContext

# Test file-level CLI detection
detector = FPContextDetector()

test_files = [
    'tests/fp_regression/cli_tool_patterns/argparse_path.py',
    'tests/fp_regression/cli_tool_patterns/click_file_open.py',
    'tests/fp_regression/cli_tool_patterns/sys_argv_direct.py',
    'tests/fp_regression/safe_loader_patterns/yaml_safe_load.py',
]

print("CLI Tool Detection:")
for f in test_files:
    is_cli = detector._is_cli_tool_file(f)
    print(f"  {Path(f).name}: CLI={is_cli}")

print()

# Test context detection for a specific bug
print("Context Detection for PATH_INJECTION in argparse_path.py:")
result = detector.detect_contexts(
    bug_type='PATH_INJECTION',
    tainted_sources=[],
    file_path='tests/fp_regression/cli_tool_patterns/argparse_path.py',
    call_chain=['main'],
    sink_function='open',
)
print(f"  Contexts: {[c.name for c in result.contexts]}")
print(f"  Multiplier: {result.confidence_multiplier}")
print(f"  Reasons: {result.reasons}")

print()

# Test with NULL_PTR (crash bug)
print("Context Detection for NULL_PTR in argparse_path.py:")
result = detector.detect_contexts(
    bug_type='NULL_PTR',
    tainted_sources=[],
    file_path='tests/fp_regression/cli_tool_patterns/argparse_path.py',
    call_chain=['main'],
    sink_function=None,
)
print(f"  Contexts: {[c.name for c in result.contexts]}")
print(f"  Multiplier: {result.confidence_multiplier}")
print(f"  Reasons: {result.reasons}")
