#!/usr/bin/env python3
"""Quick test script for all security tests."""
import sys
sys.path.insert(0, '.')
from pathlib import Path
from a3_python.analyzer import Analyzer

a = Analyzer(verbose=False)

tests = [
    ('sql_injection_001.py', 'BUG'),
    ('sql_injection_safe_001.py', 'SAFE'),
    ('command_injection_001.py', 'BUG'),
    ('command_injection_safe_001.py', 'SAFE'),
    ('path_injection_001.py', 'BUG'),
    ('tarslip_001.py', 'BUG'),
    ('tarslip_safe_001.py', 'SAFE'),
    ('zipslip_001.py', 'BUG'),
    ('zipslip_safe_001.py', 'SAFE'),
    ('xxe_001.py', 'BUG'),
    ('xxe_safe_001.py', 'SAFE'),
    ('cleartext_logging_001.py', 'BUG'),
    ('cleartext_logging_safe_001.py', 'SAFE'),
    ('cleartext_storage_001.py', 'BUG'),
    ('cleartext_storage_safe_001.py', 'SAFE'),
    ('weak_crypto_001.py', 'BUG'),
    ('weak_crypto_safe_001.py', 'SAFE'),
    ('insecure_cookie_001.py', 'BUG'),
    ('insecure_cookie_safe_001.py', 'SAFE'),
    ('regex_injection_001.py', 'BUG'),
    ('regex_injection_safe_001.py', 'SAFE'),
    ('flask_debug_001.py', 'BUG'),
    ('flask_debug_safe_001.py', 'SAFE'),
    ('cookie_injection_001.py', 'BUG'),
]

passed = 0
failed = 0
for name, expected in tests:
    try:
        result = a.analyze_file(Path(f'py_synthetic/standalone/{name}'))
        actual = result.verdict
        if actual == expected:
            print(f'✓ {name}: {actual}')
            passed += 1
        else:
            print(f'✗ {name}: expected {expected}, got {actual} ({result.bug_type})')
            failed += 1
    except Exception as e:
        print(f'✗ {name}: ERROR {e}')
        failed += 1

print(f'\n{passed}/{passed+failed} tests passed ({100*passed/(passed+failed):.1f}%)')
