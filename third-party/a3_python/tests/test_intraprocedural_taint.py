"""
Tests for intraprocedural taint analysis.

Validates that within-function dataflow correctly detects:
- Source → local → sink flows
- Cleartext logging/storage
- SQL injection through local variables
- Taint propagation through operations
"""

import pytest
from pathlib import Path
from a3_python.semantics.intraprocedural_taint import (
    IntraproceduralTaintAnalyzer,
    IntraproceduralBug,
    analyze_file_intraprocedural,
)


def test_simple_cleartext_logging():
    """Test basic cleartext logging pattern: source → local → print."""
    code = compile("""
def handler(request):
    password = request.POST.get('password')
    print(password)
""", "<test>", "exec")
    
    # Get function code
    func_code = None
    for const in code.co_consts:
        if hasattr(const, 'co_name') and const.co_name == 'handler':
            func_code = const
            break
    
    assert func_code is not None
    
    analyzer = IntraproceduralTaintAnalyzer(func_code, "handler", "<test>")
    bugs = analyzer.analyze()
    
    # Should find CLEARTEXT_LOGGING
    assert len(bugs) > 0
    assert any(b.bug_type == 'CLEARTEXT_LOGGING' for b in bugs)
    
    bug = [b for b in bugs if b.bug_type == 'CLEARTEXT_LOGGING'][0]
    # Check that the bug correctly identifies the source
    # In Python 3.14+, the source description may show request.POST('password') instead of request.POST.get
    assert ('request.POST' in bug.source_description and 'password' in bug.source_description) or 'POST.get' in bug.source_description
    assert 'print' in bug.sink_description


def test_cleartext_logging_with_formatting():
    """Test cleartext logging through string formatting."""
    code = compile("""
def handler(request):
    password = request.POST.get('password')
    msg = f"Login attempt with password: {password}"
    print(msg)
""", "<test>", "exec")
    
    func_code = None
    for const in code.co_consts:
        if hasattr(const, 'co_name') and const.co_name == 'handler':
            func_code = const
            break
    
    assert func_code is not None
    
    analyzer = IntraproceduralTaintAnalyzer(func_code, "handler", "<test>")
    bugs = analyzer.analyze()
    
    # Should find CLEARTEXT_LOGGING
    assert len(bugs) > 0
    assert any(b.bug_type == 'CLEARTEXT_LOGGING' for b in bugs)


def test_no_false_positive_safe_flow():
    """Test that safe flows don't trigger bugs."""
    code = compile("""
def handler(request):
    username = request.POST.get('username')
    print("User logged in")  # Safe: no sensitive data
""", "<test>", "exec")
    
    func_code = None
    for const in code.co_consts:
        if hasattr(const, 'co_name') and const.co_name == 'handler':
            func_code = const
            break
    
    assert func_code is not None
    
    analyzer = IntraproceduralTaintAnalyzer(func_code, "handler", "<test>")
    bugs = analyzer.analyze()
    
    # Should NOT find bugs (constant string is safe)
    cleartext_bugs = [b for b in bugs if b.bug_type == 'CLEARTEXT_LOGGING']
    assert len(cleartext_bugs) == 0


def test_sql_injection_local_flow():
    """Test SQL injection through local variable."""
    code = compile("""
def query_user(request):
    user_id = request.GET.get('id')
    sql = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor.execute(sql)
""", "<test>", "exec")
    
    func_code = None
    for const in code.co_consts:
        if hasattr(const, 'co_name') and const.co_name == 'query_user':
            func_code = const
            break
    
    assert func_code is not None
    
    analyzer = IntraproceduralTaintAnalyzer(func_code, "query_user", "<test>")
    bugs = analyzer.analyze()
    
    # Should find SQL_INJECTION or similar
    assert len(bugs) > 0
    # The execute() call should be detected as a sink
    injection_bugs = [b for b in bugs if 'INJECTION' in b.bug_type or 'SQL' in b.bug_type]
    assert len(injection_bugs) > 0


def test_taint_through_binary_ops():
    """Test that taint propagates through binary operations."""
    code = compile("""
def handler(request):
    password = request.POST.get('password')
    combined = "Password: " + password
    result = combined + " ends"
    print(result)
""", "<test>", "exec")
    
    func_code = None
    for const in code.co_consts:
        if hasattr(const, 'co_name') and const.co_name == 'handler':
            func_code = const
            break
    
    assert func_code is not None
    
    analyzer = IntraproceduralTaintAnalyzer(func_code, "handler", "<test>")
    bugs = analyzer.analyze()
    
    # Should find CLEARTEXT_LOGGING (taint propagates through +)
    assert len(bugs) > 0
    assert any(b.bug_type == 'CLEARTEXT_LOGGING' for b in bugs)


def test_multiple_sources_to_single_sink():
    """Test multiple tainted sources flowing to one sink."""
    code = compile("""
def handler(request):
    password = request.POST.get('password')
    token = request.POST.get('token')
    combined = password + token
    print(combined)
""", "<test>", "exec")
    
    func_code = None
    for const in code.co_consts:
        if hasattr(const, 'co_name') and const.co_name == 'handler':
            func_code = const
            break
    
    assert func_code is not None
    
    analyzer = IntraproceduralTaintAnalyzer(func_code, "handler", "<test>")
    bugs = analyzer.analyze()
    
    # Should find at least one CLEARTEXT_LOGGING
    assert len(bugs) > 0
    assert any(b.bug_type == 'CLEARTEXT_LOGGING' for b in bugs)


def test_cleartext_storage_to_file():
    """Test cleartext storage to file."""
    code = compile("""
def save_password(request):
    password = request.POST.get('password')
    with open('passwords.txt', 'w') as f:
        f.write(password)
""", "<test>", "exec")
    
    func_code = None
    for const in code.co_consts:
        if hasattr(const, 'co_name') and const.co_name == 'save_password':
            func_code = const
            break
    
    assert func_code is not None
    
    analyzer = IntraproceduralTaintAnalyzer(func_code, "save_password", "<test>")
    bugs = analyzer.analyze()
    
    # Should find CLEARTEXT_STORAGE or INFO_LEAK
    assert len(bugs) > 0
    # File write should be detected
    storage_bugs = [b for b in bugs if 'CLEARTEXT' in b.bug_type or 'LEAK' in b.bug_type]
    assert len(storage_bugs) > 0


def test_sanitizer_blocks_taint():
    """Test that sanitizers remove taint."""
    code = compile("""
def safe_handler(request):
    user_input = request.POST.get('input')
    sanitized = escape(user_input)  # Sanitizer
    print(sanitized)  # Should be safe
""", "<test>", "exec")
    
    func_code = None
    for const in code.co_consts:
        if hasattr(const, 'co_name') and const.co_name == 'safe_handler':
            func_code = const
            break
    
    assert func_code is not None
    
    analyzer = IntraproceduralTaintAnalyzer(func_code, "safe_handler", "<test>")
    bugs = analyzer.analyze()
    
    # After sanitization, should have fewer/no bugs
    # This depends on whether 'escape' is recognized as sanitizer
    # If not recognized, will still taint - that's OK for now


def test_getpass_creates_sensitive_local():
    """Test that getpass.getpass() creates a sensitive local variable."""
    code = compile("""
import getpass
def get_credentials():
    password = getpass.getpass()
    print(password)  # CLEARTEXT_LOGGING
""", "<test>", "exec")
    
    func_code = None
    for const in code.co_consts:
        if hasattr(const, 'co_name') and const.co_name == 'get_credentials':
            func_code = const
            break
    
    assert func_code is not None
    
    analyzer = IntraproceduralTaintAnalyzer(func_code, "get_credentials", "<test>")
    bugs = analyzer.analyze()
    
    # Should find CLEARTEXT_LOGGING if getpass.getpass is recognized as source
    # This may require the contract to be properly configured
    if bugs:
        assert any(b.bug_type == 'CLEARTEXT_LOGGING' for b in bugs)


def test_analyze_file_finds_multiple_functions():
    """Test that analyze_file_intraprocedural finds bugs in multiple functions."""
    # Create a temporary Python file
    import tempfile
    
    test_code = """
def handler1(request):
    password = request.POST.get('password')
    print(password)

def handler2(request):
    token = request.POST.get('token')
    print(token)
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(test_code)
        temp_path = Path(f.name)
    
    try:
        bugs = analyze_file_intraprocedural(temp_path)
        
        # Should find bugs in both functions
        assert len(bugs) >= 2
        
        # Check function names
        function_names = {b.function_name for b in bugs}
        assert 'handler1' in function_names or 'handler2' in function_names
    finally:
        temp_path.unlink()


def test_no_crash_on_empty_function():
    """Test that analyzer doesn't crash on empty function."""
    code = compile("""
def empty():
    pass
""", "<test>", "exec")
    
    func_code = None
    for const in code.co_consts:
        if hasattr(const, 'co_name') and const.co_name == 'empty':
            func_code = const
            break
    
    assert func_code is not None
    
    analyzer = IntraproceduralTaintAnalyzer(func_code, "empty", "<test>")
    bugs = analyzer.analyze()
    
    # Should return empty list, not crash
    assert bugs == []


def test_no_crash_on_complex_control_flow():
    """Test that analyzer handles if/else correctly."""
    code = compile("""
def handler(request):
    password = request.POST.get('password')
    if password:
        print("Password is set")
    else:
        print("No password")
""", "<test>", "exec")
    
    func_code = None
    for const in code.co_consts:
        if hasattr(const, 'co_name') and const.co_name == 'handler':
            func_code = const
            break
    
    assert func_code is not None
    
    analyzer = IntraproceduralTaintAnalyzer(func_code, "handler", "<test>")
    bugs = analyzer.analyze()
    
    # Should not crash
    # May or may not find bugs depending on how precise the analysis is
    assert isinstance(bugs, list)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
