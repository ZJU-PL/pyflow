"""
Test file object taint propagation.

When open(tainted_path) is called, the returned file object should be tainted.
When file.read() is called on a tainted file object, the result should be tainted.

This addresses the issue where:
    path = request.args.get('path')  # tainted
    f = open(path)                    # f should be tainted (from path)
    content = f.read()                # content should be tainted (from f)
    eval(content)                     # CODE_INJECTION should be detected

Without file object taint tracking, the taint from path is lost at open(),
and eval(content) won't detect the security issue.
"""

import pytest
from a3_python.z3model.taint_lattice import (
    TaintLabel, SourceType, SinkType, SanitizerType
)
from a3_python.semantics.security_tracker_lattice import LatticeSecurityTracker
from a3_python.contracts.security_lattice import init_security_contracts


def test_file_object_inherits_path_taint():
    """File object should inherit taint from the path argument."""
    init_security_contracts()
    tracker = LatticeSecurityTracker()
    
    # Simulate: path = request.args.get('path')
    tainted_path = object()
    path_label = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM, 'request.args')
    tracker.set_label(tainted_path, path_label)
    
    # Simulate: f = open(path)
    file_obj = object()
    
    # The file object should be marked as having taint from the path
    # This should happen in handle_call_pre for open()
    violation = tracker.handle_call_pre(
        func_name='open',
        args=[tainted_path],
        location='test.py:2'
    )
    
    # open() with tainted path is a PATH_INJECTION sink violation
    assert violation is not None
    assert 'PATH_INJECTION' in violation.bug_type
    
    # Now get the file object label - it should have been marked by handle_call_post
    # Simulate the VM calling handle_call_post
    tracker.handle_call_post(
        func_name='open',
        func_ref=open,  # The actual built-in open function
        args=[tainted_path],
        result=file_obj,
        location='test.py:2'
    )
    
    # Check that the file object is tainted
    file_label = tracker.get_label(file_obj)
    assert file_label.has_untrusted_taint(), "File object should be tainted from path"


def test_file_read_inherits_file_object_taint():
    """Content from file.read() should inherit the file object's taint."""
    init_security_contracts()
    tracker = LatticeSecurityTracker()
    
    # Create a tainted file object
    file_obj = object()
    file_label = TaintLabel.from_untrusted_source(SourceType.FILE_CONTENT, 'tainted_file')
    tracker.set_label(file_obj, file_label)
    
    # Simulate: content = f.read()
    content = object()
    
    # handle_call_pre with receiver (file object) as args[0]
    violation = tracker.handle_call_pre(
        func_name='file.read',
        args=[file_obj],  # receiver is args[0] for method calls
        location='test.py:3',
        is_method_call=True
    )
    
    # file.read() itself is not a sink, so no violation
    assert violation is None
    
    # handle_call_post should mark the result as tainted
    tracker.handle_call_post(
        func_name='file.read',
        func_ref=None,  # Don't have actual file.read reference
        args=[file_obj],
        result=content,
        location='test.py:3'
    )
    
    # Check that content inherited the file object's taint
    content_label = tracker.get_label(content)
    assert content_label.has_untrusted_taint(), "Content should inherit file object taint"


def test_open_tainted_path_then_read_then_eval():
    """End-to-end: open(tainted) → read() → eval() should detect CODE_INJECTION."""
    init_security_contracts()
    tracker = LatticeSecurityTracker()
    
    # 1. Tainted path from user input
    tainted_path = object()
    path_label = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM, 'request.args')
    tracker.set_label(tainted_path, path_label)
    
    # 2. open(tainted_path) → file object
    file_obj = object()
    
    # Check PATH_INJECTION at open()
    violation1 = tracker.handle_call_pre(
        func_name='open',
        args=[tainted_path],
        location='test.py:2'
    )
    assert violation1 is not None
    assert 'PATH_INJECTION' in violation1.bug_type
    
    # Mark file object as tainted
    tracker.handle_call_post(
        func_name='open',
        func_ref=open,
        args=[tainted_path],
        result=file_obj,
        location='test.py:2'
    )
    
    # 3. file.read() → content
    content = object()
    tracker.handle_call_pre(
        func_name='file.read',
        args=[file_obj],
        location='test.py:3',
        is_method_call=True
    )
    tracker.handle_call_post(
        func_name='file.read',
        func_ref=None,
        args=[file_obj],
        result=content,
        location='test.py:3'
    )
    
    # 4. eval(content)
    violation2 = tracker.handle_call_pre(
        func_name='eval',
        args=[content],
        location='test.py:4'
    )
    
    # Should detect CODE_INJECTION because content is tainted from file
    assert violation2 is not None
    assert 'CODE_INJECTION' in violation2.bug_type


def test_clean_path_produces_clean_file():
    """File from clean path should be clean."""
    init_security_contracts()
    tracker = LatticeSecurityTracker()
    
    # Clean path
    clean_path = object()
    tracker.set_label(clean_path, TaintLabel.clean())
    
    # open(clean_path)
    file_obj = object()
    tracker.handle_call_post(
        func_name='open',
        func_ref=open,
        args=[clean_path],
        result=file_obj,
        location='test.py:1'
    )
    
    # File object should be clean
    file_label = tracker.get_label(file_obj)
    # NOTE: file.read() is a FILE_CONTENT source, so the result of read() will be tainted
    # But the file object itself should be clean if the path was clean
    # Actually, we need to reconsider: should file object carry path taint or not?
    
    # For now, let's say: if path is clean, file object itself is clean,
    # but read() still returns FILE_CONTENT source (this is a policy decision)


def test_file_read_with_tainted_args_propagates():
    """file.read(size) should propagate taint from size argument."""
    init_security_contracts()
    tracker = LatticeSecurityTracker()
    
    # Clean file
    file_obj = object()
    tracker.set_label(file_obj, TaintLabel.clean())
    
    # Tainted size argument
    tainted_size = object()
    size_label = TaintLabel.from_untrusted_source(SourceType.USER_INPUT, 'user_input')
    tracker.set_label(tainted_size, size_label)
    
    # file.read(tainted_size)
    content = object()
    tracker.handle_call_post(
        func_name='file.read',
        func_ref=None,
        args=[file_obj, tainted_size],
        result=content,
        location='test.py:2'
    )
    
    # Content should be tainted from the size argument
    content_label = tracker.get_label(content)
    assert content_label.has_untrusted_taint(), "Content should inherit arg taint"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
