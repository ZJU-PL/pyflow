"""Test TAR_SLIP detection with kwargs (iteration 559)."""

import pytest
from pathlib import Path
import tempfile

from a3_python.semantics.intraprocedural_taint import analyze_file_intraprocedural


def analyze_code(code: str):
    """Analyze a temporary file with the intraprocedural taint engine."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        f.flush()
        temp_path = Path(f.name)

    try:
        return analyze_file_intraprocedural(temp_path)
    finally:
        temp_path.unlink()


@pytest.mark.xfail(reason="Current taint contracts do not yet model extractall(path=...) kwargs.")
def test_tarslip_with_path_kwarg():
    """tarfile.extractall(path=user_input) should trigger TARSLIP."""
    
    code = '''
import tarfile

def path_bug_4(user_input):
    """Tarfile extraction with tainted path - SHOULD FIND BUG"""
    with tarfile.open('archive.tar') as tar:
        tar.extractall(path=user_input)
'''
    
    bugs = analyze_code(code)
    assert any("TAR" in b.bug_type or "PATH" in b.bug_type for b in bugs)


@pytest.mark.xfail(reason="Current taint contracts do not yet model extractall(path=...) kwargs.")
def test_zipslip_with_path_kwarg():
    """zipfile.ZipFile.extractall(path=user_input) should trigger ZIPSLIP."""
    
    code = '''
import zipfile

def path_bug_5(user_input):
    """Zipfile extraction with tainted path - SHOULD FIND BUG"""
    with zipfile.ZipFile('archive.zip') as zf:
        zf.extractall(path=user_input)
'''
    
    bugs = analyze_code(code)
    assert any("ZIP" in b.bug_type or "PATH" in b.bug_type for b in bugs)


def test_tarfile_extractall_safe_constant():
    """tarfile.extractall with constant path should be SAFE."""
    
    code = '''
import tarfile

def safe_extract():
    """Constant path is safe"""
    with tarfile.open('archive.tar') as tar:
        tar.extractall(path='/safe/directory')
'''
    
    bugs = analyze_code(code)
    assert not any("TAR" in b.bug_type or "PATH" in b.bug_type for b in bugs)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
