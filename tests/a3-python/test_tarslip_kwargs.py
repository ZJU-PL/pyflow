"""Test TAR_SLIP detection with kwargs (iteration 559)."""

import pytest
from pathlib import Path
import tempfile
import subprocess
import sys


def test_tarslip_with_path_kwarg(tmp_path):
    """tarfile.extractall(path=user_input) should trigger TARSLIP."""
    
    code = '''
import tarfile

def path_bug_4(user_input):
    """Tarfile extraction with tainted path - SHOULD FIND BUG"""
    with tarfile.open('archive.tar') as tar:
        tar.extractall(path=user_input)
'''
    
    test_file = tmp_path / "test_tarslip.py"
    test_file.write_text(code)
    
    result = subprocess.run(
        [sys.executable, "-m", "pyfromscratch.cli", str(test_file)],
        capture_output=True,
        text=True
    )
    
    # Should find TARSLIP violation
    # Exit code 1 = BUG found
    assert result.returncode == 1, f"Expected BUG (1), got {result.returncode}: stdout={result.stdout}, stderr={result.stderr}"
    assert "TARSLIP" in result.stdout or "PATH_INJECTION" in result.stdout, f"Should detect TAR_SLIP or PATH_INJECTION: {result.stdout}"


def test_zipslip_with_path_kwarg(tmp_path):
    """zipfile.ZipFile.extractall(path=user_input) should trigger ZIPSLIP."""
    
    code = '''
import zipfile

def path_bug_5(user_input):
    """Zipfile extraction with tainted path - SHOULD FIND BUG"""
    with zipfile.ZipFile('archive.zip') as zf:
        zf.extractall(path=user_input)
'''
    
    test_file = tmp_path / "test_zipslip.py"
    test_file.write_text(code)
    
    result = subprocess.run(
        [sys.executable, "-m", "pyfromscratch.cli", str(test_file)],
        capture_output=True,
        text=True
    )
    
    # Should find ZIPSLIP violation
    assert result.returncode == 1, f"Expected BUG (1), got {result.returncode}: stdout={result.stdout}, stderr={result.stderr}"
    assert "ZIPSLIP" in result.stdout or "PATH_INJECTION" in result.stdout, f"Should detect ZIP_SLIP or PATH_INJECTION: {result.stdout}"


def test_tarfile_extractall_safe_constant(tmp_path):
    """tarfile.extractall with constant path should be SAFE."""
    
    code = '''
import tarfile

def safe_extract():
    """Constant path is safe"""
    with tarfile.open('archive.tar') as tar:
        tar.extractall(path='/safe/directory')
'''
    
    test_file = tmp_path / "test_tar_safe.py"
    test_file.write_text(code)
    
    result = subprocess.run(
        [sys.executable, "-m", "pyfromscratch.cli", str(test_file)],
        capture_output=True,
        text=True
    )
    
    # Should find NO violations (constant path is safe)
    assert result.returncode == 0, f"Expected SAFE (0), got {result.returncode}: stdout={result.stdout}, stderr={result.stderr}"
    assert "TARSLIP" not in result.stdout, f"Should not detect TAR_SLIP with constant path"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
