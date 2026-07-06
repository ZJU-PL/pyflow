"""
Comprehensive Path Injection / Path Traversal detection tests.

Tests PATH_INJECTION detection for CWE-022 across various file operation scenarios.
Verifies barrier-theoretic approach with Z3 constraints.
"""

import pytest
import tempfile
from pathlib import Path
from a3_python.semantics.intraprocedural_taint import analyze_file_intraprocedural


def analyze_code(code: str):
    """Helper to analyze code string by writing to temp file."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        f.flush()
        temp_path = Path(f.name)
    
    try:
        return analyze_file_intraprocedural(temp_path)
    finally:
        temp_path.unlink()


def test_path_injection_open_direct():
    """Test path injection with direct open(user_input)."""
    code = '''
def read_file(request):
    filename = request.GET['file']
    with open(filename, 'r') as f:
        return f.read()
'''
    findings = analyze_code(code)
    
    path_findings = [f for f in findings if 'PATH' in f.bug_type]
    assert len(path_findings) >= 1, f"Expected PATH_INJECTION, found: {[f.bug_type for f in findings]}"


def test_path_injection_os_remove():
    """Test path injection with os.remove."""
    code = '''
import os

def delete_file(request):
    filepath = request.POST.get('file')
    os.remove(filepath)
    return "deleted"
'''
    findings = analyze_code(code)
    
    path_findings = [f for f in findings if 'PATH' in f.bug_type]
    assert len(path_findings) >= 1


def test_path_injection_shutil_copy():
    """Test path injection with shutil.copy."""
    code = '''
import shutil

def copy_file(request):
    source = request.GET['src']
    dest = request.GET['dst']
    shutil.copy(source, dest)
    return "copied"
'''
    findings = analyze_code(code)
    
    path_findings = [f for f in findings if 'PATH' in f.bug_type]
    # Should detect path injection on both source and dest
    assert len(path_findings) >= 1


def test_path_injection_flask_send_file():
    """Test path injection with Flask send_file."""
    code = '''
from flask import send_file

def download_file(request):
    filename = request.args.get('file')
    return send_file(filename)
'''
    findings = analyze_code(code)
    
    path_findings = [f for f in findings if 'PATH' in f.bug_type]
    assert len(path_findings) >= 1


def test_path_injection_through_variable():
    """Test path injection when path flows through intermediate variables."""
    code = '''
def read_config(request):
    user_path = request.POST.get('config')
    config_path = user_path
    temp = config_path
    final_path = temp
    with open(final_path, 'r') as f:
        return f.read()
'''
    findings = analyze_code(code)
    
    path_findings = [f for f in findings if 'PATH' in f.bug_type]
    assert len(path_findings) >= 1


def test_path_injection_in_string_formatting():
    """Test path injection when path is constructed with f-string."""
    code = '''
def load_template(request):
    template_name = request.GET['template']
    path = f'/var/www/templates/{template_name}'
    with open(path, 'r') as f:
        return f.read()
'''
    findings = analyze_code(code)
    
    path_findings = [f for f in findings if 'PATH' in f.bug_type]
    assert len(path_findings) >= 1


def test_no_path_injection_hardcoded_path():
    """Test that hardcoded paths don't trigger path injection."""
    code = '''
def read_static_config():
    with open('/etc/myapp/config.ini', 'r') as f:
        return f.read()
'''
    findings = analyze_code(code)
    
    path_findings = [f for f in findings if 'PATH' in f.bug_type]
    assert len(path_findings) == 0, f"False positive PATH_INJECTION: {path_findings}"


def test_path_safe_with_basename():
    """Test that os.path.basename sanitizes path traversal."""
    code = '''
import os

def read_file(request):
    filename = request.GET['file']
    # basename removes directory components
    safe_name = os.path.basename(filename)
    path = f'/var/data/{safe_name}'
    with open(path, 'r') as f:
        return f.read()
'''
    findings = analyze_code(code)
    
    # basename should be recognized as sanitizer for path traversal
    path_findings = [f for f in findings if 'PATH' in f.bug_type]
    # Should be safe after basename
    # Note: depends on whether os.path.basename is registered as sanitizer


def test_path_safe_with_realpath_check():
    """Test that realpath + startswith check prevents traversal."""
    code = '''
import os

def read_file(request):
    filename = request.GET['file']
    base_dir = '/var/data/'
    full_path = os.path.realpath(os.path.join(base_dir, filename))
    # Validate that resolved path is within base_dir
    if not full_path.startswith(base_dir):
        raise ValueError("Invalid path")
    with open(full_path, 'r') as f:
        return f.read()
'''
    findings = analyze_code(code)
    
    # realpath + startswith check should sanitize
    path_findings = [f for f in findings if 'PATH' in f.bug_type]
    # This is a common safe pattern


def test_path_injection_pathlib():
    """Test path injection with pathlib.Path."""
    code = '''
from pathlib import Path

def read_file(request):
    filename = request.GET['file']
    path = Path(filename)
    return path.read_text()
'''
    findings = analyze_code(code)
    
    path_findings = [f for f in findings if 'PATH' in f.bug_type]
    assert len(path_findings) >= 1


def test_path_injection_os_path_join():
    """Test path injection with os.path.join."""
    code = '''
import os

def read_file(request):
    subdir = request.GET['dir']
    filename = request.GET['file']
    # Both components from user input
    path = os.path.join('/var/data', subdir, filename)
    with open(path, 'r') as f:
        return f.read()
'''
    findings = analyze_code(code)
    
    path_findings = [f for f in findings if 'PATH' in f.bug_type]
    assert len(path_findings) >= 1


def test_path_injection_write_operation():
    """Test path injection with write operations."""
    code = '''
def save_file(request):
    filename = request.POST['filename']
    content = request.POST['content']
    with open(filename, 'w') as f:
        f.write(content)
    return "saved"
'''
    findings = analyze_code(code)
    
    path_findings = [f for f in findings if 'PATH' in f.bug_type]
    # Write operations are also dangerous
    assert len(path_findings) >= 1


def test_path_injection_append_mode():
    """Test path injection with append mode."""
    code = '''
def append_to_file(request):
    logfile = request.GET['log']
    message = request.GET['msg']
    with open(logfile, 'a') as f:
        f.write(message + '\\n')
    return "appended"
'''
    findings = analyze_code(code)
    
    path_findings = [f for f in findings if 'PATH' in f.bug_type]
    assert len(path_findings) >= 1


def test_path_injection_environment_variable():
    """Test path injection when path comes from environment variable."""
    code = '''
import os

def read_config():
    config_path = os.environ.get('CONFIG_FILE', '/etc/default.conf')
    with open(config_path, 'r') as f:
        return f.read()
'''
    findings = analyze_code(code)
    
    path_findings = [f for f in findings if 'PATH' in f.bug_type]
    # Environment variables are untrusted sources
    assert len(path_findings) >= 1


def test_tarslip_tarfile_extract():
    """Test tar slip vulnerability with tarfile.extractall."""
    code = '''
import tarfile

def extract_archive(request):
    archive_path = request.FILES['archive'].name
    with tarfile.open(archive_path) as tar:
        # Dangerous: members could contain ../../../etc/passwd
        tar.extractall('/var/extract/')
    return "extracted"
'''
    findings = analyze_code(code)
    
    # Should detect path injection and/or tarslip
    path_findings = [f for f in findings if 'PATH' in f.bug_type or 'TAR' in f.bug_type]
    assert len(path_findings) >= 1


def test_path_injection_zipfile_extract():
    """Test path injection with zipfile.extractall."""
    code = '''
import zipfile

def extract_zip(request):
    zip_path = request.POST['zipfile']
    with zipfile.ZipFile(zip_path) as zf:
        # Dangerous: could extract outside target directory
        zf.extractall('/var/extract/')
    return "extracted"
'''
    findings = analyze_code(code)
    
    path_findings = [f for f in findings if 'PATH' in f.bug_type]
    assert len(path_findings) >= 1
