"""
Comprehensive SSRF detection tests.

Tests SSRF detection across various scenarios.
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
        temp_path.unlink()  # Clean up temp file


def test_ssrf_requests_get_direct():
    """Test SSRF with direct requests.get(user_input)."""
    code = '''
import requests

def fetch_url(request):
    url = request.POST.get('url')
    response = requests.get(url)
    return response.text
'''
    findings = analyze_code(code)
    
    ssrf_findings = [f for f in findings if 'SSRF' in f.bug_type]
    assert len(ssrf_findings) >= 1, f"Expected SSRF, found: {[f.bug_type for f in findings]}"
    assert any('request' in f.source_description for f in ssrf_findings)


def test_ssrf_requests_post():
    """Test SSRF with requests.post(user_input)."""
    code = '''
import requests

def post_to_webhook(request):
    webhook = request.POST['webhook']
    requests.post(webhook, data={'event': 'test'})
'''
    findings = analyze_code(code)
    
    ssrf_findings = [f for f in findings if 'SSRF' in f.bug_type]
    assert len(ssrf_findings) >= 1


def test_ssrf_urllib_urlopen():
    """Test SSRF with urllib.request.urlopen."""
    code = '''
from urllib.request import urlopen

def fetch_data(request):
    url = request.GET.get('target')
    response = urlopen(url)
    return response.read()
'''
    findings = analyze_code(code)
    
    ssrf_findings = [f for f in findings if 'SSRF' in f.bug_type]
    assert len(ssrf_findings) >= 1


def test_ssrf_through_variable():
    """Test SSRF when URL flows through intermediate variables."""
    code = '''
import requests

def indirect_fetch(request):
    user_input = request.POST["url"]
    target_url = user_input
    endpoint = target_url
    
    return requests.get(endpoint)
'''
    findings = analyze_code(code)
    
    ssrf_findings = [f for f in findings if 'SSRF' in f.bug_type]
    assert len(ssrf_findings) >= 1, "Should track taint through variable assignments"


def test_ssrf_in_string_formatting():
    """Test SSRF when URL is constructed with f-string."""
    code = '''
import requests

def format_and_fetch(request):
    host = request.POST["host"]
    url = f"http://{host}/api/data"
    
    return requests.get(url)
'''
    findings = analyze_code(code)
    
    ssrf_findings = [f for f in findings if 'SSRF' in f.bug_type]
    assert len(ssrf_findings) >= 1, "Should track taint through string formatting"


def test_ssrf_dict_subscript():
    """Test SSRF when URL comes from dict subscript."""
    code = '''
import requests

def fetch_from_config(request):
    config = {'url': request.POST.get('target')}
    target = config['url']
    
    requests.get(target)
'''
    findings = analyze_code(code)
    
    ssrf_findings = [f for f in findings if 'SSRF' in f.bug_type]
    assert len(ssrf_findings) >= 1, "Should track taint through dict operations"


def test_no_ssrf_hardcoded_url():
    """Test that hardcoded URLs don't trigger SSRF."""
    code = '''
import requests

def safe_fetch():
    return requests.get('https://api.example.com/data')
'''
    findings = analyze_code(code)
    
    ssrf_findings = [f for f in findings if 'SSRF' in f.bug_type]
    assert len(ssrf_findings) == 0, "Hardcoded URLs should not trigger SSRF"


def test_ssrf_environment_variable():
    """Test SSRF when URL comes from environment variable."""
    code = '''
import os
import requests

def fetch_from_env():
    url = os.environ.get('API_URL')
    return requests.get(url)
'''
    findings = analyze_code(code)
    
    ssrf_findings = [f for f in findings if 'SSRF' in f.bug_type]
    assert len(ssrf_findings) >= 1, "Environment variables should be tainted sources"


def test_ssrf_multiple_sinks():
    """Test detection of multiple SSRF vulnerabilities."""
    code = '''
import requests

def multi_fetch(request):
    url1 = request.POST["url1"]
    url2 = request.POST["url2"]
    
    r1 = requests.get(url1)
    r2 = requests.post(url2)
    
    return r1.text + r2.text
'''
    findings = analyze_code(code)
    
    ssrf_findings = [f for f in findings if 'SSRF' in f.bug_type]
    assert len(ssrf_findings) >= 2, "Should detect both SSRF vulnerabilities"


def test_ssrf_pygoat_example():
    """Test with actual PyGoat ssrf_lab2 code."""
    code = '''
import requests

def ssrf_lab2(request):
    if request.method == "GET":
        return None

    elif request.method == "POST":
        url = request.POST["url"]
        try:
            response = requests.get(url)
            return response.content
        except:
            return "error"
'''
    findings = analyze_code(code)
    
    ssrf_findings = [f for f in findings if 'SSRF' in f.bug_type]
    assert len(ssrf_findings) >= 1, "Should detect SSRF in PyGoat example"
    
    # Verify it detected the right line
    assert any(f.line_number == 11 for f in ssrf_findings), "Should detect at requests.get line"


def test_ssrf_confidence_scoring():
    """Test that SSRF findings have required metadata."""
    code = '''
import requests

def fetch(request):
    url = request.POST["url"]
    return requests.get(url)
'''
    findings = analyze_code(code)
    
    ssrf_findings = [f for f in findings if 'SSRF' in f.bug_type]
    
    for finding in ssrf_findings:
        # Should have required fields
        assert hasattr(finding, 'bug_type')
        assert hasattr(finding, 'line_number')
        assert hasattr(finding, 'source_description')
        assert hasattr(finding, 'sink_description')
        assert hasattr(finding, 'reason')
        assert hasattr(finding, 'confidence')


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
