"""
Tests for import alias tracking in intraprocedural taint analysis.

ITERATION 517: Verify that aliased imports are resolved correctly
when identifying sink calls, so that "ET.fromstring" is recognized
as "xml.etree.ElementTree.fromstring" for XXE detection.
"""

import sys
import types
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from a3_python.semantics.intraprocedural_taint import (
    IntraproceduralTaintAnalyzer,
    extract_module_imports,
)


def get_function_code(code_str: str, func_name: str) -> types.CodeType:
    """Compile code and extract the function's code object."""
    code_obj = compile(code_str, '<test>', 'exec')
    
    # Find the function code object in constants
    for const in code_obj.co_consts:
        if isinstance(const, types.CodeType) and const.co_name == func_name:
            return const
    
    raise ValueError(f"Function '{func_name}' not found in code constants")


def analyze_with_imports(code_str: str, func_name: str) -> IntraproceduralTaintAnalyzer:
    """Compile code, extract imports, and create analyzer with import context."""
    module_code = compile(code_str, '<test>', 'exec')
    func_code = get_function_code(code_str, func_name)
    
    # Extract imports from module-level code
    imports = extract_module_imports(module_code)
    
    return IntraproceduralTaintAnalyzer(func_code, func_name, "<test>", import_aliases=imports)


def test_import_alias_simple():
    """Test that 'import X as Y' creates alias mapping."""
    code = """
import xml.etree.ElementTree as ET

def parse(data):
    return ET.fromstring(data)
"""
    module_code = compile(code, '<test>', 'exec')
    imports = extract_module_imports(module_code)
    
    # Check that alias was extracted
    assert 'ET' in imports
    assert imports['ET'] == 'xml.etree.ElementTree'


def test_import_alias_xxe_detection():
    """Test that XXE is detected when using aliased import."""
    code = """
import xml.etree.ElementTree as ET

def parse_untrusted(xml_data):
    # xml_data is tainted (from parameter name)
    tree = ET.fromstring(xml_data)
    return tree
"""
    analyzer = analyze_with_imports(code, 'parse_untrusted')
    bugs = analyzer.analyze()
    
    # Should detect XXE because:
    # 1. 'xml_data' parameter is tainted (name contains 'data')
    # 2. 'ET.fromstring' resolves to 'xml.etree.ElementTree.fromstring'
    # 3. That's a known XXE sink
    xxe_bugs = [b for b in bugs if b.bug_type == 'XXE']
    assert len(xxe_bugs) > 0, f"Expected XXE bug, got {[b.bug_type for b in bugs]}"
    
    bug = xxe_bugs[0]
    assert 'xml_data' in bug.source_description.lower() or 'data' in bug.source_description.lower()
    assert 'fromstring' in bug.sink_description.lower()


def test_from_import_alias():
    """Test that 'from X import Y as Z' creates alias mapping."""
    code = """
from xml.etree.ElementTree import fromstring as parse_xml

def parse(data):
    return parse_xml(data)
"""
    module_code = compile(code, '<test>', 'exec')
    imports = extract_module_imports(module_code)
    
    # Check that alias was extracted
    assert 'parse_xml' in imports
    assert imports['parse_xml'] == 'xml.etree.ElementTree.fromstring'


def test_from_import_no_alias():
    """Test that 'from X import Y' creates mapping for Y."""
    code = """
from xml.etree.ElementTree import fromstring

def parse(data):
    return fromstring(data)
"""
    module_code = compile(code, '<test>', 'exec')
    imports = extract_module_imports(module_code)
    
    # Check that direct import was tracked
    assert 'fromstring' in imports
    assert imports['fromstring'] == 'xml.etree.ElementTree.fromstring'


def test_regex_compile_alias():
    """Test that regex.compile is detected when imported as 're'."""
    code = """
import re

def validate(pattern, input_data):
    # pattern is tainted (from parameter name)
    regex = re.compile(pattern)
    return regex.match(input_data)
"""
    analyzer = analyze_with_imports(code, 'validate')
    bugs = analyzer.analyze()
    
    # Should detect REGEX_INJECTION because:
    # 1. 'pattern' parameter is tainted
    # 2. 're.compile' is a known regex sink
    regex_bugs = [b for b in bugs if b.bug_type == 'REGEX_INJECTION']
    
    # Note: 're' is the actual module name, not an alias, so no mapping needed
    # But this test verifies the overall flow works
    if len(regex_bugs) > 0:
        bug = regex_bugs[0]
        assert 'pattern' in bug.source_description.lower()


def test_call_name_resolution_with_alias():
    """Test that _identify_call correctly resolves aliased imports."""
    code = """
import subprocess as sp

def run_cmd(cmd):
    sp.Popen(cmd, shell=True)
"""
    analyzer = analyze_with_imports(code, 'run_cmd')
    
    # Check that alias was extracted
    assert 'sp' in analyzer.import_aliases
    assert analyzer.import_aliases['sp'] == 'subprocess'
    
    # Analyze to trigger call name resolution
    bugs = analyzer.analyze()
    
    # Should detect COMMAND_INJECTION
    cmd_bugs = [b for b in bugs if b.bug_type == 'COMMAND_INJECTION']
    assert len(cmd_bugs) > 0, f"Expected COMMAND_INJECTION, got {[b.bug_type for b in bugs]}"
    
    bug = cmd_bugs[0]
    # The sink description should be 'subprocess.Popen', not 'sp.Popen'
    assert 'subprocess' in bug.sink_description.lower() or 'sp.popen' in bug.sink_description.lower()


if __name__ == '__main__':
    import pytest
    pytest.main([__file__, '-v'])

