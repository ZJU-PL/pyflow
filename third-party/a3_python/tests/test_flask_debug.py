"""
Tests for FLASK_DEBUG detector (CWE-215): py/flask-debug

According to python-barrier-certificate-theory.md §11.34:

Unsafe region (static):
    U_flask_debug := { s | π == π_flask_run ∧ debug == True }

This tests detection of Flask applications running with debug=True, which
exposes the Werkzeug debugger (remote code execution risk).

Tests include:
- BUG tests: Flask with debug=True (3 tests)
- NON-BUG tests: Flask with debug=False or no debug (2 tests)
"""

import pytest
import tempfile
import os
from pathlib import Path
from a3_python.semantics.sota_intraprocedural import SOTAIntraproceduralAnalyzer


class TestFlaskDebug:
    """Test FLASK_DEBUG detection (CWE-215)."""
    
    def run_analysis(self, code: str) -> list:
        """Helper to run analysis on code and return violations."""
        # Compile the code
        code_obj = compile(code, '<test>', 'exec')
        
        # Find all function code objects
        violations = []
        for const in code_obj.co_consts:
            if hasattr(const, 'co_code'):
                # It's a function code object
                analyzer = SOTAIntraproceduralAnalyzer(
                    code_obj=const,
                    function_name=const.co_name,
                    file_path='<test>',
                    verbose=False
                )
                analyzer.analyze()
                violations.extend(analyzer.violations)
        
        return violations
    
    # ========================================================================
    # BUG TESTS: Flask with debug=True patterns
    # ========================================================================
    
    def test_flask_run_debug_true_explicit(self):
        """Detect app.run(debug=True) explicitly."""
        code = """
def start_app(app):
    app.run(debug=True)
"""
        violations = self.run_analysis(code)
        flask_debug_violations = [v for v in violations if v.bug_type == 'FLASK_DEBUG']
        assert len(flask_debug_violations) >= 1
        v = flask_debug_violations[0]
        assert v.bug_type == 'FLASK_DEBUG'
        assert 'debug' in v.reason.lower() or 'flask' in v.reason.lower()
    
    def test_flask_run_debug_true_variable(self):
        """Detect app.run with debug variable set to True."""
        code = """
def start_app(app):
    debug_mode = True
    app.run(debug=debug_mode)
"""
        violations = self.run_analysis(code)
        flask_debug_violations = [v for v in violations if v.bug_type == 'FLASK_DEBUG']
        assert len(flask_debug_violations) >= 1
    
    def test_flask_app_run_main_pattern(self):
        """Detect Flask debug=True in __main__ pattern."""
        code = """
from flask import Flask

def main():
    app = Flask(__name__)
    app.run(host='0.0.0.0', port=5000, debug=True)
"""
        violations = self.run_analysis(code)
        flask_debug_violations = [v for v in violations if v.bug_type == 'FLASK_DEBUG']
        assert len(flask_debug_violations) >= 1
    
    # ========================================================================
    # NON-BUG TESTS: Flask with debug=False or production patterns
    # ========================================================================
    
    def test_flask_run_debug_false(self):
        """Flask with debug=False should not trigger."""
        code = """
def start_app(app):
    app.run(debug=False)
"""
        violations = self.run_analysis(code)
        flask_debug_violations = [v for v in violations if v.bug_type == 'FLASK_DEBUG']
        assert len(flask_debug_violations) == 0
    
    def test_flask_run_no_debug(self):
        """Flask run() without debug parameter should not trigger."""
        code = """
def start_app(app):
    app.run(host='0.0.0.0', port=5000)
"""
        violations = self.run_analysis(code)
        flask_debug_violations = [v for v in violations if v.bug_type == 'FLASK_DEBUG']
        assert len(flask_debug_violations) == 0
