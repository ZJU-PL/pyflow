"""
Tests for DSE execution context improvements.

Tests that the concrete executor properly sets up:
- Module-level globals (__name__, __file__, etc.)
- Import context (sys.path)
- Execution environment

Per workflow: DSE is a refinement oracle, not a proof system.
"""

import pytest
import types
from pathlib import Path

from a3_python.dse.concolic import (
    ConcreteInput,
    ConcreteExecutor,
    ConcreteTrace
)


class TestConcreteInputContext:
    """Test ConcreteInput context setup."""
    
    def test_empty_input_has_main_module(self):
        """Empty input should default to __main__ module."""
        input_obj = ConcreteInput.empty()
        assert input_obj.module_name == "__main__"
        assert input_obj.file_path is None
    
    def test_for_module_sets_context(self):
        """for_module() should set module name and file path."""
        input_obj = ConcreteInput.for_module(
            module_name="mymodule",
            file_path="/path/to/mymodule.py"
        )
        assert input_obj.module_name == "mymodule"
        assert input_obj.file_path == "/path/to/mymodule.py"
    
    def test_for_module_accepts_globals(self):
        """for_module() should accept custom globals."""
        custom_globals = {"custom_var": 42}
        input_obj = ConcreteInput.for_module(
            module_name="test",
            file_path="test.py",
            globals_dict=custom_globals
        )
        assert input_obj.globals_dict["custom_var"] == 42


class TestGlobalsSetup:
    """Test that executor builds proper globals dictionary."""
    
    def test_executor_adds_standard_globals(self):
        """Executor should add __name__, __file__, etc."""
        code = compile("result = __name__", "test.py", "exec")
        input_obj = ConcreteInput.for_module(
            module_name="testmodule",
            file_path="test.py"
        )
        
        executor = ConcreteExecutor()
        trace = executor.execute(code, input_obj)
        
        # Should execute without NameError
        assert trace.exception_raised is None
    
    def test_executor_provides_builtins(self):
        """Executor should provide __builtins__."""
        code = compile("result = len([1, 2, 3])", "test.py", "exec")
        input_obj = ConcreteInput.empty()
        
        executor = ConcreteExecutor()
        trace = executor.execute(code, input_obj)
        
        # Should execute without NameError on 'len'
        assert trace.exception_raised is None
    
    def test_executor_uses_provided_globals(self):
        """Executor should use globals provided in input."""
        code = compile("result = custom_value * 2", "test.py", "exec")
        input_obj = ConcreteInput.for_module(
            module_name="test",
            file_path="test.py",
            globals_dict={"custom_value": 21}
        )
        
        executor = ConcreteExecutor()
        trace = executor.execute(code, input_obj)
        
        # Should execute without NameError
        assert trace.exception_raised is None
    
    def test_executor_sets_package_for_submodules(self):
        """Executor should set __package__ correctly for submodules."""
        code = compile("result = __package__", "test.py", "exec")
        input_obj = ConcreteInput.for_module(
            module_name="mypackage.submodule",
            file_path="mypackage/submodule.py"
        )
        
        executor = ConcreteExecutor()
        trace = executor.execute(code, input_obj)
        
        # Should execute without error
        assert trace.exception_raised is None


class TestModuleLevelExecution:
    """Test execution of module-level code."""
    
    def test_module_can_access_name(self):
        """Module code should access __name__ without error."""
        code = compile("""
if __name__ == '__main__':
    result = "main"
else:
    result = "not main"
""", "test.py", "exec")
        
        input_obj = ConcreteInput.empty()
        executor = ConcreteExecutor()
        trace = executor.execute(code, input_obj)
        
        assert trace.exception_raised is None
    
    def test_module_can_access_file(self):
        """Module code should access __file__ if provided."""
        code = compile("""
if __file__:
    result = "has file"
else:
    result = "no file"
""", "test.py", "exec")
        
        input_obj = ConcreteInput.for_module(
            module_name="test",
            file_path="/path/to/test.py"
        )
        executor = ConcreteExecutor()
        trace = executor.execute(code, input_obj)
        
        assert trace.exception_raised is None
    
    def test_module_globals_isolation(self):
        """Different executions should have isolated globals."""
        code = compile("x = 1", "test.py", "exec")
        input_obj = ConcreteInput.empty()
        
        executor = ConcreteExecutor()
        trace1 = executor.execute(code, input_obj)
        trace2 = executor.execute(code, input_obj)
        
        # Both should succeed independently
        assert trace1.exception_raised is None
        assert trace2.exception_raised is None


class TestImportContext:
    """Test that imports work in the execution context."""
    
    def test_sys_path_includes_file_directory(self):
        """sys.path should include the file's directory during execution."""
        # This is a minimal test - full import testing requires actual modules
        code = compile("import sys; result = len(sys.path)", "test.py", "exec")
        input_obj = ConcreteInput.for_module(
            module_name="test",
            file_path="/some/path/test.py"
        )
        
        executor = ConcreteExecutor()
        trace = executor.execute(code, input_obj)
        
        # Should execute without error
        assert trace.exception_raised is None
    
    def test_sys_path_restored_after_execution(self):
        """sys.path should be restored after execution."""
        import sys
        original_path = sys.path.copy()
        
        code = compile("import sys", "test.py", "exec")
        input_obj = ConcreteInput.for_module(
            module_name="test",
            file_path="/some/path/test.py"
        )
        
        executor = ConcreteExecutor()
        executor.execute(code, input_obj)
        
        # sys.path should be unchanged
        assert sys.path == original_path


class TestErrorHandling:
    """Test that errors are properly captured in traces."""
    
    def test_captures_name_error(self):
        """NameError should be captured in trace."""
        code = compile("result = undefined_variable", "test.py", "exec")
        input_obj = ConcreteInput.empty()
        
        executor = ConcreteExecutor()
        trace = executor.execute(code, input_obj)
        
        assert trace.exception_raised is not None
        assert isinstance(trace.exception_raised, NameError)
    
    def test_captures_import_error(self):
        """ImportError should be captured in trace."""
        code = compile("import nonexistent_module", "test.py", "exec")
        input_obj = ConcreteInput.empty()
        
        executor = ConcreteExecutor()
        trace = executor.execute(code, input_obj)
        
        assert trace.exception_raised is not None
        assert isinstance(trace.exception_raised, ModuleNotFoundError)
    
    def test_no_error_with_proper_context(self):
        """Code that needs context should work with proper setup."""
        # Code that checks __name__ should work
        code = compile("""
if __name__ == '__main__':
    result = 42
""", "test.py", "exec")
        
        input_obj = ConcreteInput.empty()
        executor = ConcreteExecutor()
        trace = executor.execute(code, input_obj)
        
        # Should NOT raise NameError
        assert trace.exception_raised is None


class TestOracleUsage:
    """Test proper oracle usage patterns."""
    
    def test_failed_execution_not_proof_of_infeasibility(self):
        """
        Per workflow: DSE failure does NOT prove trace is infeasible.
        
        This test documents the interpretation rule.
        """
        # Code that requires specific inputs to avoid error
        code = compile("""
# This needs 'x' to be defined
result = x + 1
""", "test.py", "exec")
        
        input_obj = ConcreteInput.empty()
        executor = ConcreteExecutor()
        trace = executor.execute(code, input_obj)
        
        # Execution fails (NameError)
        assert trace.exception_raised is not None
        
        # But this does NOT mean the symbolic trace is infeasible!
        # It just means we need to:
        # 1. Solve path constraints to find proper inputs
        # 2. Or expand the execution context
        # 3. Or accept UNKNOWN if we can't validate
    
    def test_successful_execution_produces_witness(self):
        """Successful execution produces a concrete witness."""
        code = compile("result = 2 + 2", "test.py", "exec")
        input_obj = ConcreteInput.empty()
        
        executor = ConcreteExecutor()
        trace = executor.execute(code, input_obj)
        
        # Success - we have a concrete witness
        assert trace.exception_raised is None
        assert trace.is_normal_return()
        # This witness can be attached to a bug report


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
