import pytest
import os
from pathlib import Path
from typing import Dict, Set, List, Optional, Tuple

# Helper function to get the absolute path to benchmark files
def get_benchmark_path(filename):
    project_root = Path(__file__).parent.parent.parent.absolute()
    return project_root / 'benchmark' / filename

# Helper to mark tests that should only run in integration mode
def pytest_addoption(parser):
    parser.addoption(
        "--run-integration", action="store_true", default=False, help="run integration tests"
    )

def pytest_configure(config):
    config.addinivalue_line("markers", "integration: mark test as integration test")

def pytest_collection_modifyitems(config, items):
    if config.getoption("--run-integration"):
        # --run-integration given in cli: do not skip integration tests
        return
    skip_integration = pytest.mark.skip(reason="need --run-integration option to run")
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip_integration)

# Fixture for creating basic module and function infrastructure
@pytest.fixture
def mock_module():
    from pyflow.analysis.pointer._pythonstan.ir.ir_statements import IRModule
    return IRModule("test_module")

@pytest.fixture
def abstract_state():
    from pyflow.analysis.pointer._pythonstan.analysis.ai import AbstractState, ContextType, FlowSensitivity
    return AbstractState(ContextType.CALL_SITE, FlowSensitivity.SENSITIVE)

@pytest.fixture
def abstract_interpreter(abstract_state):
    from pyflow.analysis.pointer._pythonstan.analysis.ai import AbstractInterpreter
    return AbstractInterpreter(abstract_state)

@pytest.fixture
def abstract_solver():
    from pyflow.analysis.pointer._pythonstan.analysis.ai import create_solver, ContextType, FlowSensitivity
    return create_solver(
        context_type=ContextType.CALL_SITE,
        flow_sensitivity=FlowSensitivity.SENSITIVE,
        context_depth=1,
        max_iterations=50,
        max_recursion_depth=3
    )


# ===== Pointer Analysis Fixtures =====

@pytest.fixture
def make_pointer_results():
    """Factory fixture for creating pointer analysis results with different configurations."""
    from pyflow.analysis.pointer._pythonstan.analysis.ai.pointer_adapter import MockPointerResults
    
    def _create_pointer_results(
        precise: bool = True,
        singleton_vars: Optional[Set[str]] = None,
        alias_pairs: Optional[Set[Tuple[str, str]]] = None,
        callee_map: Optional[Dict[str, Set[str]]] = None
    ) -> MockPointerResults:
        """
        Create mock pointer results for testing.
        
        Args:
            precise: Whether to provide precise results (False = over-approximate)
            singleton_vars: Set of variables that are singletons
            alias_pairs: Set of variable pairs that may alias
            callee_map: Mapping from call site IDs to possible callee names
        
        Returns:
            MockPointerResults instance configured as specified
        """
        return MockPointerResults(
            precise=precise,
            singleton_vars=singleton_vars or set(),
            alias_pairs=alias_pairs or set(),
            callee_map=callee_map or {}
        )
    
    return _create_pointer_results


@pytest.fixture
def precise_pointer_results(make_pointer_results):
    """Precise pointer analysis results for testing."""
    return make_pointer_results(
        precise=True,
        singleton_vars={"singleton_obj", "unique_var", "single_instance"},
        alias_pairs={("alias_a", "alias_b"), ("param", "arg"), ("obj", "self")},
        callee_map={
            "direct_call": {"target_function"},
            "indirect_call": {"method_a", "method_b"},
            "virtual_call": {"base_method", "derived_method"},
            "factory_call": {"create_instance"}
        }
    )


@pytest.fixture 
def imprecise_pointer_results(make_pointer_results):
    """Imprecise pointer analysis results (over-approximating) for testing."""
    return make_pointer_results(
        precise=False,
        singleton_vars=set(),  # No singletons in imprecise mode
        alias_pairs=set(),     # Will over-approximate all aliases
        callee_map={}          # Will over-approximate all callees
    )


@pytest.fixture
def moderate_pointer_results(make_pointer_results):
    """Moderately precise pointer analysis results for testing."""
    return make_pointer_results(
        precise=True,
        singleton_vars={"singleton_obj"},
        alias_pairs={("alias_a", "alias_b")},
        callee_map={
            "monomorphic_call": {"specific_method"},
            "polymorphic_call": {"method_a", "method_b", "method_c"}
        }
    )


@pytest.fixture
def mock_call_sites():
    """Factory for creating mock call sites."""
    from pyflow.analysis.pointer._pythonstan.analysis.ai.pointer_adapter import MockCallSite
    
    def _create_call_sites(count: int = 3, prefix: str = "call") -> List[MockCallSite]:
        """Create a list of mock call sites for testing."""
        return [
            MockCallSite(f"{prefix}_{i}", f"test_{i}.py", i * 10, i * 5)
            for i in range(count)
        ]
    
    return _create_call_sites


@pytest.fixture
def mock_abstract_objects():
    """Factory for creating mock abstract objects."""
    from pyflow.analysis.pointer._pythonstan.analysis.ai.pointer_adapter import MockAbstractObject
    
    def _create_objects(count: int = 3, prefix: str = "obj") -> List[MockAbstractObject]:
        """Create a list of mock abstract objects for testing."""
        return [
            MockAbstractObject(f"{prefix}_{i}")
            for i in range(count)
        ]
    
    return _create_objects


@pytest.fixture
def field_keys():
    """Factory for creating different types of field keys."""
    from pyflow.analysis.pointer._pythonstan.analysis.ai.pointer_adapter import (
        AttrFieldKey, ElemFieldKey, ValueFieldKey, UnknownFieldKey
    )
    
    def _create_field_keys() -> Dict[str, object]:
        """Create examples of different field key types."""
        return {
            "attr_field": AttrFieldKey("attribute_name"),
            "elem_field": ElemFieldKey(0),
            "elem_field_generic": ElemFieldKey(),
            "value_field": ValueFieldKey("dict_key"),
            "value_field_generic": ValueFieldKey(),
            "unknown_field": UnknownFieldKey()
        }
    
    return _create_field_keys


@pytest.fixture
def mock_contexts():
    """Factory for creating mock analysis contexts."""
    from pyflow.analysis.pointer._pythonstan.analysis.ai.pointer_adapter import MockContext, MockCallSite
    
    def _create_contexts(depth: int = 2) -> List[MockContext]:
        """Create mock contexts with different call string depths."""
        contexts = [MockContext()]  # Empty context
        
        # Create contexts with increasing call string depth
        call_sites = []
        for i in range(depth):
            call_site = MockCallSite(f"call_{i}", f"file_{i}.py", i * 10, i * 5)
            call_sites.append(call_site)
            contexts.append(MockContext(tuple(call_sites)))
        
        return contexts
    
    return _create_contexts


@pytest.fixture
def pointer_enabled_ai_solver():
    """AI solver configured to work with pointer analysis results."""
    from pyflow.analysis.pointer._pythonstan.analysis.ai import create_solver, ContextType, FlowSensitivity
    
    return create_solver(
        context_type=ContextType.CALL_SITE,
        flow_sensitivity=FlowSensitivity.SENSITIVE,
        context_depth=2,
        max_iterations=100,
        max_recursion_depth=5
    )


@pytest.fixture
def legacy_ai_solver():
    """Legacy AI solver without pointer analysis (for comparison)."""
    from pyflow.analysis.pointer._pythonstan.analysis.ai import create_solver, ContextType, FlowSensitivity
    
    return create_solver(
        context_type=ContextType.INSENSITIVE,
        flow_sensitivity=FlowSensitivity.INSENSITIVE,
        context_depth=0,
        max_iterations=50,
        max_recursion_depth=2
    )


@pytest.fixture
def benchmark_pointer_scenarios():
    """Pointer analysis scenarios based on benchmark patterns."""
    return {
        "oop_inheritance": {
            "description": "Object-oriented inheritance with virtual calls",
            "singleton_vars": {"base_instance"},
            "alias_pairs": {("this", "self"), ("base_ref", "obj")},
            "callee_map": {
                "virtual_method_call": {"Base.method", "Derived.method"},
                "constructor_call": {"Base.__init__", "Derived.__init__"}
            }
        },
        "closure_capture": {
            "description": "Closure variable capture and modification",
            "singleton_vars": {"closure_func"},
            "alias_pairs": {("outer_var", "captured_var"), ("closure_result", "return_val")},
            "callee_map": {
                "closure_call": {"inner_function"},
                "callback_call": {"closure_func"}
            }
        },
        "generator_state": {
            "description": "Generator function state management",
            "singleton_vars": {"generator_obj"},
            "alias_pairs": {("gen_state", "local_state")},
            "callee_map": {
                "next_call": {"generator.next", "generator.__next__"},
                "send_call": {"generator.send"}
            }
        },
        "dataflow_chains": {
            "description": "Complex dataflow chains with multiple assignments",
            "singleton_vars": set(),  # No singletons in complex dataflow
            "alias_pairs": {("temp_var", "result_var"), ("input_param", "processed_val")},
            "callee_map": {
                "transform_call": {"transform_func", "process_func"},
                "aggregate_call": {"sum_func", "collect_func"}
            }
        }
    }


@pytest.fixture
def integration_test_helpers():
    """Helpers for integration testing between AI and pointer analysis."""
    def create_integrated_analysis_scenario(
        pointer_results,
        ai_solver,
        test_program: str
    ) -> Dict[str, object]:
        """
        Create an integrated analysis scenario for testing.
        
        Args:
            pointer_results: Pointer analysis results to use
            ai_solver: AI solver instance
            test_program: Python code string to analyze
        
        Returns:
            Dictionary containing analysis components and utilities
        """
        import ast
        
        # Parse the test program
        ast_module = ast.parse(test_program)
        
        # In a real implementation, this would:
        # 1. Convert to IR
        # 2. Build CFG
        # 3. Run pointer analysis
        # 4. Run AI analysis with pointer results
        # 5. Compare and verify consistency
        
        return {
            "ast_module": ast_module,
            "pointer_results": pointer_results,
            "ai_solver": ai_solver,
            "test_program": test_program,
            "analysis_methods": {
                "check_consistency": lambda: True,  # Mock
                "measure_precision": lambda: 0.85,  # Mock
                "validate_soundness": lambda: True  # Mock
            }
        }
    
    return {
        "create_scenario": create_integrated_analysis_scenario,
        "benchmark_programs": {
            "simple_assignment": "x = 42; y = x + 1; print(y)",
            "function_call": "def f(x): return x * 2\nresult = f(21)",
            "object_method": "class C:\n  def m(self): return 42\nobj = C()\nval = obj.m()",
            "conditional": "x = 10\nif x > 5:\n  y = x\nelse:\n  y = 0\nprint(y)"
        }
    } 
