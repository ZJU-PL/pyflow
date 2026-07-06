"""
Tests for interprocedural analysis infrastructure.

Tests call graph construction, taint summaries, and cross-function dataflow.
"""

import pytest
import tempfile
import os
from pathlib import Path


class TestCallGraphConstruction:
    """Tests for call graph building."""
    
    def test_simple_call_graph(self):
        """Test building call graph from simple code."""
        from a3_python.cfg.call_graph import build_call_graph_from_file
        
        code = '''
def helper(x):
    return x + 1

def main():
    result = helper(5)
    return result
'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()
            
            graph = build_call_graph_from_file(Path(f.name), 'test_module')
            
            assert 'test_module.helper' in graph.functions
            assert 'test_module.main' in graph.functions
            
            # main calls helper
            assert 'test_module.helper' in graph.edges.get('test_module.main', set())
            
            os.unlink(f.name)
    
    def test_method_calls(self):
        """Test call graph with method calls."""
        from a3_python.cfg.call_graph import build_call_graph_from_file
        
        code = '''
class MyClass:
    def method1(self):
        return self.method2()
    
    def method2(self):
        return 42
'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()
            
            graph = build_call_graph_from_file(Path(f.name), 'test_module')
            
            assert 'test_module.MyClass.method1' in graph.functions
            assert 'test_module.MyClass.method2' in graph.functions
            
            os.unlink(f.name)
    
    def test_imported_calls(self):
        """Test tracking of imported function calls."""
        from a3_python.cfg.call_graph import build_call_graph_from_file
        
        code = '''
from os.path import join

def combine(a, b):
    return join(a, b)
'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()
            
            graph = build_call_graph_from_file(Path(f.name), 'test_module')
            
            # join should be in external calls
            assert 'os.path.join' in graph.external_calls.get('test_module.combine', set())
            
            os.unlink(f.name)
    
    def test_scc_detection(self):
        """Test strongly connected component detection."""
        from a3_python.cfg.call_graph import build_call_graph_from_file
        
        code = '''
def even(n):
    if n == 0:
        return True
    return odd(n - 1)

def odd(n):
    if n == 0:
        return False
    return even(n - 1)
'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()
            
            graph = build_call_graph_from_file(Path(f.name), 'test_module')
            
            # Add edges for mutual recursion
            graph.add_edge('test_module.even', 'test_module.odd')
            graph.add_edge('test_module.odd', 'test_module.even')
            
            sccs = graph.compute_sccs()
            
            # Should have an SCC containing both functions
            mutual_scc = None
            for scc in sccs:
                if 'test_module.even' in scc and 'test_module.odd' in scc:
                    mutual_scc = scc
                    break
            
            assert mutual_scc is not None
            assert len(mutual_scc) == 2
            
            os.unlink(f.name)


class TestEntryPointDetection:
    """Tests for entry point detection."""
    
    def test_main_block_detection(self):
        """Test detection of if __name__ == "__main__" blocks."""
        from a3_python.frontend.entry_points import detect_entry_points_in_file
        
        code = '''
def main():
    print("Hello")

if __name__ == "__main__":
    main()
'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()
            
            entries = detect_entry_points_in_file(Path(f.name), 'test_module')
            
            entry_types = [e.entry_type for e in entries]
            assert 'main_block' in entry_types
            
            os.unlink(f.name)
    
    def test_flask_route_detection(self):
        """Test detection of Flask route decorators."""
        from a3_python.frontend.entry_points import detect_entry_points_in_file
        
        code = '''
from flask import Flask

app = Flask(__name__)

@app.route('/hello')
def hello():
    return "Hello World"
'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()
            
            entries = detect_entry_points_in_file(Path(f.name), 'test_module')
            
            route_entries = [e for e in entries if e.entry_type == 'flask_route']
            assert len(route_entries) >= 1
            assert route_entries[0].route_path == '/hello'
            
            os.unlink(f.name)
    
    def test_pytest_detection(self):
        """Test detection of pytest test functions."""
        from a3_python.frontend.entry_points import detect_entry_points_in_file
        
        code = '''
import pytest

def test_something():
    assert True

def test_another():
    assert 1 == 1
'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()
            
            entries = detect_entry_points_in_file(Path(f.name), 'test_module')
            
            test_entries = [e for e in entries if e.entry_type == 'pytest']
            assert len(test_entries) == 2
            
            os.unlink(f.name)


class TestTaintSummaries:
    """Tests for taint summary computation."""
    
    def test_identity_summary(self):
        """Test summary for identity function."""
        from a3_python.semantics.summaries import TaintSummary, TaintDependency
        
        summary = TaintSummary(
            function_name='identity',
            parameter_count=1,
            dependency=TaintDependency(param_to_return={0}),
        )
        
        # Tainted input -> tainted output
        result = summary.apply([(0b1, 0, 0)])
        assert result[0] == 0b1  # tau preserved
        
        # Clean input -> clean output
        result = summary.apply([(0, 0xFFFFFFFF, 0)])
        assert result[0] == 0  # tau stays clean
    
    def test_sanitizer_summary(self):
        """Test summary for sanitizer function."""
        from a3_python.semantics.summaries import TaintSummary, TaintDependency
        
        summary = TaintSummary(
            function_name='escape',
            parameter_count=1,
            dependency=TaintDependency(
                param_to_return={0},
                is_sanitizer=True,
                sinks_protected={6},  # HTML_RENDER sink
            ),
        )
        
        # Tainted input gets sanitized for HTML sink
        result = summary.apply([(0b1, 0, 0)])
        assert result[0] == 0b1  # tau preserved
        assert result[1] & (1 << 6)  # kappa has HTML_RENDER bit set
    
    def test_source_summary(self):
        """Test summary for source function."""
        from a3_python.semantics.summaries import TaintSummary, TaintDependency
        
        summary = TaintSummary(
            function_name='get_input',
            parameter_count=0,
            dependency=TaintDependency(
                introduces_taint=True,
                source_type=0,  # HTTP_PARAM
            ),
        )
        
        # No args, returns tainted value
        result = summary.apply([])
        assert result[0] == 0b1  # tau has HTTP_PARAM bit
    
    def test_join_summary(self):
        """Test summary that joins multiple parameters."""
        from a3_python.semantics.summaries import TaintSummary, TaintDependency
        
        summary = TaintSummary(
            function_name='concat',
            parameter_count=2,
            dependency=TaintDependency(param_to_return={0, 1}),
        )
        
        # Both params flow to return
        result = summary.apply([
            (0b01, 0b11, 0),  # param0: tau={0}, kappa={0,1}
            (0b10, 0b10, 0),  # param1: tau={1}, kappa={1}
        ])
        
        assert result[0] == 0b11  # tau = union = {0,1}
        assert result[1] == 0b10  # kappa = intersection = {1}


class TestInterproceduralTracker:
    """Tests for interprocedural taint tracking."""
    
    def test_summary_application(self):
        """Test that summaries are applied at call sites."""
        from a3_python.semantics.interprocedural_taint import InterproceduralTaintTracker
        from a3_python.semantics.summaries import TaintSummary, TaintDependency
        from a3_python.cfg.call_graph import CallGraph, FunctionInfo
        from a3_python.semantics.interprocedural_taint import InterproceduralContext
        
        # Create minimal context
        graph = CallGraph()
        graph.add_function(FunctionInfo(
            name='identity',
            qualified_name='test.identity',
            file_path='test.py',
            line_number=1,
            parameters=['x'],
        ))
        
        summaries = {
            'test.identity': TaintSummary(
                function_name='test.identity',
                parameter_count=1,
                dependency=TaintDependency(param_to_return={0}),
            ),
        }
        
        context = InterproceduralContext(
            call_graph=graph,
            summaries=summaries,
            entry_points={'test.main'},
            reachable_functions={'test.identity', 'test.main'},
        )
        
        tracker = InterproceduralTaintTracker(context=context)
        
        # Create a tainted value
        from a3_python.z3model.taint_lattice import TaintLabel, SourceType
        tainted_val = object()
        tracker.set_label(tainted_val, TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM))
        
        # Apply summary via handle_call_post
        result_val = object()
        concrete, symbolic = tracker.handle_call_post(
            'test.identity',
            None,  # func_ref (not used for summaries)
            [tainted_val],
            result_val,
            'test.py:10',
        )
        
        # Result should be tainted
        assert concrete.tau != 0


class TestCrossFileTaint:
    """Tests for cross-file taint tracking."""
    
    def test_cross_file_flow(self):
        """Test taint flowing across file boundaries."""
        from a3_python.cfg.call_graph import build_call_graph_from_directory
        from a3_python.semantics.summaries import SummaryComputer
        from a3_python.frontend.entry_points import detect_entry_points_in_project
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create source file
            source_file = Path(tmpdir) / 'sources.py'
            source_file.write_text('''
def get_input():
    return input()
''')
            
            # Create handler file
            handler_file = Path(tmpdir) / 'handlers.py'
            handler_file.write_text('''
from sources import get_input

def process():
    data = get_input()
    return data
''')
            
            # Build call graph
            graph = build_call_graph_from_directory(Path(tmpdir))
            
            # Should have both functions
            assert 'sources.get_input' in graph.functions
            assert 'handlers.process' in graph.functions
            
            # Compute summaries
            computer = SummaryComputer(graph)
            summaries = computer.compute_all()
            
            # get_input summary should exist
            assert 'sources.get_input' in summaries


class TestBugDeduplication:
    """Tests for interprocedural bug deduplication."""
    
    def test_deduplicate_by_location_and_type(self):
        """Test that bugs are deduplicated by (file:line, bug_type)."""
        from a3_python.semantics.interprocedural_bugs import (
            InterproceduralBugTracker,
            InterproceduralBug,
        )
        
        # Create duplicate bugs at same location
        bugs = [
            InterproceduralBug(
                bug_type='SQL_INJECTION',
                crash_function='handler1',
                crash_location='app.py:100',
                call_chain=['main', 'handler1'],
                reason='Test',
                confidence=0.8,
            ),
            InterproceduralBug(
                bug_type='SQL_INJECTION',
                crash_function='handler1',
                crash_location='app.py:100',
                call_chain=['main', 'route', 'handler1'],  # Longer chain
                reason='Test',
                confidence=0.9,
            ),
            InterproceduralBug(
                bug_type='SQL_INJECTION',
                crash_function='handler1',
                crash_location='app.py:100',
                call_chain=['main', 'handler1'],  # Same length as first
                reason='Test',
                confidence=0.9,  # Higher confidence
            ),
        ]
        
        tracker = InterproceduralBugTracker(
            call_graph=None,
            entry_points=set(),
            reachable_functions=set(),
        )
        deduplicated = tracker._deduplicate_bugs(bugs)
        
        # Should deduplicate to 1 bug
        assert len(deduplicated) == 1
        
        # Should keep the shortest chain with highest confidence
        bug = deduplicated[0]
        assert len(bug.call_chain) == 2
        assert bug.confidence == 0.9
    
    def test_different_locations_not_deduplicated(self):
        """Test that bugs at different locations are kept separate."""
        from a3_python.semantics.interprocedural_bugs import (
            InterproceduralBugTracker,
            InterproceduralBug,
        )
        
        bugs = [
            InterproceduralBug(
                bug_type='SQL_INJECTION',
                crash_function='handler1',
                crash_location='app.py:100',
                call_chain=['main', 'handler1'],
                reason='Test',
                confidence=0.8,
            ),
            InterproceduralBug(
                bug_type='SQL_INJECTION',
                crash_function='handler2',
                crash_location='app.py:200',  # Different location
                call_chain=['main', 'handler2'],
                reason='Test',
                confidence=0.8,
            ),
        ]
        
        tracker = InterproceduralBugTracker(
            call_graph=None,
            entry_points=set(),
            reachable_functions=set(),
        )
        deduplicated = tracker._deduplicate_bugs(bugs)
        
        # Should keep both bugs (different locations)
        assert len(deduplicated) == 2
    
    def test_different_bug_types_not_deduplicated(self):
        """Test that different bug types at same location are kept separate."""
        from a3_python.semantics.interprocedural_bugs import (
            InterproceduralBugTracker,
            InterproceduralBug,
        )
        
        bugs = [
            InterproceduralBug(
                bug_type='SQL_INJECTION',
                crash_function='handler1',
                crash_location='app.py:100',
                call_chain=['main', 'handler1'],
                reason='Test',
                confidence=0.8,
            ),
            InterproceduralBug(
                bug_type='COMMAND_INJECTION',  # Different type
                crash_function='handler1',
                crash_location='app.py:100',  # Same location
                call_chain=['main', 'handler1'],
                reason='Test',
                confidence=0.8,
            ),
        ]
        
        tracker = InterproceduralBugTracker(
            call_graph=None,
            entry_points=set(),
            reachable_functions=set(),
        )
        deduplicated = tracker._deduplicate_bugs(bugs)
        
        # Should keep both bugs (different types)
        assert len(deduplicated) == 2


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
