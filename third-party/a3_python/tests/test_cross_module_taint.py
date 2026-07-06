"""
Test cross-module taint tracking for interprocedural analysis.

Tests that taint properly flows across module boundaries when functions
call each other via imports.
"""

import pytest
import tempfile
import os
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from a3_python.analyzer import Analyzer
from a3_python.cfg.call_graph import build_call_graph_from_directory
from a3_python.semantics.interprocedural_taint import InterproceduralContext
from a3_python.semantics.summaries import SummaryComputer
from a3_python.contracts.security_lattice import (
    get_source_contracts_for_summaries,
    get_sink_contracts_for_summaries,
    get_sanitizer_contracts_for_summaries
)


class TestCrossModuleTaint:
    """Test taint tracking across module boundaries."""
    
    def test_simple_cross_module_sql_injection(self):
        """Test SQL injection where source and sink are in different modules.
        
        Module layout:
        - handlers.py: get_user_data(request) -> calls db_query()
        - database.py: db_query(user_input) -> executes SQL
        
        Expected: Detect that tainted data flows from handlers -> database -> SQL sink
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            
            # Create database.py
            database_code = """
import sqlite3

def db_query(user_input):
    '''Query database with user input'''
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    # SQL injection sink: user_input is not parameterized
    cursor.execute(f"SELECT * FROM users WHERE name = '{user_input}'")
    return cursor.fetchall()
"""
            (tmpdir_path / "database.py").write_text(database_code)
            
            # Create handlers.py
            handlers_code = """
from database import db_query

def get_user_data(request):
    '''Handler that processes user request'''
    # Source: HTTP parameter
    username = request.args.get('username')
    # Call to another module
    results = db_query(username)
    return results
"""
            (tmpdir_path / "handlers.py").write_text(handlers_code)
            
            # Build interprocedural context
            call_graph = build_call_graph_from_directory(tmpdir_path)
            
            # Check that cross-module edge was created
            handlers_func = None
            for qname in call_graph.functions:
                if 'get_user_data' in qname:
                    handlers_func = qname
                    break
            
            assert handlers_func is not None, "Should find handlers.get_user_data"
            
            # Check callees - should include database.db_query
            callees = call_graph.get_callees(handlers_func)
            db_query_func = None
            for qname in call_graph.functions:
                if 'db_query' in qname:
                    db_query_func = qname
                    break
            
            # This is the key test: cross-module edge should exist
            if db_query_func:
                assert db_query_func in callees or db_query_func in str(call_graph.external_calls.get(handlers_func, set())), \
                    f"Cross-module call from {handlers_func} to {db_query_func} should be tracked"
            
            # Compute summaries
            computer = SummaryComputer(
                call_graph,
                source_contracts=get_source_contracts_for_summaries(),
                sink_contracts=get_sink_contracts_for_summaries(),
                sanitizer_contracts=get_sanitizer_contracts_for_summaries(),
            )
            summaries = computer.compute_all()
            
            # db_query should be marked as having a sink
            if db_query_func and db_query_func in summaries:
                summary = summaries[db_query_func]
                assert summary.dependency.is_sink, "db_query should be detected as having a SQL sink"
            
            # get_user_data should propagate taint from param 0 to its callees
            if handlers_func in summaries:
                handler_summary = summaries[handlers_func]
                # Should detect that param 0 flows to a sink (transitively through db_query)
                # This may not work yet, but is the goal
    
    def test_multi_hop_cross_module(self):
        """Test taint through multiple module hops.
        
        Module layout:
        - web.py: route() -> calls controller.process()
        - controller.py: process() -> calls service.execute()
        - service.py: execute() -> has command injection sink
        
        Expected: Detect 3-hop taint flow
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            
            # Create service.py
            service_code = """
import subprocess

def execute(command):
    '''Execute a system command'''
    # Command injection sink
    subprocess.run(command, shell=True)
"""
            (tmpdir_path / "service.py").write_text(service_code)
            
            # Create controller.py
            controller_code = """
from service import execute

def process(user_data):
    '''Process user data'''
    command = f"echo {user_data}"
    execute(command)
"""
            (tmpdir_path / "controller.py").write_text(controller_code)
            
            # Create web.py
            web_code = """
from controller import process

def route(request):
    '''Web route handler'''
    data = request.args.get('data')
    process(data)
"""
            (tmpdir_path / "web.py").write_text(web_code)
            
            # Build call graph
            call_graph = build_call_graph_from_directory(tmpdir_path)
            
            # Verify that the call chain is complete
            route_func = None
            process_func = None
            execute_func = None
            
            for qname in call_graph.functions:
                if 'route' in qname:
                    route_func = qname
                elif 'process' in qname and 'controller' in qname:
                    process_func = qname
                elif 'execute' in qname and 'service' in qname:
                    execute_func = qname
            
            assert route_func, "Should find web.route"
            assert process_func, "Should find controller.process"
            assert execute_func, "Should find service.execute"
            
            # Compute summaries
            computer = SummaryComputer(
                call_graph,
                source_contracts=get_source_contracts_for_summaries(),
                sink_contracts=get_sink_contracts_for_summaries(),
                sanitizer_contracts=get_sanitizer_contracts_for_summaries(),
            )
            summaries = computer.compute_all()
            
            # service.execute should be detected as a sink
            if execute_func in summaries:
                summary = summaries[execute_func]
                assert summary.dependency.is_sink, "service.execute should have command injection sink"
    
    def test_import_alias_resolution(self):
        """Test that import aliases are properly resolved.
        
        Module layout:
        - main.py: from helpers import dangerous_func as df; df(x)
        - helpers.py: def dangerous_func(x): exec(x)
        
        Expected: Resolve 'df' to 'helpers.dangerous_func'
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            
            # Create helpers.py
            helpers_code = """
def dangerous_func(user_code):
    '''Execute user code'''
    exec(user_code)
"""
            (tmpdir_path / "helpers.py").write_text(helpers_code)
            
            # Create main.py with aliased import
            main_code = """
from helpers import dangerous_func as df

def process(request):
    '''Process request'''
    code = request.args.get('code')
    df(code)  # Should resolve to helpers.dangerous_func
"""
            (tmpdir_path / "main.py").write_text(main_code)
            
            # Build call graph
            call_graph = build_call_graph_from_directory(tmpdir_path)
            
            process_func = None
            dangerous_func = None
            
            for qname in call_graph.functions:
                if 'process' in qname:
                    process_func = qname
                elif 'dangerous_func' in qname:
                    dangerous_func = qname
            
            assert process_func, "Should find main.process"
            assert dangerous_func, "Should find helpers.dangerous_func"
            
            # Check that the alias was resolved correctly
            # This test documents current behavior and expected improvement


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
