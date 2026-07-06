"""
Test database cursor taint tracking (Iteration 529).

Verifies that cursors created from tainted connections properly
propagate taint to query results.
"""

import pytest
from a3_python.z3model.taint_lattice import (
    TaintLabel, SourceType, SinkType
)
from a3_python.semantics.security_tracker_lattice import (
    LatticeSecurityTracker
)


def test_cursor_from_tainted_connection_is_tainted():
    """
    Test: cursor = conn.cursor() where conn is tainted
    Expected: cursor inherits taint from conn
    """
    tracker = LatticeSecurityTracker()
    
    # Simulate: conn_str = os.environ.get('DB_URL')
    conn_str = "tainted_connection_string"
    conn_str_label = TaintLabel.from_untrusted_source(SourceType.ENVIRONMENT)
    tracker.set_label(conn_str, conn_str_label)
    
    # Simulate: conn = sqlite3.connect(conn_str)
    # The connect() function should propagate taint from argument to result
    conn = "connection_object"
    conn_result_label, _ = tracker.handle_call_post(
        func_name="sqlite3.connect",
        func_ref=None,
        args=[conn_str],
        result=conn,
        location="test:10"
    )
    
    # Verify: conn is tainted from conn_str
    assert conn_result_label.has_untrusted_taint(), \
        "Connection should inherit taint from connection string"
    assert conn_result_label.tau == conn_str_label.tau, \
        "Connection should have same τ bits as connection string"
    
    # Simulate: cursor = conn.cursor()
    cursor = "cursor_object"
    cursor_result_label, _ = tracker.handle_call_post(
        func_name="connection.cursor",
        func_ref=conn,  # Crucially, the callable is the tainted conn object
        args=[],
        result=cursor,
        location="test:11"
    )
    
    # Verify: cursor is tainted from conn
    assert cursor_result_label.has_untrusted_taint(), \
        "Cursor should inherit taint from connection"
    assert cursor_result_label.tau == conn_result_label.tau, \
        "Cursor should have same τ bits as connection"


def test_fetchone_from_tainted_cursor_is_tainted():
    """
    Test: results = cursor.fetchone() where cursor is tainted
    Expected: results inherit taint from cursor AND DATABASE_RESULT source
    """
    tracker = LatticeSecurityTracker()
    
    # Create tainted cursor (simulating conn from tainted conn_str)
    cursor = "cursor_object"
    cursor_label = TaintLabel.from_untrusted_source(SourceType.ENVIRONMENT)
    tracker.set_label(cursor, cursor_label)
    
    # Simulate: results = cursor.fetchone()
    # This is BOTH a source (DATABASE_RESULT) AND should inherit from cursor
    results = "database_row"
    results_label, _ = tracker.handle_call_post(
        func_name="cursor.fetchone",
        func_ref=cursor,  # Method call on cursor
        args=[],
        result=results,
        location="test:20"
    )
    
    # Verify: results have DATABASE_RESULT taint
    assert results_label.has_untrusted_taint(), \
        "Results should be tainted (from DATABASE_RESULT source)"
    
    # Verify: results also inherit cursor's taint
    database_bit = 1 << SourceType.DATABASE_RESULT.value
    env_bit = 1 << SourceType.ENVIRONMENT.value
    assert (results_label.tau & env_bit) != 0, \
        "Results should inherit ENVIRONMENT taint from cursor"
    assert (results_label.tau & database_bit) != 0, \
        "Results should have DATABASE_RESULT taint from source"


def test_clean_connection_produces_clean_cursor():
    """
    Test: cursor from clean connection should be clean (no false positives)
    """
    tracker = LatticeSecurityTracker()
    
    # Clean connection string (hardcoded)
    conn_str = "clean.db"
    conn_str_label = TaintLabel.clean()
    tracker.set_label(conn_str, conn_str_label)
    
    # conn = sqlite3.connect(conn_str)
    conn = "connection"
    conn_label, _ = tracker.handle_call_post(
        func_name="sqlite3.connect",
        func_ref=None,
        args=[conn_str],
        result=conn,
        location="test:30"
    )
    
    # cursor = conn.cursor()
    cursor = "cursor"
    cursor_label, _ = tracker.handle_call_post(
        func_name="connection.cursor",
        func_ref=conn,
        args=[],
        result=cursor,
        location="test:31"
    )
    
    # Clean connection → clean cursor (but fetchone will add DATABASE_RESULT taint)
    assert not cursor_label.has_untrusted_taint(), \
        "Cursor from clean connection should be clean (no false positive)"


def test_end_to_end_tainted_cursor_to_sql_injection():
    """
    Test: full flow from tainted connection to SQL injection
    
    conn_str = os.environ.get('DB_URL')  # Tainted
    conn = connect(conn_str)              # Tainted
    cursor = conn.cursor()                # Tainted
    results = cursor.fetchone()           # Tainted
    query = f"SELECT * FROM {results[0]}" # Tainted
    cursor.execute(query)                 # SQL_INJECTION!
    """
    tracker = LatticeSecurityTracker()
    
    # 1. Tainted connection string from environment
    conn_str = "env_db_url"
    conn_str_label = TaintLabel.from_untrusted_source(SourceType.ENVIRONMENT)
    tracker.set_label(conn_str, conn_str_label)
    
    # 2. Connect with tainted string
    conn = "conn"
    conn_label, _ = tracker.handle_call_post(
        func_name="sqlite3.connect",
        func_ref=None,
        args=[conn_str],
        result=conn,
        location="test:40"
    )
    assert conn_label.has_untrusted_taint()
    
    # 3. Create cursor from tainted connection
    cursor = "cursor"
    cursor_label, _ = tracker.handle_call_post(
        func_name="connection.cursor",
        func_ref=conn,
        args=[],
        result=cursor,
        location="test:41"
    )
    assert cursor_label.has_untrusted_taint()
    
    # 4. Fetch results from tainted cursor
    results = "row"
    results_label, _ = tracker.handle_call_post(
        func_name="cursor.fetchone",
        func_ref=cursor,
        args=[],
        result=results,
        location="test:42"
    )
    assert results_label.has_untrusted_taint()
    
    # 5. Build query string from tainted results (simulated string formatting)
    query = "query_string"
    # Simulate string concatenation/formatting with tainted data
    tracker.set_label(query, results_label)
    
    # 6. Execute tainted query - should detect SQL_INJECTION
    violation = tracker.handle_call_pre(
        func_name="cursor.execute",
        args=[cursor, query],  # For method calls, args[0] is the receiver
        location="test:45",
        is_method_call=True
    )
    
    # Verify: SQL_INJECTION detected
    assert violation is not None, "Should detect SQL_INJECTION"
    assert violation.bug_type == "SQL_INJECTION", \
        f"Expected SQL_INJECTION, got {violation.bug_type}"


def test_cursor_from_clean_connection_with_tainted_query():
    """
    Test: Clean cursor can still execute tainted queries (normal SQL injection)
    
    This is the standard SQL injection case - the cursor itself is clean,
    but the query is tainted from user input.
    """
    tracker = LatticeSecurityTracker()
    
    # Clean connection
    conn = "clean_conn"
    tracker.set_label(conn, TaintLabel.clean())
    
    # Clean cursor
    cursor = "cursor"
    cursor_label, _ = tracker.handle_call_post(
        func_name="connection.cursor",
        func_ref=conn,
        args=[],
        result=cursor,
        location="test:50"
    )
    assert not cursor_label.has_untrusted_taint()
    
    # Tainted query from HTTP param
    query = "SELECT * FROM users WHERE id = " + "user_input"
    query_label = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM, "test:51")
    tracker.set_label(query, query_label)
    
    # Execute tainted query - should detect SQL_INJECTION
    violation = tracker.handle_call_pre(
        func_name="cursor.execute",
        args=[cursor, query],  # For method calls, args[0] is the receiver
        location="test:52",
        is_method_call=True
    )
    
    assert violation is not None, "Should detect SQL_INJECTION"
    assert violation.bug_type == "SQL_INJECTION"
