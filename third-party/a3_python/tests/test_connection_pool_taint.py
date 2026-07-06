"""
Test connection pool taint tracking (iteration 532).

The pattern: taint flows through object composition
1. Pool created with tainted config → pool object is tainted
2. Connection from tainted pool → connection object is tainted
3. Cursor from tainted connection → cursor object is tainted
4. Data from tainted cursor → data is tainted

This is enabled by the compositional object taint tracking in
security_tracker_lattice.py handle_call_post (iteration 529-530).
"""

import pytest
from a3_python.z3model.taint_lattice import (
    TaintLabel, SourceType, SinkType
)
from a3_python.contracts.security_lattice import (
    init_security_contracts,
    apply_source_taint,
    check_sink_taint,
)
from a3_python.semantics.security_tracker_lattice import LatticeSecurityTracker


def test_connection_pool_taint_sqlite3():
    """
    Test taint propagation through sqlite3 connection pool pattern.
    
    Pattern:
        user_path = request.args.get('db')  # TAINTED
        conn = sqlite3.connect(user_path)   # conn inherits taint
        cursor = conn.cursor()              # cursor inherits taint
        cursor.execute("SELECT * FROM t")   # INJECTION!
    """
    init_security_contracts()
    tracker = LatticeSecurityTracker()
    
    # Simulate: user_path = request.args.get('db')
    user_path = object()  # mock value
    user_path_label = apply_source_taint("request.args.get", "test.py:1")
    tracker.set_label(user_path, user_path_label)
    
    assert user_path_label.has_untrusted_taint(), "user_path should be tainted"
    
    # Simulate: conn = sqlite3.connect(user_path)
    # The VM will call handle_call_post which propagates taint from args to result
    conn = object()
    conn_concrete, conn_symbolic = tracker.handle_call_post(
        "sqlite3.connect",
        None,  # func_ref (not a method call)
        [user_path],
        conn,
        "test.py:2"
    )
    
    # Connection should inherit taint from user_path
    assert conn_concrete.has_untrusted_taint(), "conn should inherit taint from tainted path"
    assert SourceType.HTTP_PARAM in conn_concrete.get_untrusted_sources()
    
    # Simulate: cursor = conn.cursor()
    cursor = object()
    cursor_concrete, cursor_symbolic = tracker.handle_call_post(
        "cursor",
        conn,  # func_ref - this is the key!
        [],
        cursor,
        "test.py:3"
    )
    
    # Cursor should inherit taint from conn
    assert cursor_concrete.has_untrusted_taint(), "cursor should inherit taint from tainted connection"
    
    # Simulate: cursor.execute(query)
    query = "SELECT * FROM users"  # not tainted
    query_val = object()
    tracker.set_label(query_val, TaintLabel.clean())
    
    # Check sink violation
    # NOTE: cursor.execute sink checks the query argument AND the cursor object
    violations = check_sink_taint(
        "cursor.execute",
        "test.py:4",
        [TaintLabel.clean()],  # query argument is clean
        receiver_label=cursor_concrete  # but cursor is tainted!
    )
    
    # This should be a violation because the cursor itself is tainted
    # (second-order SQL injection through tainted connection)
    assert len(violations) > 0, "Should detect SQL injection through tainted cursor"


def test_connection_pool_taint_psycopg2():
    """
    Test taint propagation through psycopg2 connection pool.
    
    Pattern:
        dsn = os.getenv('DATABASE_URL')  # TAINTED
        pool = psycopg2.pool.SimpleConnectionPool(dsn)  # pool inherits taint
        conn = pool.getconn()            # conn inherits taint from pool
        cursor = conn.cursor()           # cursor inherits taint from conn
        cursor.execute(query)            # INJECTION if query or cursor tainted
    """
    init_security_contracts()
    tracker = LatticeSecurityTracker()
    
    # Simulate: dsn = os.getenv('DATABASE_URL')
    dsn = object()
    dsn_label = apply_source_taint("os.getenv", "test.py:1")
    tracker.set_label(dsn, dsn_label)
    
    assert dsn_label.has_untrusted_taint()
    
    # Simulate: pool = psycopg2.pool.SimpleConnectionPool(dsn)
    pool = object()
    pool_concrete, _ = tracker.handle_call_post(
        "psycopg2.pool.SimpleConnectionPool",
        None,
        [dsn],
        pool,
        "test.py:2"
    )
    
    assert pool_concrete.has_untrusted_taint(), "pool should inherit taint from dsn"
    
    # Simulate: conn = pool.getconn()
    conn = object()
    conn_concrete, _ = tracker.handle_call_post(
        "getconn",
        pool,  # method call on pool - this is the key!
        [],
        conn,
        "test.py:3"
    )
    
    assert conn_concrete.has_untrusted_taint(), "conn should inherit taint from pool"
    
    # Simulate: cursor = conn.cursor()
    cursor = object()
    cursor_concrete, _ = tracker.handle_call_post(
        "cursor",
        conn,
        [],
        cursor,
        "test.py:4"
    )
    
    assert cursor_concrete.has_untrusted_taint(), "cursor should inherit taint from conn"
    
    # Simulate: cursor.execute("SELECT ...")
    violations = check_sink_taint(
        "cursor.execute", 
        "test.py:5",
        [TaintLabel.clean()],  # query is clean
        receiver_label=cursor_concrete  # cursor is tainted
    )
    assert len(violations) > 0, "Should detect SQL injection through tainted cursor from pool"


def test_connection_pool_taint_sqlalchemy():
    """
    Test taint propagation through SQLAlchemy engine/pool.
    
    Pattern:
        db_url = request.form.get('database')  # TAINTED
        engine = create_engine(db_url)         # engine inherits taint
        conn = engine.connect()                # conn inherits taint from engine
        result = conn.execute(query)           # INJECTION
    """
    init_security_contracts()
    tracker = LatticeSecurityTracker()
    
    # Simulate: db_url = request.form.get('database')
    db_url = object()
    db_url_label = apply_source_taint("request.form.get", "test.py:1")
    tracker.set_label(db_url, db_url_label)
    
    # Simulate: engine = create_engine(db_url)
    engine = object()
    engine_concrete, _ = tracker.handle_call_post(
        "sqlalchemy.create_engine",
        None,
        [db_url],
        engine,
        "test.py:2"
    )
    
    assert engine_concrete.has_untrusted_taint()
    
    # Simulate: conn = engine.connect()
    conn = object()
    conn_concrete, _ = tracker.handle_call_post(
        "connect",
        engine,  # method on engine
        [],
        conn,
        "test.py:3"
    )
    
    assert conn_concrete.has_untrusted_taint()
    
    # Simulate: conn.execute(query)
    violations = check_sink_taint(
        "connection.execute",
        "test.py:4", 
        [TaintLabel.clean()],  # query is clean
        receiver_label=conn_concrete  # connection is tainted
    )
    assert len(violations) > 0


def test_connection_pool_no_taint_clean():
    """
    Test that clean (non-tainted) connection pools don't trigger false positives.
    
    Pattern:
        conn = sqlite3.connect('/hardcoded/path.db')  # NOT tainted
        cursor = conn.cursor()                        # NOT tainted
        cursor.execute(query)                         # OK if query is clean
    """
    init_security_contracts()
    tracker = LatticeSecurityTracker()
    
    # Simulate: path = '/hardcoded/path.db' (not tainted)
    path = object()
    tracker.set_label(path, TaintLabel.clean())
    
    # Simulate: conn = sqlite3.connect(path)
    conn = object()
    conn_concrete, _ = tracker.handle_call_post(
        "sqlite3.connect",
        None,
        [path],
        conn,
        "test.py:1"
    )
    
    assert not conn_concrete.has_untrusted_taint()
    
    # Simulate: cursor = conn.cursor()
    cursor = object()
    cursor_concrete, _ = tracker.handle_call_post(
        "cursor",
        conn,
        [],
        cursor,
        "test.py:2"
    )
    
    assert not cursor_concrete.has_untrusted_taint()
    
    # Simulate: cursor.execute with clean query
    query = object()
    tracker.set_label(query, TaintLabel.clean())
    
    violations = check_sink_taint(
        "cursor.execute",
        "test.py:3",
        [TaintLabel.clean()],  # query is clean
        receiver_label=cursor_concrete  # cursor is clean too
    )
    assert len(violations) == 0, "Clean connection + clean query should not trigger"


def test_redis_connection_pool_taint():
    """
    Test taint propagation through Redis connection pool.
    
    Pattern:
        redis_url = os.getenv('REDIS_URL')  # TAINTED
        pool = redis.ConnectionPool.from_url(redis_url)
        client = redis.Redis(connection_pool=pool)
        client.set(key, value)  # INJECTION
    """
    init_security_contracts()
    tracker = LatticeSecurityTracker()
    
    # Simulate: redis_url = os.getenv('REDIS_URL')
    redis_url = object()
    redis_url_label = apply_source_taint("os.getenv", "test.py:1")
    tracker.set_label(redis_url, redis_url_label)
    
    # Simulate: pool = redis.ConnectionPool.from_url(redis_url)
    pool = object()
    pool_concrete, _ = tracker.handle_call_post(
        "redis.ConnectionPool.from_url",
        None,
        [redis_url],
        pool,
        "test.py:2"
    )
    
    assert pool_concrete.has_untrusted_taint()
    
    # Simulate: client = redis.Redis(connection_pool=pool)
    client = object()
    client_concrete, _ = tracker.handle_call_post(
        "redis.Redis",
        None,
        [pool],  # pool passed as kwarg
        client,
        "test.py:3"
    )
    
    assert client_concrete.has_untrusted_taint()


def test_mongodb_client_taint():
    """
    Test taint propagation through MongoDB client.
    
    Pattern:
        mongo_uri = request.args.get('mongo')  # TAINTED
        client = pymongo.MongoClient(mongo_uri)
        db = client.get_database('test')
        collection = db.get_collection('users')
        collection.find({...})  # INJECTION
    """
    init_security_contracts()
    tracker = LatticeSecurityTracker()
    
    # Simulate: mongo_uri = request.args.get('mongo')
    mongo_uri = object()
    uri_label = apply_source_taint("request.args.get", "test.py:1")
    tracker.set_label(mongo_uri, uri_label)
    
    # Simulate: client = pymongo.MongoClient(mongo_uri)
    client = object()
    client_concrete, _ = tracker.handle_call_post(
        "pymongo.MongoClient",
        None,
        [mongo_uri],
        client,
        "test.py:2"
    )
    
    assert client_concrete.has_untrusted_taint()
    
    # Simulate: db = client.get_database('test')
    db = object()
    db_concrete, _ = tracker.handle_call_post(
        "get_database",
        client,  # method on client
        [],
        db,
        "test.py:3"
    )
    
    assert db_concrete.has_untrusted_taint()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
