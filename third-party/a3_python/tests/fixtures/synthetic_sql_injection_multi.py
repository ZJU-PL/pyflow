# Synthetic SQL injection tests - multiple patterns
import sqlite3

def sql_bug_1(user_input):
    """Direct concatenation - SHOULD FIND BUG"""
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name = '" + user_input + "'"
    cursor.execute(query)
    return cursor.fetchall()

def sql_bug_2(user_input):
    """Format string - SHOULD FIND BUG"""
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    cursor.execute(query)
    return cursor.fetchall()

def sql_safe_1(user_input):
    """Parameterized query - SHOULD BE SAFE"""
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = ?", (user_input,))
    return cursor.fetchall()

def sql_safe_2(user_input):
    """Type conversion sanitizer - SHOULD BE SAFE"""
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    user_id = int(user_input)
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchall()

def sql_bug_second_order(user_input):
    """Second-order via connection taint - SHOULD FIND BUG"""
    conn_str = 'file:' + user_input + '?mode=ro'
    conn = sqlite3.connect(conn_str)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    return cursor.fetchall()
