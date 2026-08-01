from flask import Flask, request, jsonify, render_template_string, escape
import sqlite3
import os
from werkzeug.security import safe_join

app = Flask(__name__)

DATABASE = 'users.db'

def init_db():
    if not os.path.exists(DATABASE):
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                email TEXT NOT NULL
            )
        ''')
        conn.commit()
        conn.close()

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/api/users', methods=['GET'])
def list_users():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users')
    users = cursor.fetchall()
    conn.close()
    return jsonify([dict(user) for user in users])

@app.route('/api/users', methods=['POST'])
def add_user():
    data = request.get_json()
    if not data or 'username' not in data or 'email' not in data:
        return jsonify({'error': 'Missing username or email'}), 400
    
    # Basic input validation
    username = str(data['username'])[:50]  # Limit length
    email = str(data['email'])[:100]       # Limit length
    
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            'INSERT INTO users (username, email) VALUES (?, ?)',
            (username, email)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username or email already exists'}), 400
    finally:
        conn.close()
    return jsonify({'message': 'User added successfully'}), 201

@app.route('/user/profile/<username>', methods=['GET'])
def user_profile(username):
    # Validate username to prevent path traversal
    if not username.isalnum():  # Only allow alphanumeric usernames
        return jsonify({'error': 'Invalid username'}), 400
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Safe template rendering with escaped values
    template = """
    <html>
    <head><title>Profile: {{ username }}</title></head>
    <body>
        <h1>User Profile</h1>
        <p>Username: {{ username }}</p>
        <p>Email: {{ email }}</p>
        <div>Last Login: {{ last_login }}</div>
    </body>
    </html>
    """
    return render_template_string(
        template,
        username=escape(user['username']),
        email=escape(user['email']),
        last_login=escape(request.args.get('last_login', 'Never'))
    )

# Removed the vulnerable admin_actions endpoint entirely
# Admin functionality should be implemented with proper authentication
# and without dynamic code execution

if __name__ == '__main__':
    init_db()
    app.run(debug=False)  # Disable debug mode in production