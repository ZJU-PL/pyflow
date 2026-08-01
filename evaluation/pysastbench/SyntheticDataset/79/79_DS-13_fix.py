from bottle import Bottle, run, request, response, template, redirect, abort
import sqlite3
import uuid
import hashlib
import secrets
from html import escape

app = Bottle()

# Generate secure secret for cookie signing
COOKIE_SECRET = secrets.token_urlsafe(32)

# Database setup
def init_db():
    conn = sqlite3.connect('user_profiles.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id TEXT PRIMARY KEY,
                 username TEXT UNIQUE,
                 password TEXT,
                 bio TEXT,
                 theme TEXT)''')
    conn.commit()
    conn.close()

init_db()

# Password hashing
def hash_password(password):
    salt = secrets.token_hex(16)
    return f"{salt}:{hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()}"

def verify_password(stored_password, provided_password):
    salt, hashed = stored_password.split(':')
    new_hash = hashlib.pbkdf2_hmac('sha256', provided_password.encode(), salt.encode(), 100000).hex()
    return hashed == new_hash

# Helper functions
def create_user(username, password):
    conn = sqlite3.connect('user_profiles.db')
    c = conn.cursor()
    user_id = str(uuid.uuid4())
    hashed_pw = hash_password(password)
    c.execute("INSERT INTO users (id, username, password, bio, theme) VALUES (?, ?, ?, ?, ?)",
              (user_id, username, hashed_pw, '', 'light'))
    conn.commit()
    conn.close()
    return user_id

def get_user(username):
    conn = sqlite3.connect('user_profiles.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=?", (username,))
    user = c.fetchone()
    conn.close()
    return user

def update_bio(user_id, bio):
    # Sanitize bio before storage
    sanitized_bio = escape(bio)
    conn = sqlite3.connect('user_profiles.db')
    c = conn.cursor()
    c.execute("UPDATE users SET bio=? WHERE id=?", (sanitized_bio, user_id))
    conn.commit()
    conn.close()

# Routes
@app.route('/')
def index():
    return '''
        <h1>Welcome to MyApp</h1>
        <a href="/login">Login</a> | 
        <a href="/register">Register</a>
    '''

@app.route('/register', method=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = escape(request.forms.get('username', '').strip())
        password = request.forms.get('password', '')
        
        if not username or not password:
            return "Username and password are required"
        
        if get_user(username):
            return "Username already exists"
            
        if len(password) < 8:
            return "Password must be at least 8 characters"
            
        create_user(username, password)
        response.set_cookie("user", username, secret=COOKIE_SECRET, httponly=True, secure=True)
        return redirect('/profile')
        
    return '''
        <h1>Register</h1>
        <form method="POST">
            Username: <input type="text" name="username" required><br>
            Password: <input type="password" name="password" required minlength="8"><br>
            <input type="submit" value="Register">
        </form>
    '''

@app.route('/login', method=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = escape(request.forms.get('username', '').strip())
        password = request.forms.get('password', '')
        user = get_user(username)
        
        if user and verify_password(user[2], password):
            response.set_cookie("user", username, secret=COOKIE_SECRET, httponly=True, secure=True)
            return redirect('/profile')
        return "Invalid credentials"
        
    return '''
        <h1>Login</h1>
        <form method="POST">
            Username: <input type="text" name="username" required><br>
            Password: <input type="password" name="password" required><br>
            <input type="submit" value="Login">
        </form>
    '''

@app.route('/profile', method=['GET', 'POST'])
def profile():
    username = request.get_cookie("user", secret=COOKIE_SECRET)
    if not username:
        return redirect('/login')
    
    user = get_user(username)
    if not user:
        return redirect('/login')
    
    if request.method == 'POST':
        new_bio = request.forms.get('bio', '')
        update_bio(user[0], new_bio)
        return redirect('/profile')
    
    # Safe template rendering with escaped values
    return template('''
        <h1>Profile: {{username}}</h1>
        <div id="user-bio">{{!bio}}</div>
        <form method="POST">
            <textarea name="bio">{{bio}}</textarea><br>
            <input type="submit" value="Update Bio">
        </form>
        <a href="/logout">Logout</a>
    ''', username=escape(username), bio=user[3])

@app.route('/logout')
def logout():
    response.delete_cookie("user")
    return redirect('/')

if __name__ == '__main__':
    run(app, host='localhost', port=8080, debug=False, reloader=False)