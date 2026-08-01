from bottle import Bottle, run, request, response, template, redirect
import sqlite3
import uuid

app = Bottle()

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

# Helper functions
def create_user(username, password):
    conn = sqlite3.connect('user_profiles.db')
    c = conn.cursor()
    user_id = str(uuid.uuid4())
    c.execute("INSERT INTO users (id, username, password, bio, theme) VALUES (?, ?, ?, ?, ?)",
              (user_id, username, password, '', 'light'))
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
    conn = sqlite3.connect('user_profiles.db')
    c = conn.cursor()
    c.execute("UPDATE users SET bio=? WHERE id=?", (bio, user_id))
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
        username = request.forms.get('username')
        password = request.forms.get('password')
        if get_user(username):
            return "Username already exists"
        create_user(username, password)
        response.set_cookie("user", username, secret='weaksecret')
        return redirect('/profile')
    return '''
        <h1>Register</h1>
        <form method="POST">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <input type="submit" value="Register">
        </form>
    '''

@app.route('/login', method=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.forms.get('username')
        password = request.forms.get('password')
        user = get_user(username)
        if user and user[2] == password:
            response.set_cookie("user", username, secret='weaksecret')
            return redirect('/profile')
        return "Invalid credentials"
    return '''
        <h1>Login</h1>
        <form method="POST">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <input type="submit" value="Login">
        </form>
    '''

@app.route('/profile', method=['GET', 'POST'])
def profile():
    username = request.get_cookie("user", secret='weaksecret')
    if not username:
        return redirect('/login')
    
    user = get_user(username)
    if not user:
        return redirect('/login')
    
    if request.method == 'POST':
        new_bio = request.forms.get('bio')
        update_bio(user[0], new_bio)
        return redirect('/profile')
    
    # Vulnerable function - injects unsanitized user input into JavaScript
    return template('''
        <h1>Profile: {{username}}</h1>
        <div id="user-bio"></div>
        <script>
            var userBio = "{{bio}}";
            document.getElementById("user-bio").innerHTML = userBio;
        </script>
        <form method="POST">
            <textarea name="bio">{{bio}}</textarea><br>
            <input type="submit" value="Update Bio">
        </form>
        <a href="/logout">Logout</a>
    ''', username=username, bio=user[3])

@app.route('/logout')
def logout():
    response.delete_cookie("user")
    return redirect('/')

if __name__ == '__main__':
    run(app, host='localhost', port=8080, debug=True)