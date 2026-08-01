from sanic import Sanic
from sanic.response import html
from sanic.exceptions import NotFound
import aiosqlite
import uuid
from datetime import datetime
import html as html_escape
import json
import secrets

app = Sanic("ProfileApp")
app.config.SECRET = secrets.token_urlsafe(32)  # Secure secret key

# Database setup
async def init_db():
    async with aiosqlite.connect("profiles.db") as db:
        await db.execute('''CREATE TABLE IF NOT EXISTS users
                          (id TEXT PRIMARY KEY,
                          username TEXT UNIQUE,
                          full_name TEXT,
                          bio TEXT,
                          created_at TEXT)''')
        await db.commit()

@app.listener('before_server_start')
async def setup_db(app, loop):
    await init_db()

# Helper functions
async def create_user(username, full_name, bio):
    # Sanitize inputs before storage
    sanitized_username = html_escape.escape(username)
    sanitized_full_name = html_escape.escape(full_name)
    sanitized_bio = html_escape.escape(bio)
    
    user_id = str(uuid.uuid4())
    async with aiosqlite.connect("profiles.db") as db:
        await db.execute(
            "INSERT INTO users VALUES (?, ?, ?, ?, ?)",
            (user_id, sanitized_username, sanitized_full_name, sanitized_bio, datetime.now().isoformat())
        )
        await db.commit()
    return user_id

async def get_user(username):
    async with aiosqlite.connect("profiles.db") as db:
        cursor = await db.execute(
            "SELECT * FROM users WHERE username = ?", 
            (username,)
        )
        return await cursor.fetchone()

# Security middleware
@app.middleware("response")
async def add_security_headers(request, response):
    response.headers.update({
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Content-Security-Policy": "default-src 'self'; script-src 'self'",
    })
    return response

# Routes
@app.route('/')
async def index(request):
    return html('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Profile System</title>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
                .profile { border: 1px solid #ddd; padding: 20px; margin-top: 20px; }
            </style>
        </head>
        <body>
            <h1>Profile System</h1>
            <form action="/profile" method="GET">
                <input type="text" name="username" placeholder="Enter username" required>
                <button type="submit">View Profile</button>
            </form>
            <p>Try usernames: alice, bob, charlie</p>
        </body>
        </html>
    ''')

@app.route('/profile')
async def view_profile(request):
    username = request.args.get("username", "")
    if not username:
        return html("Username parameter is required")
    
    user = await get_user(username)
    if not user:
        return html("User not found")
    
    # Safely handle theme parameter
    theme = request.args.get("theme", "light")
    if theme not in ["light", "dark"]:
        theme = "light"
    
    # Safely pass data to JavaScript
    safe_user_data = {
        "full_name": user[2],
        "username": user[1],
        "bio": user[3],
        "joined": user[4],
        "theme": theme
    }
    
    return html(f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>{html_escape.escape(user[1])}'s Profile</title>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }}
                .profile {{ border: 1px solid #ddd; padding: 20px; margin-top: 20px; }}
                .dark {{ background: #333; color: white; }}
            </style>
        </head>
        <body id="body">
            <div class="profile">
                <h1>{html_escape.escape(user[2])}</h1>
                <p>@{html_escape.escape(user[1])}</p>
                <div id="bio">{html_escape.escape(user[3])}</div>
                <p><small>Joined: {html_escape.escape(user[4])}</small></p>
            </div>
            <a href="/">Back to home</a>
            
            <script>
                // Safely apply theme
                const userData = {json.dumps(safe_user_data)};
                document.getElementById("body").className = userData.theme;
                
                // Safe way to handle URL parameters
                const urlParams = new URLSearchParams(window.location.search);
                const welcomeMessage = urlParams.get('welcome') || 'Welcome to my profile!';
                
                // Safely add content to DOM
                const bioElement = document.getElementById("bio");
                const welcomePara = document.createElement('p');
                welcomePara.innerHTML = '<em>' + document.createTextNode(welcomeMessage).textContent + '</em>';
                bioElement.appendChild(welcomePara);
            </script>
        </body>
        </html>
    ''')

@app.route('/create', methods=['GET', 'POST'])
async def create_profile(request):
    if request.method == 'POST':
        form = await request.form
        username = form.get("username", "").strip()
        full_name = form.get("full_name", "").strip()
        bio = form.get("bio", "").strip()
        
        if not username or not full_name:
            return html("Username and full name are required")
            
        user_id = await create_user(username, full_name, bio)
        return html(f"Profile created! <a href='/profile?username={html_escape.escape(username)}'>View profile</a>")
    
    return html('''
        <h1>Create Profile</h1>
        <form method="POST">
            <p>
                <label>Username:</label><br>
                <input type="text" name="username" required maxlength="50">
            </p>
            <p>
                <label>Full Name:</label><br>
                <input type="text" name="full_name" required maxlength="100">
            </p>
            <p>
                <label>Bio:</label><br>
                <textarea name="bio" rows="4" maxlength="500"></textarea>
            </p>
            <button type="submit">Create Profile</button>
        </form>
    ''')

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8000, debug=False)  # Disable debug mode in production