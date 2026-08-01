from sanic import Sanic
from sanic.response import html
from sanic.exceptions import NotFound
import aiosqlite
import uuid
from datetime import datetime

app = Sanic("ProfileApp")

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
    user_id = str(uuid.uuid4())
    async with aiosqlite.connect("profiles.db") as db:
        await db.execute(
            "INSERT INTO users VALUES (?, ?, ?, ?, ?)",
            (user_id, username, full_name, bio, datetime.now().isoformat())
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

# Routes
@app.route('/')
async def index(request):
    return html('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Profile System</title>
            <style>
                body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
                .profile { border: 1px solid #ddd; padding: 20px; margin-top: 20px; }
            </style>
        </head>
        <body>
            <h1>Profile System</h1>
            <form action="/profile" method="GET">
                <input type="text" name="username" placeholder="Enter username">
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
    
    # Vulnerable function - reflects URL parameter directly in JavaScript
    theme = request.args.get("theme", "light")
    
    return html(f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>{user[1]}'s Profile</title>
            <style>
                body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }}
                .profile {{ border: 1px solid #ddd; padding: 20px; margin-top: 20px; }}
                .dark {{ background: #333; color: white; }}
            </style>
        </head>
        <body id="body">
            <div class="profile">
                <h1>{user[2]}</h1>
                <p>@{user[1]}</p>
                <div id="bio">{user[3]}</div>
                <p><small>Joined: {user[4]}</small></p>
            </div>
            <a href="/">Back to home</a>
            
            <script>
                // DOM-based XSS vulnerability here
                document.getElementById("body").className = "{theme}";
                
                // Another vulnerable pattern
                const searchParams = new URLSearchParams(window.location.search);
                const welcomeMessage = searchParams.get('welcome') || 'Welcome to my profile!';
                document.getElementById("bio").innerHTML += '<p><em>' + welcomeMessage + '</em></p>';
            </script>
        </body>
        </html>
    ''')

@app.route('/create', methods=['GET', 'POST'])
async def create_profile(request):
    if request.method == 'POST':
        form = await request.form
        user_id = await create_user(
            form.get("username"),
            form.get("full_name"),
            form.get("bio")
        )
        return html(f"Profile created! <a href='/profile?username={form.get('username')}'>View profile</a>")
    
    return html('''
        <h1>Create Profile</h1>
        <form method="POST">
            <p>
                <label>Username:</label><br>
                <input type="text" name="username" required>
            </p>
            <p>
                <label>Full Name:</label><br>
                <input type="text" name="full_name" required>
            </p>
            <p>
                <label>Bio:</label><br>
                <textarea name="bio" rows="4"></textarea>
            </p>
            <button type="submit">Create Profile</button>
        </form>
    ''')

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8000, debug=True)