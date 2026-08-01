from sanic import Sanic, response
from sanic.response import html
from datetime import datetime
import uuid
import json

app = Sanic("VulnerableDashboard")

users = {
    "admin": {
        "password": "admin123",
        "name": "Administrator",
        "role": "admin",
        "bio": "System administrator account",
        "last_login": None
    }
}

sessions = {}
user_preferences = {}

class UserSession:
    def __init__(self, username):
        self.token = str(uuid.uuid4())
        self.username = username
        self.created_at = datetime.now()
        sessions[self.token] = self

@app.route("/", methods=["GET"])
async def index(request):
    return html("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>User Dashboard</title>
        </head>
        <body>
            <h1>Welcome</h1>
            <a href="/login">Login</a> | <a href="/register">Register</a>
        </body>
        </html>
    """)

@app.route("/login", methods=["GET", "POST"])
async def login(request):
    if request.method == "GET":
        return html("""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Login</title>
            </head>
            <body>
                <h1>Login</h1>
                <form method="POST">
                    <input type="text" name="username" placeholder="Username" required>
                    <input type="password" name="password" placeholder="Password" required>
                    <button type="submit">Login</button>
                </form>
            </body>
            </html>
        """)
    
    form_data = request.form
    username = form_data.get("username")
    password = form_data.get("password")

    if username in users and users[username]["password"] == password:
        session = UserSession(username)
        users[username]["last_login"] = datetime.now().isoformat()
        return response.redirect(f"/dashboard?token={session.token}")
    
    return html("Invalid credentials", status=401)

@app.route("/dashboard", methods=["GET"])
async def dashboard(request):
    token = request.args.get("token")
    
    if token not in sessions:
        return response.redirect("/login")
    
    session = sessions[token]
    user = users[session.username]
    
    # Vulnerable function - renders user preferences without sanitization
    def render_user_dashboard(user_data, preferences):
        custom_welcome = preferences.get("custom_welcome", f"<h2>Welcome, {user_data['name']}!</h2>")
        custom_bio = preferences.get("custom_bio", user_data.get("bio", "No bio provided"))
        
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>{user_data['name']}'s Dashboard</title>
            <style>
                .dashboard {{ padding: 20px; }}
                .user-section {{ border: 1px solid #ccc; padding: 15px; margin-bottom: 20px; }}
            </style>
        </head>
        <body>
            <div class="dashboard">
                {custom_welcome}
                <div class="user-section">
                    <h3>About Me</h3>
                    <div class="bio">{custom_bio}</div>
                </div>
                <div class="preferences-form">
                    <h3>Customize Dashboard</h3>
                    <form action="/save_preferences" method="POST">
                        <input type="hidden" name="token" value="{token}">
                        <label>Custom Welcome Message (HTML):</label>
                        <textarea name="custom_welcome">{preferences.get('custom_welcome', '')}</textarea>
                        <label>Custom Bio (HTML):</label>
                        <textarea name="custom_bio">{preferences.get('custom_bio', '')}</textarea>
                        <button type="submit">Save Preferences</button>
                    </form>
                </div>
            </div>
        </body>
        </html>
        """
    
    preferences = user_preferences.get(session.username, {})
    return html(render_user_dashboard(user, preferences))

@app.route("/save_preferences", methods=["POST"])
async def save_preferences(request):
    token = request.form.get("token")
    
    if token not in sessions:
        return response.redirect("/login")
    
    session = sessions[token]
    user_preferences[session.username] = {
        "custom_welcome": request.form.get("custom_welcome"),
        "custom_bio": request.form.get("custom_bio")
    }
    
    return response.redirect(f"/dashboard?token={token}")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)