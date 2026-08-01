import tornado.ioloop
import tornado.web
import tornado.template
import os
import json
import uuid
from datetime import datetime
import html
import secrets

class NotificationSystem:
    def __init__(self):
        self.notifications = {}
        
    def add_notification(self, user_id, message):
        if user_id not in self.notifications:
            self.notifications[user_id] = []
        note_id = str(uuid.uuid4())
        self.notifications[user_id].append({
            'id': note_id,
            'message': message,
            'timestamp': datetime.now().isoformat()
        })
        return note_id
        
    def get_notifications(self, user_id):
        return self.notifications.get(user_id, [])

notification_system = NotificationSystem()

class BaseHandler(tornado.web.RequestHandler):
    def get_current_user(self):
        return self.get_secure_cookie("user")
    
    def set_default_headers(self):
        # Security headers
        self.set_header("X-Content-Type-Options", "nosniff")
        self.set_header("X-Frame-Options", "DENY")
        self.set_header("X-XSS-Protection", "1; mode=block")
        self.set_header("Content-Security-Policy", "default-src 'self'")

class MainHandler(BaseHandler):
    def get(self):
        if not self.current_user:
            self.redirect("/login")
            return
        self.render("main.html", user=html.escape(self.current_user.decode()))

class LoginHandler(BaseHandler):
    def get(self):
        self.render("login.html")
        
    def post(self):
        username = self.get_body_argument("username", "").strip()
        if not username:
            self.set_status(400)
            return
            
        # Set secure cookie flags
        self.set_secure_cookie(
            "user", 
            username,
            httponly=True,
            secure=True,  # Requires HTTPS
            samesite='Lax'  # CSRF protection
        )
        self.redirect("/")

class NotificationHandler(BaseHandler):
    def post(self):
        if not self.current_user:
            self.set_status(403)
            return
            
        user_id = self.current_user.decode()
        message = self.get_body_argument("message", "")
        
        # Sanitize message before storage
        sanitized_message = html.escape(message)
        if not sanitized_message:
            self.set_status(400)
            return
            
        note_id = notification_system.add_notification(user_id, sanitized_message)
        
        self.write(json.dumps({"status": "success", "id": note_id}))

class GetNotificationsHandler(BaseHandler):
    def get(self):
        if not self.current_user:
            self.set_status(403)
            return
            
        user_id = self.current_user.decode()
        notes = notification_system.get_notifications(user_id)
        
        # Ensure notes are safe for JSON output
        safe_notes = []
        for note in notes:
            safe_notes.append({
                'id': note['id'],
                'message': note['message'],  # Already sanitized
                'timestamp': note['timestamp']
            })
            
        self.set_header("Content-Type", "application/json")
        self.write(json.dumps(safe_notes))

def make_app():
    # Create template directory
    if not os.path.exists("templates"):
        os.makedirs("templates")
    
    # Create secure templates
    with open("templates/login.html", "w") as f:
        f.write('''<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body>
    <form method="post">
        <input type="text" name="username" placeholder="Username" required>
        <button type="submit">Login</button>
    </form>
</body>
</html>''')
    
    with open("templates/main.html", "w") as f:
        f.write('''<!DOCTYPE html>
<html>
<head>
    <title>Notification System</title>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
</head>
<body>
    <h1>Welcome, {{ user }}</h1>
    
    <div>
        <h2>Send Notification</h2>
        <textarea id="message" placeholder="Notification message" required></textarea>
        <button onclick="sendNotification()">Send</button>
    </div>
    
    <div id="notifications"></div>
    
    <script>
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        function sendNotification() {
            const message = $('#message').val();
            if (!message) return;
            
            $.post('/notify', {message: message}, function(data) {
                $('#message').val('');
                loadNotifications();
            });
        }
        
        function loadNotifications() {
            $.get('/get_notifications', function(data) {
                try {
                    const notes = JSON.parse(data);
                    let html = '<h2>Your Notifications</h2><ul>';
                    notes.forEach(note => {
                        // Fixed: Use textContent or proper escaping
                        html += `<li>${escapeHtml(note.message)} <small>${escapeHtml(note.timestamp)}</small></li>`;
                    });
                    html += '</ul>';
                    $('#notifications').html(html);
                } catch (e) {
                    console.error('Error loading notifications:', e);
                }
            });
        }
        
        // Load notifications on page load
        $(document).ready(loadNotifications);
    </script>
</body>
</html>''')
    
    # Generate secure cookie secret
    cookie_secret = secrets.token_urlsafe(64)
    
    return tornado.web.Application([
        (r"/", MainHandler),
        (r"/login", LoginHandler),
        (r"/notify", NotificationHandler),
        (r"/get_notifications", GetNotificationsHandler),
    ], 
    cookie_secret=cookie_secret,
    xsrf_cookies=True)  # Enable CSRF protection

if __name__ == "__main__":
    app = make_app()
    app.listen(8888)
    print("Server started at http://localhost:8888")
    tornado.ioloop.IOLoop.current().start()