import tornado.ioloop
import tornado.web
import tornado.template
import os
import json
import uuid
from datetime import datetime

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

class MainHandler(BaseHandler):
    def get(self):
        if not self.current_user:
            self.redirect("/login")
            return
        self.render("main.html", user=self.current_user.decode())

class LoginHandler(BaseHandler):
    def get(self):
        self.render("login.html")
        
    def post(self):
        username = self.get_body_argument("username")
        self.set_secure_cookie("user", username)
        self.redirect("/")

class NotificationHandler(BaseHandler):
    def post(self):
        if not self.current_user:
            self.set_status(403)
            return
            
        user_id = self.current_user.decode()
        message = self.get_body_argument("message")
        
        # Vulnerable function - stores raw user input without sanitization
        note_id = notification_system.add_notification(user_id, message)
        
        self.write(json.dumps({"status": "success", "id": note_id}))

class GetNotificationsHandler(BaseHandler):
    def get(self):
        if not self.current_user:
            self.set_status(403)
            return
            
        user_id = self.current_user.decode()
        notes = notification_system.get_notifications(user_id)
        self.write(json.dumps(notes))

def make_app():
    # Create template directory
    if not os.path.exists("templates"):
        os.makedirs("templates")
    
    # Create templates
    with open("templates/login.html", "w") as f:
        f.write('''<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body>
    <form method="post">
        <input type="text" name="username" placeholder="Username">
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
        <textarea id="message" placeholder="Notification message"></textarea>
        <button onclick="sendNotification()">Send</button>
    </div>
    
    <div id="notifications"></div>
    
    <script>
        function sendNotification() {
            const message = $('#message').val();
            $.post('/notify', {message: message}, function(data) {
                loadNotifications();
            });
        }
        
        function loadNotifications() {
            $.get('/get_notifications', function(data) {
                const notes = JSON.parse(data);
                let html = '<h2>Your Notifications</h2><ul>';
                notes.forEach(note => {
                    // DOM-based XSS vulnerability here
                    html += `<li>${note.message} <small>${note.timestamp}</small></li>`;
                });
                html += '</ul>';
                $('#notifications').html(html);
            });
        }
        
        // Load notifications on page load
        $(document).ready(loadNotifications);
    </script>
</body>
</html>''')
    
    return tornado.web.Application([
        (r"/", MainHandler),
        (r"/login", LoginHandler),
        (r"/notify", NotificationHandler),
        (r"/get_notifications", GetNotificationsHandler),
    ], cookie_secret="__TODO:_GENERATE_YOUR_OWN_RANDOM_VALUE_HERE__")

if __name__ == "__main__":
    app = make_app()
    app.listen(8888)
    print("Server started at http://localhost:8888")
    tornado.ioloop.IOLoop.current().start()