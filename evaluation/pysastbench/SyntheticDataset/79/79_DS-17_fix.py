import cherrypy
import os
import sqlite3
import html
from datetime import datetime
import secrets

class FeedbackSystem:
    def __init__(self):
        self.conn = sqlite3.connect('feedback.db')
        self.create_table()
        
    def create_table(self):
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                message TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        self.conn.commit()
        
    def add_feedback(self, name, message):
        # Sanitize inputs before storage
        sanitized_name = html.escape(name)
        sanitized_message = html.escape(message)
        
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO feedback (name, message) VALUES (?, ?)
        ''', (sanitized_name, sanitized_message))
        self.conn.commit()
        return cursor.lastrowid
        
    def get_all_feedback(self):
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM feedback ORDER BY timestamp DESC')
        return cursor.fetchall()

feedback_system = FeedbackSystem()

class Root:
    @cherrypy.expose
    def index(self):
        feedback_list = feedback_system.get_all_feedback()
        feedback_html = ""
        
        for item in feedback_list:
            feedback_html += f'''
                <div class="feedback-item">
                    <h3>{item[1]}</h3>  <!-- Already escaped in storage -->
                    <p>{item[2]}</p>     <!-- Already escaped in storage -->
                    <small>{item[3]}</small>
                </div>
            '''
        
        return f'''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Feedback System</title>
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <style>
                    body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }}
                    .feedback-item {{ border: 1px solid #ddd; padding: 15px; margin-bottom: 15px; }}
                    textarea {{ width: 100%; height: 100px; }}
                </style>
            </head>
            <body>
                <h1>Customer Feedback</h1>
                
                <form method="post" action="/submit_feedback">
                    <input type="hidden" name="_csrf_token" value="{self.get_csrf_token()}">
                    <h2>Submit Your Feedback</h2>
                    <p>
                        <label>Your Name:</label><br>
                        <input type="text" name="name" required maxlength="100">
                    </p>
                    <p>
                        <label>Your Feedback:</label><br>
                        <textarea name="message" required maxlength="2000"></textarea>
                    </p>
                    <button type="submit">Submit Feedback</button>
                </form>
                
                <h2>Recent Feedback</h2>
                {feedback_html}
            </body>
            </html>
        '''
    
    def get_csrf_token(self):
        if not cherrypy.session.get('_csrf_token'):
            cherrypy.session['_csrf_token'] = secrets.token_urlsafe(32)
        return cherrypy.session['_csrf_token']
    
    @cherrypy.expose
    def submit_feedback(self, name, message, _csrf_token=None):
        # Verify CSRF token
        if not _csrf_token or _csrf_token != cherrypy.session.get('_csrf_token'):
            raise cherrypy.HTTPError(403, "Invalid CSRF token")
            
        # Basic input validation
        if not name or not message:
            raise cherrypy.HTTPError(400, "Name and message are required")
            
        if len(name) > 100 or len(message) > 2000:
            raise cherrypy.HTTPError(400, "Input too long")
            
        feedback_system.add_feedback(name, message)
        raise cherrypy.HTTPRedirect("/")

def secureheaders():
    headers = cherrypy.response.headers
    headers['X-Frame-Options'] = 'DENY'
    headers['X-XSS-Protection'] = '1; mode=block'
    headers['X-Content-Type-Options'] = 'nosniff'
    headers['Content-Security-Policy'] = "default-src 'self'"

if __name__ == '__main__':
    conf = {
        '/': {
            'tools.sessions.on': True,
            'tools.staticdir.root': os.path.abspath(os.getcwd()),
            'tools.secureheaders.on': True,
            'tools.sessions.secure': True,
            'tools.sessions.httponly': True,
            'tools.sessions.timeout': 60,  # 1 hour timeout
        },
        '/static': {
            'tools.staticdir.on': True,
            'tools.staticdir.dir': './public'
        }
    }
    
    # Generate secure secret for session
    cherrypy.config.update({
        'server.socket_host': '0.0.0.0',
        'server.socket_port': 8080,
        'tools.sessions.storage_type': 'file',
        'tools.sessions.storage_path': './sessions',
        'tools.sessions.secret': secrets.token_urlsafe(64),
        'tools.secureheaders.on': True,
    })
    
    # Add secure headers hook
    cherrypy.tools.secureheaders = cherrypy.Tool('before_finalize', secureheaders)
    
    cherrypy.quickstart(Root(), '/', conf)