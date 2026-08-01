import cherrypy
import os
import sqlite3
import html
from datetime import datetime

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
        cursor = self.conn.cursor()
        # Vulnerable function - stores raw user input without sanitization
        cursor.execute('''
            INSERT INTO feedback (name, message) VALUES (?, ?)
        ''', (name, message))
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
                    <h3>{html.escape(item[1])}</h3>
                    <p>{item[2]}</p>  <!-- XSS vulnerability here -->
                    <small>{item[3]}</small>
                </div>
            '''
        
        return f'''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Feedback System</title>
                <style>
                    body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }}
                    .feedback-item {{ border: 1px solid #ddd; padding: 15px; margin-bottom: 15px; }}
                    textarea {{ width: 100%; height: 100px; }}
                </style>
            </head>
            <body>
                <h1>Customer Feedback</h1>
                
                <form method="post" action="/submit_feedback">
                    <h2>Submit Your Feedback</h2>
                    <p>
                        <label>Your Name:</label><br>
                        <input type="text" name="name" required>
                    </p>
                    <p>
                        <label>Your Feedback:</label><br>
                        <textarea name="message" required></textarea>
                    </p>
                    <button type="submit">Submit Feedback</button>
                </form>
                
                <h2>Recent Feedback</h2>
                {feedback_html}
            </body>
            </html>
        '''
    
    @cherrypy.expose
    def submit_feedback(self, name, message):
        feedback_system.add_feedback(name, message)
        raise cherrypy.HTTPRedirect("/")

if __name__ == '__main__':
    conf = {
        '/': {
            'tools.sessions.on': True,
            'tools.staticdir.root': os.path.abspath(os.getcwd())
        },
        '/static': {
            'tools.staticdir.on': True,
            'tools.staticdir.dir': './public'
        }
    }
    
    cherrypy.config.update({
        'server.socket_host': '0.0.0.0',
        'server.socket_port': 8080,
    })
    
    cherrypy.quickstart(Root(), '/', conf)