import cherrypy
import sqlite3
import os
import html
from datetime import datetime

DB_NAME = 'feedback.db'

class FeedbackSystem:
    def __init__(self):
        self.setup_database()
    
    def setup_database(self):
        if not os.path.exists(DB_NAME):
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE feedback (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT,
                    message TEXT,
                    rating INTEGER,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            conn.commit()
            conn.close()
    
    def add_feedback(self, username, message, rating):
        # Validate rating is between 1 and 5
        try:
            rating = int(rating)
            if rating < 1 or rating > 5:
                raise ValueError("Rating must be between 1 and 5")
        except ValueError:
            raise ValueError("Invalid rating value")

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO feedback (username, message, rating)
            VALUES (?, ?, ?)
        ''', (html.escape(username), html.escape(message), rating))
        conn.commit()
        conn.close()
    
    def get_all_feedback(self):
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute('SELECT username, message, rating, timestamp FROM feedback ORDER BY timestamp DESC')
        feedback = cursor.fetchall()
        conn.close()
        return feedback

feedback_system = FeedbackSystem()

class FeedbackApp:
    @cherrypy.expose
    def index(self):
        return '''
        <html>
        <head>
            <title>Feedback System</title>
            <style>
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
            </style>
        </head>
        <body>
            <h1>Submit Feedback</h1>
            <form method="post" action="/submit">
                <label>Name: <input type="text" name="username" required></label><br>
                <label>Message: <textarea name="message" required></textarea></label><br>
                <label>Rating: 
                    <select name="rating" required>
                        <option value="5">5 - Excellent</option>
                        <option value="4">4 - Good</option>
                        <option value="3">3 - Average</option>
                        <option value="2">2 - Poor</option>
                        <option value="1">1 - Terrible</option>
                    </select>
                </label><br>
                <button type="submit">Submit</button>
            </form>
            <p><a href="/view">View all feedback</a></p>
        </body>
        </html>
        '''
    
    @cherrypy.expose
    def submit(self, username=None, message=None, rating=None):
        if not all([username, message, rating]):
            raise cherrypy.HTTPError(400, "All fields are required")
        
        try:
            feedback_system.add_feedback(username, message, rating)
        except ValueError as e:
            raise cherrypy.HTTPError(400, str(e))
            
        raise cherrypy.HTTPRedirect("/view")
    
    @cherrypy.expose
    def view(self):
        feedback = feedback_system.get_all_feedback()
        
        # Build safe HTML output
        html_output = """
        <html>
        <head>
            <title>Feedback Results</title>
            <style>
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
            </style>
        </head>
        <body>
            <h1>All Feedback</h1>
            <table>
                <tr><th>Username</th><th>Message</th><th>Rating</th><th>Date</th></tr>
        """
        
        for item in feedback:
            html_output += f"""
                <tr>
                    <td>{html.escape(item[0])}</td>
                    <td>{html.escape(item[1])}</td>
                    <td>{html.escape(str(item[2]))}/5</td>
                    <td>{html.escape(item[3])}</td>
                </tr>
            """
        
        html_output += """
            </table>
            <p><a href="/">Submit more feedback</a></p>
        </body>
        </html>
        """
        
        return html_output

if __name__ == '__main__':
    cherrypy.config.update({
        'server.socket_host': '0.0.0.0',
        'tools.encode.on': True,
        'tools.encode.encoding': 'utf-8',
        'tools.decode.on': True
    })
    cherrypy.quickstart(FeedbackApp())