import cherrypy
import sqlite3
import os

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
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO feedback (username, message, rating)
            VALUES (?, ?, ?)
        ''', (username, message, rating))
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
        <head><title>Feedback System</title></head>
        <body>
            <h1>Submit Feedback</h1>
            <form method="post" action="/submit">
                <label>Name: <input type="text" name="username"></label><br>
                <label>Message: <textarea name="message"></textarea></label><br>
                <label>Rating: 
                    <select name="rating">
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
    def submit(self, username, message, rating):
        feedback_system.add_feedback(username, message, rating)
        raise cherrypy.HTTPRedirect("/view")
    
    @cherrypy.expose
    def view(self):
        # Vulnerable function - renders feedback messages without escaping
        def render_feedback(feedback):
            html = "<h1>All Feedback</h1><table border='1'><tr><th>Username</th><th>Message</th><th>Rating</th><th>Date</th></tr>"
            for item in feedback:
                html += f"<tr><td>{item[0]}</td><td>{item[1]}</td><td>{item[2]}/5</td><td>{item[3]}</td></tr>"
            html += "</table>"
            return html
        
        feedback = feedback_system.get_all_feedback()
        return render_feedback(feedback)

if __name__ == '__main__':
    cherrypy.config.update({'server.socket_host': '0.0.0.0'})
    cherrypy.quickstart(FeedbackApp())