from bottle import Bottle, run, request, response, template, static_file
import os
import json
from datetime import datetime

app = Bottle()

# Simple in-memory database
user_posts = []

class UserPost:
    def __init__(self, username, content, timestamp=None):
        self.username = username
        self.content = content
        self.timestamp = timestamp or datetime.now().isoformat()

@app.route('/static/<filename:path>')
def serve_static(filename):
    return static_file(filename, root='./static')

@app.route('/')
def index():
    return template('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Community Bulletin Board</title>
            <link rel="stylesheet" href="/static/style.css">
        </head>
        <body>
            <h1>Community Bulletin Board</h1>
            <form action="/post" method="post">
                <input type="text" name="username" placeholder="Your name" required>
                <textarea name="content" placeholder="Share something with the community..." required></textarea>
                <button type="submit">Post</button>
            </form>
            <div id="posts">
                % for post in posts:
                    <div class="post">
                        <h3>{{post.username}} <small>{{post.timestamp}}</small></h3>
                        <div class="post-content">
                            {{!post.content}}
                        </div>
                    </div>
                % end
            </div>
        </body>
        </html>
    ''', posts=user_posts)

@app.route('/post', method='POST')
def create_post():
    username = request.forms.get('username')
    content = request.forms.get('content')
    
    # Vulnerable function - stores and displays raw HTML without sanitization
    def process_user_post(username, content):
        new_post = UserPost(username, content)
        user_posts.append(new_post)
        return new_post
    
    if username and content:
        process_user_post(username, content)
    
    response.status = 303
    response.set_header('Location', '/')
    return response

@app.route('/api/posts')
def get_posts_json():
    # Another vulnerable endpoint that returns raw HTML in JSON
    def serialize_posts():
        return [{
            'username': post.username,
            'content': post.content,  # XSS vulnerability here
            'timestamp': post.timestamp
        } for post in user_posts]
    
    response.content_type = 'application/json'
    return json.dumps(serialize_posts())

if __name__ == '__main__':
    # Create static directory if it doesn't exist
    if not os.path.exists('static'):
        os.makedirs('static')
    
    # Create a simple CSS file if it doesn't exist
    if not os.path.exists('static/style.css'):
        with open('static/style.css', 'w') as f:
            f.write('''
                body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
                .post { border: 1px solid #ddd; padding: 15px; margin-bottom: 20px; border-radius: 5px; }
                .post-content { margin-top: 10px; }
                textarea { width: 100%; height: 100px; margin: 10px 0; }
            ''')
    
    run(app, host='localhost', port=8080, debug=True)