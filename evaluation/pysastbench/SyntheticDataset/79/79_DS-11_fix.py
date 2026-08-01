from flask import Flask, request, render_template_string, redirect, url_for
import sqlite3
import html  # Import html module for escaping

app = Flask(__name__)

# Database initialization
def init_db():
    conn = sqlite3.connect('blog.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS posts
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 title TEXT NOT NULL,
                 content TEXT NOT NULL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS comments
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 post_id INTEGER NOT NULL,
                 author TEXT NOT NULL,
                 content TEXT NOT NULL,
                 FOREIGN KEY(post_id) REFERENCES posts(id))''')
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def index():
    conn = sqlite3.connect('blog.db')
    c = conn.cursor()
    c.execute("SELECT id, title FROM posts")
    posts = c.fetchall()
    conn.close()
    return render_template_string('''
        <h1>Blog Posts</h1>
        <ul>
            {% for post in posts %}
                <li><a href="/post/{{ post[0] }}">{{ post[1] }}</a></li>
            {% endfor %}
        </ul>
        <a href="/create">Create New Post</a>
    ''', posts=posts)

@app.route('/create', methods=['GET', 'POST'])
def create_post():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        conn = sqlite3.connect('blog.db')
        c = conn.cursor()
        c.execute("INSERT INTO posts (title, content) VALUES (?, ?)", (title, content))
        conn.commit()
        conn.close()
        return redirect(url_for('index'))
    return render_template_string('''
        <h1>Create New Post</h1>
        <form method="POST">
            Title: <input type="text" name="title"><br>
            Content: <textarea name="content"></textarea><br>
            <input type="submit" value="Submit">
        </form>
    ''')

@app.route('/post/<int:post_id>', methods=['GET', 'POST'])
def view_post(post_id):
    conn = sqlite3.connect('blog.db')
    c = conn.cursor()
    
    if request.method == 'POST':
        author = html.escape(request.form['author'])  # Sanitize author input
        comment = html.escape(request.form['comment'])  # Sanitize comment input
        c.execute("INSERT INTO comments (post_id, author, content) VALUES (?, ?, ?)", 
                 (post_id, author, comment))
        conn.commit()
    
    c.execute("SELECT title, content FROM posts WHERE id = ?", (post_id,))
    post = c.fetchone()
    
    c.execute("SELECT author, content FROM comments WHERE post_id = ?", (post_id,))
    comments = c.fetchall()
    conn.close()
    
    return render_template_string('''
        <h1>{{ post[0] }}</h1>
        <p>{{ post[1] }}</p>
        
        <h2>Comments</h2>
        <ul>
            {% for comment in comments %}
                <li>
                    <strong>{{ comment[0] }}:</strong>
                    <div>{{ comment[1] }}</div>  <!-- Removed | safe filter -->
                </li>
            {% endfor %}
        </ul>
        
        <h2>Add Comment</h2>
        <form method="POST">
            Name: <input type="text" name="author"><br>
            Comment: <textarea name="comment"></textarea><br>
            <input type="submit" value="Submit">
        </form>
        
        <a href="/">Back to Home</a>
    ''', post=post, comments=comments)

if __name__ == '__main__':
    app.run(debug=False)  # Turn off debug mode in production