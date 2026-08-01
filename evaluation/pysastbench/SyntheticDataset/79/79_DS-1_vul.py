from flask import Flask, request, render_template_string, redirect, url_for

app = Flask(__name__)

# In-memory database
posts = [
    {"id": 1, "title": "First Post", "content": "This is my first post!", "comments": []},
    {"id": 2, "title": "Second Post", "content": "Another post here.", "comments": []}
]

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Blog</title>
</head>
<body>
    <h1>Blog Posts</h1>
    {% for post in posts %}
        <div style="border: 1px solid #ccc; padding: 10px; margin-bottom: 20px;">
            <h2>{{ post.title }}</h2>
            <p>{{ post.content }}</p>
            <h3>Comments</h3>
            <ul>
                {% for comment in post.comments %}
                    <li>{{ comment|safe }}</li>
                {% endfor %}
            </ul>
            <form action="/add_comment/{{ post.id }}" method="POST">
                <input type="text" name="comment" placeholder="Add comment">
                <button type="submit">Submit</button>
            </form>
        </div>
    {% endfor %}
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE, posts=posts)

@app.route('/add_comment/<int:post_id>', methods=['POST'])
def add_comment(post_id):
    comment = request.form.get('comment', '')
    
    # Vulnerable function - directly stores and displays user input without sanitization
    def store_comment(post_id, comment):
        for post in posts:
            if post['id'] == post_id:
                post['comments'].append(comment)
                return True
        return False
    
    if comment:
        store_comment(post_id, comment)
    
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)