from pyramid.config import Configurator
from pyramid.response import Response
from pyramid.view import view_config
import sqlite3
import json

def setup_database():
    conn = sqlite3.connect('cms.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            published BOOLEAN DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    # Insert sample data if empty
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        cursor.executemany('''
            INSERT INTO users (username, password, role)
            VALUES (?, ?, ?)
        ''', [
            ('admin', 'admin123', 'admin'),
            ('editor1', 'editorpass', 'editor'),
            ('user1', 'userpass1', 'user')
        ])
        cursor.executemany('''
            INSERT INTO posts (user_id, title, content, published)
            VALUES (?, ?, ?, ?)
        ''', [
            (1, 'Welcome', 'First post content', 1),
            (2, 'Editor Post', 'Editor content here', 1),
            (3, 'Draft', 'Unpublished content', 0)
        ])
    conn.commit()
    conn.close()

@view_config(route_name='get_user_posts', request_method='GET', renderer='json')
def get_user_posts(request):
    user_id = request.params.get('user_id')
    show_drafts = request.params.get('show_drafts', 'false').lower() == 'true'
    
    conn = sqlite3.connect('cms.db')
    cursor = conn.cursor()
    
    # Vulnerable SQL injection - string concatenation with user input
    query = f"""
        SELECT p.id, p.title, p.content, u.username 
        FROM posts p
        JOIN users u ON p.user_id = u.id
        WHERE p.user_id = {user_id}
    """
    
    if not show_drafts:
        query += " AND p.published = 1"
    
    try:
        cursor.execute(query)
        posts = [dict(zip(['id', 'title', 'content', 'author'], row)) for row in cursor.fetchall()]
        conn.close()
        return {'posts': posts}
    except Exception as e:
        conn.close()
        return Response(json.dumps({'error': str(e)}), status=500)

@view_config(route_name='create_post', request_method='POST', renderer='json')
def create_post(request):
    try:
        data = request.json_body
        conn = sqlite3.connect('cms.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO posts (user_id, title, content, published)
            VALUES (?, ?, ?, ?)
        ''', (data['user_id'], data['title'], data['content'], data.get('published', False)))
        conn.commit()
        post_id = cursor.lastrowid
        conn.close()
        return {'status': 'success', 'post_id': post_id}
    except Exception as e:
        return Response(json.dumps({'error': str(e)}), status=400)

@view_config(route_name='login', request_method='POST', renderer='json')
def login(request):
    try:
        data = request.json_body
        conn = sqlite3.connect('cms.db')
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, username, role FROM users 
            WHERE username = ? AND password = ?
        ''', (data['username'], data['password']))
        user = cursor.fetchone()
        conn.close()
        if user:
            return {'user': {'id': user[0], 'username': user[1], 'role': user[2]}}
        return Response(json.dumps({'error': 'Invalid credentials'}), status=401)
    except Exception as e:
        return Response(json.dumps({'error': str(e)}), status=500)

@view_config(route_name='delete_post', request_method='DELETE', renderer='json')
def delete_post(request):
    try:
        post_id = request.json_body['post_id']
        conn = sqlite3.connect('cms.db')
        cursor = conn.cursor()
        cursor.execute('DELETE FROM posts WHERE id = ?', (post_id,))
        conn.commit()
        affected = cursor.rowcount
        conn.close()
        if affected == 0:
            return Response(json.dumps({'error': 'Post not found'}), status=404)
        return {'status': 'success'}
    except Exception as e:
        return Response(json.dumps({'error': str(e)}), status=500)

def main(global_config, **settings):
    setup_database()
    config = Configurator(settings=settings)
    config.add_route('get_user_posts', '/api/posts')
    config.add_route('create_post', '/api/posts')
    config.add_route('login', '/api/login')
    config.add_route('delete_post', '/api/posts')
    config.scan()
    return config.make_wsgi_app()