from pyramid.config import Configurator
from pyramid.response import Response
from pyramid.view import view_config
import sqlite3
import json
import hashlib
import re

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
        # Hash passwords before storing
        passwords = [
            hashlib.sha256('admin123'.encode()).hexdigest(),
            hashlib.sha256('editorpass'.encode()).hexdigest(),
            hashlib.sha256('userpass1'.encode()).hexdigest()
        ]
        cursor.executemany('''
            INSERT INTO users (username, password, role)
            VALUES (?, ?, ?)
        ''', [
            ('admin', passwords[0], 'admin'),
            ('editor1', passwords[1], 'editor'),
            ('user1', passwords[2], 'user')
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

def validate_user_id(user_id):
    """Validate user_id is a positive integer"""
    if not user_id or not user_id.isdigit():
        raise ValueError("Invalid user ID")
    return int(user_id)

@view_config(route_name='get_user_posts', request_method='GET', renderer='json')
def get_user_posts(request):
    try:
        user_id = validate_user_id(request.params.get('user_id'))
        show_drafts = request.params.get('show_drafts', 'false').lower() == 'true'
        
        conn = sqlite3.connect('cms.db')
        cursor = conn.cursor()
        
        # Fixed SQL injection using parameterized queries
        query = """
            SELECT p.id, p.title, p.content, u.username 
            FROM posts p
            JOIN users u ON p.user_id = u.id
            WHERE p.user_id = ?
        """
        params = [user_id]
        
        if not show_drafts:
            query += " AND p.published = 1"
        
        cursor.execute(query, params)
        posts = [dict(zip(['id', 'title', 'content', 'author'], row)) for row in cursor.fetchall()]
        conn.close()
        return {'posts': posts}
    except ValueError as e:
        return Response(json.dumps({'error': str(e)}), status=400)
    except Exception as e:
        conn.close() if 'conn' in locals() else None
        return Response(json.dumps({'error': 'Internal server error'}), status=500)

@view_config(route_name='create_post', request_method='POST', renderer='json')
def create_post(request):
    try:
        data = request.json_body
        # Validate input
        if not all(key in data for key in ['user_id', 'title', 'content']):
            return Response(json.dumps({'error': 'Missing required fields'}), status=400)
        
        # Validate user_id
        user_id = validate_user_id(str(data['user_id']))
        
        # Validate title length
        if len(data['title']) > 200:
            return Response(json.dumps({'error': 'Title too long'}), status=400)
            
        conn = sqlite3.connect('cms.db')
        cursor = conn.cursor()
        
        # Check user exists
        cursor.execute('SELECT 1 FROM users WHERE id = ?', (user_id,))
        if not cursor.fetchone():
            return Response(json.dumps({'error': 'User not found'}), status=404)
        
        cursor.execute('''
            INSERT INTO posts (user_id, title, content, published)
            VALUES (?, ?, ?, ?)
        ''', (user_id, data['title'], data['content'], data.get('published', False)))
        conn.commit()
        post_id = cursor.lastrowid
        conn.close()
        return {'status': 'success', 'post_id': post_id}
    except ValueError as e:
        return Response(json.dumps({'error': str(e)}), status=400)
    except Exception as e:
        conn.close() if 'conn' in locals() else None
        return Response(json.dumps({'error': 'Failed to create post'}), status=500)

@view_config(route_name='login', request_method='POST', renderer='json')
def login(request):
    try:
        data = request.json_body
        if not all(key in data for key in ['username', 'password']):
            return Response(json.dumps({'error': 'Missing credentials'}), status=400)
        
        # Basic input validation
        if not re.match(r'^[a-zA-Z0-9_]{4,20}$', data['username']):
            return Response(json.dumps({'error': 'Invalid username format'}), status=400)
            
        conn = sqlite3.connect('cms.db')
        cursor = conn.cursor()
        
        # Get stored password hash
        cursor.execute('''
            SELECT id, username, role, password FROM users 
            WHERE username = ?
        ''', (data['username'],))
        user = cursor.fetchone()
        conn.close()
        
        if user:
            # Verify password
            hashed_input = hashlib.sha256(data['password'].encode()).hexdigest()
            if hashed_input == user[3]:
                return {
                    'user': {
                        'id': user[0],
                        'username': user[1],
                        'role': user[2]
                    }
                }
        return Response(json.dumps({'error': 'Invalid credentials'}), status=401)
    except Exception as e:
        conn.close() if 'conn' in locals() else None
        return Response(json.dumps({'error': 'Login failed'}), status=500)

@view_config(route_name='delete_post', request_method='DELETE', renderer='json')
def delete_post(request):
    try:
        data = request.json_body
        if 'post_id' not in data:
            return Response(json.dumps({'error': 'Missing post_id'}), status=400)
            
        if not str(data['post_id']).isdigit():
            return Response(json.dumps({'error': 'Invalid post ID'}), status=400)
            
        conn = sqlite3.connect('cms.db')
        cursor = conn.cursor()
        cursor.execute('DELETE FROM posts WHERE id = ?', (data['post_id'],))
        conn.commit()
        affected = cursor.rowcount
        conn.close()
        
        if affected == 0:
            return Response(json.dumps({'error': 'Post not found'}), status=404)
        return {'status': 'success'}
    except Exception as e:
        conn.close() if 'conn' in locals() else None
        return Response(json.dumps({'error': 'Failed to delete post'}), status=500)

def main(global_config, **settings):
    setup_database()
    config = Configurator(settings=settings)
    config.add_route('get_user_posts', '/api/posts')
    config.add_route('create_post', '/api/posts')
    config.add_route('login', '/api/login')
    config.add_route('delete_post', '/api/posts')
    config.scan()
    return config.make_wsgi_app()