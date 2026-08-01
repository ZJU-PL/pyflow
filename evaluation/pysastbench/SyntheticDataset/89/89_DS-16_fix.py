from pyramid.config import Configurator
from pyramid.response import Response
from pyramid.view import view_config
import sqlite3
import json

def init_db():
    conn = sqlite3.connect('user_profiles.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users
                     (id INTEGER PRIMARY KEY, 
                     username TEXT UNIQUE, 
                     password TEXT, 
                     email TEXT, 
                     bio TEXT)''')
    
    # Insert sample data if empty
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        users = [
            (1, 'admin', 'securepass123', 'admin@example.com', 'System administrator'),
            (2, 'johndoe', 'johnspass', 'john@example.com', 'Software developer'),
            (3, 'janedoe', 'janespass', 'jane@example.com', 'Data scientist')
        ]
        cursor.executemany("INSERT INTO users VALUES (?, ?, ?, ?, ?)", users)
        conn.commit()
    conn.close()

@view_config(route_name='home', request_method='GET')
def home_view(request):
    return Response(json.dumps({'message': 'User Profile API'}), 
                   content_type='application/json')

@view_config(route_name='register', request_method='POST')
def register_view(request):
    try:
        data = request.json_body
        conn = sqlite3.connect('user_profiles.db')
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, password, email, bio) VALUES (?, ?, ?, ?)",
            (data['username'], data['password'], data['email'], data.get('bio', ''))
        )
        conn.commit()
        return Response(json.dumps({'status': 'success'}), 
                       content_type='application/json')
    except sqlite3.IntegrityError:
        return Response(json.dumps({'error': 'Username already exists'}), 
                       status=400, content_type='application/json')

@view_config(route_name='search_users', request_method='GET')
def search_users_view(request):
    search_term = request.params.get('q', '')
    
    if not search_term:
        return Response(json.dumps({'error': 'Search term required'}),
                      status=400, content_type='application/json')
    
    conn = sqlite3.connect('user_profiles.db')
    cursor = conn.cursor()
    
    # Fixed: Using parameterized query to prevent SQL injection
    query = "SELECT id, username, email, bio FROM users WHERE username LIKE ? OR bio LIKE ?"
    search_pattern = f"%{search_term}%"
    cursor.execute(query, (search_pattern, search_pattern))
    
    results = []
    for row in cursor.fetchall():
        results.append({
            'id': row[0],
            'username': row[1],
            'email': row[2],
            'bio': row[3]
        })
    
    return Response(json.dumps(results), content_type='application/json')

@view_config(route_name='user_detail', request_method='GET')
def user_detail_view(request):
    user_id = request.matchdict['user_id']
    conn = sqlite3.connect('user_profiles.db')
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, username, email, bio FROM users WHERE id = ?",
        (user_id,)
    )
    user = cursor.fetchone()
    
    if user:
        return Response(json.dumps({
            'id': user[0],
            'username': user[1],
            'email': user[2],
            'bio': user[3]
        }), content_type='application/json')
    else:
        return Response(json.dumps({'error': 'User not found'}),
                      status=404, content_type='application/json')

def main(global_config, **settings):
    init_db()
    config = Configurator()
    
    config.add_route('home', '/')
    config.add_route('register', '/register')
    config.add_route('search_users', '/search')
    config.add_route('user_detail', '/users/{user_id}')
    
    config.scan()
    return config.make_wsgi_app()