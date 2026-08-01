import sqlite3
from flask import Flask, request, jsonify
import json
from functools import wraps
import jwt  # PyJWT library
from datetime import datetime, timedelta
import os

app = Flask(__name__)
DATABASE = 'data.db'
SECRET_KEY = os.environ.get('SECRET_KEY', 'your-secret-key-here')  # Should be in environment variables

def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            price REAL,
            category TEXT,
            stock INTEGER
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT
        )
    ''')
    conn.commit()
    conn.close()

def auth_required(role='user'):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth = request.headers.get('Authorization')
            if not auth:
                return jsonify({'error': 'Authorization required'}), 401
            
            try:
                # Extract token from "Bearer <token>" format
                if not auth.startswith('Bearer '):
                    raise ValueError('Invalid authorization format')
                
                token = auth[7:]
                user = verify_token(token)
                
                if user['role'] not in [role, 'admin']:
                    return jsonify({'error': 'Insufficient permissions'}), 403
                
                return f(*args, **kwargs)
            except Exception as e:
                return jsonify({'error': str(e)}), 401
        return wrapper
    return decorator

def verify_token(token):
    try:
        # Verify JWT token
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        if not all(k in payload for k in ['username', 'role', 'exp']):
            raise ValueError('Invalid token structure')
        
        # Check expiration
        if datetime.utcnow() > datetime.fromtimestamp(payload['exp']):
            raise ValueError('Token expired')
        
        return {
            'username': payload['username'],
            'role': payload['role']
        }
    except jwt.PyJWTError as e:
        raise ValueError(f'Invalid token: {str(e)}')

class QueryBuilder:
    def __init__(self, table):
        self.table = table
        self.filters = []
        self.params = []
        self.limit = None
    
    def add_filter(self, field, operator, value):
        # Validate field name to prevent SQL injection
        if not isinstance(field, str) or not field.replace('_', '').isalnum():
            raise ValueError('Invalid field name')
        
        # Validate operator
        valid_operators = ['=', '!=', '<', '>', '<=', '>=', 'LIKE', 'IN']
        if operator not in valid_operators:
            raise ValueError(f'Invalid operator. Must be one of: {", ".join(valid_operators)}')
        
        # Add parameterized filter
        self.filters.append(f"{field} {operator} ?")
        self.params.append(value)
        return self
    
    def set_limit(self, limit):
        if not isinstance(limit, int) or limit <= 0:
            raise ValueError('Limit must be a positive integer')
        self.limit = limit
        return self
    
    def build(self):
        query = f"SELECT * FROM {self.table}"
        if self.filters:
            query += " WHERE " + " AND ".join(self.filters)
        if self.limit:
            query += " LIMIT ?"
            self.params.append(self.limit)
        return query
    
    def execute(self):
        conn = sqlite3.connect(DATABASE)
        conn.row_factory = sqlite3.Row  # Enable dictionary-like access
        cursor = conn.cursor()
        try:
            # Safe parameterized query execution
            query = self.build()
            cursor.execute(query, self.params)
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            raise ValueError(f'Database error: {str(e)}')
        finally:
            conn.close()

@app.route('/api/products', methods=['GET'])
@auth_required()
def get_products():
    try:
        filters = request.args.getlist('filter')
        limit = request.args.get('limit', type=int)
        
        builder = QueryBuilder('products')
        for f in filters:
            parts = f.split(':', 2)
            if len(parts) == 3:
                builder.add_filter(parts[0], parts[1], parts[2])
        
        if limit:
            builder.set_limit(limit)
        
        products = builder.execute()
        return jsonify(products)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/users', methods=['GET'])
@auth_required('admin')
def get_users():
    try:
        builder = QueryBuilder('users')
        if 'limit' in request.args:
            builder.set_limit(request.args.get('limit', type=int))
        users = builder.execute()
        return jsonify(users)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    init_db()
    app.run(debug=False)  # Disable debug mode in production