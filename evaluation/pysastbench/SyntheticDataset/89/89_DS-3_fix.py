from django.shortcuts import render
from django.http import JsonResponse
from django.db import connection
from django.views.decorators.http import require_http_methods
from django.core.exceptions import ValidationError
from django.contrib.auth.hashers import make_password, check_password
from django.conf import settings
import json
import re
from functools import wraps
from django_ratelimit.decorators import ratelimit

# Rate limiting decorator
def rate_limited(max_calls, period):
    return ratelimit(key='ip', rate=f'{max_calls}/{period}s')

def validate_input(data, rules):
    """Validate input data against rules"""
    errors = {}
    for field, validator in rules.items():
        if field not in data:
            errors[field] = "This field is required"
        else:
            try:
                validator(data[field])
            except ValidationError as e:
                errors[field] = str(e)
    if errors:
        raise ValidationError(errors)

def sanitize_search_term(term):
    """Sanitize search term to prevent SQL injection"""
    if not isinstance(term, str):
        return ""
    # Remove potentially dangerous characters
    return re.sub(r'[;\'"\\]', '', term)[:100]

def init_db():
    with connection.cursor() as cursor:
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                price REAL,
                stock INTEGER,
                category TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT
            )
        ''')
        # Insert sample data if empty
        cursor.execute("SELECT COUNT(*) FROM products")
        if cursor.fetchone()[0] == 0:
            cursor.executemany('''
                INSERT INTO products (name, description, price, stock, category)
                VALUES (%s, %s, %s, %s, %s)
            ''', [
                ('Laptop', 'High performance laptop', 999.99, 50, 'Electronics'),
                ('Phone', 'Latest smartphone', 699.99, 100, 'Electronics'),
                ('Headphones', 'Noise cancelling', 199.99, 75, 'Accessories')
            ])

@require_http_methods(["POST"])
@rate_limited(5, 60)  # 5 requests per minute
def register_user(request):
    try:
        data = json.loads(request.body)
        
        # Validate input
        validate_input(data, {
            'username': lambda x: ValidationError("Invalid username") if len(x) > 50 else None,
            'password': lambda x: ValidationError("Password too short") if len(x) < 8 else None,
            'email': lambda x: ValidationError("Invalid email") if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', x) else None
        })
        
        with connection.cursor() as cursor:
            # Hash password before storage
            hashed_password = make_password(data['password'])
            cursor.execute('''
                INSERT INTO users (username, password, email)
                VALUES (%s, %s, %s)
            ''', [data['username'], hashed_password, data['email']])
        return JsonResponse({'status': 'success'})
    except ValidationError as e:
        return JsonResponse({'error': e.message_dict}, status=400)
    except Exception as e:
        return JsonResponse({'error': 'Registration failed'}, status=400)

@require_http_methods(["GET"])
@rate_limited(60, 60)  # 60 requests per minute
def search_products(request):
    search_term = request.GET.get('q', '')
    safe_search_term = sanitize_search_term(search_term)
    
    try:
        with connection.cursor() as cursor:
            # Use parameterized queries
            query = """
                SELECT * FROM products 
                WHERE name LIKE %s 
                OR description LIKE %s
                OR category LIKE %s
                ORDER BY price DESC
            """
            search_param = f'%{safe_search_term}%'
            cursor.execute(query, [search_param, search_param, search_param])
            columns = [col[0] for col in cursor.description]
            products = [dict(zip(columns, row)) for row in cursor.fetchall()]
            return JsonResponse({'products': products})
    except Exception as e:
        return JsonResponse({'error': 'Search failed'}, status=500)

@require_http_methods(["GET"])
@rate_limited(120, 60)  # 120 requests per minute
def get_product(request, product_id):
    try:
        # Validate product_id is numeric
        if not str(product_id).isdigit():
            raise ValidationError("Invalid product ID")
            
        with connection.cursor() as cursor:
            cursor.execute('SELECT * FROM products WHERE id = %s', [product_id])
            columns = [col[0] for col in cursor.description]
            product = dict(zip(columns, cursor.fetchone()))
            return JsonResponse(product)
    except Exception as e:
        return JsonResponse({'error': 'Product not found'}, status=404)

@require_http_methods(["POST"])
@rate_limited(30, 60)  # 30 requests per minute
def update_stock(request):
    try:
        data = json.loads(request.body)
        
        # Validate input
        validate_input(data, {
            'product_id': lambda x: ValidationError("Invalid product ID") if not str(x).isdigit() else None,
            'stock': lambda x: ValidationError("Invalid stock value") if not isinstance(x, int) or x < 0 else None
        })
        
        with connection.cursor() as cursor:
            cursor.execute('''
                UPDATE products 
                SET stock = %s 
                WHERE id = %s
            ''', [data['stock'], data['product_id']])
            return JsonResponse({'status': 'success'})
    except ValidationError as e:
        return JsonResponse({'error': e.message_dict}, status=400)
    except Exception as e:
        return JsonResponse({'error': 'Update failed'}, status=400)

@require_http_methods(["POST"])
@rate_limited(5, 60)  # 5 requests per minute
def user_login(request):
    try:
        data = json.loads(request.body)
        
        # Validate input
        validate_input(data, {
            'username': lambda x: None,  # Just check existence
            'password': lambda x: None   # Just check existence
        })
        
        with connection.cursor() as cursor:
            cursor.execute('''
                SELECT * FROM users 
                WHERE username = %s
            ''', [data['username']])
            columns = [col[0] for col in cursor.description]
            user = dict(zip(columns, cursor.fetchone()))
            
            # Verify password
            if not check_password(data['password'], user['password']):
                raise ValidationError("Invalid credentials")
                
            # Don't return password hash
            del user['password']
            return JsonResponse({'status': 'success', 'user': user})
    except ValidationError as e:
        return JsonResponse({'error': str(e)}, status=401)
    except Exception as e:
        return JsonResponse({'error': 'Login failed'}, status=401)

# Initialize database on startup
init_db()