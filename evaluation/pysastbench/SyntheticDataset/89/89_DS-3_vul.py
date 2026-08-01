from django.shortcuts import render
from django.http import JsonResponse
from django.db import connection
from django.views.decorators.csrf import csrf_exempt
import json

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

@csrf_exempt
def register_user(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            with connection.cursor() as cursor:
                cursor.execute('''
                    INSERT INTO users (username, password, email)
                    VALUES (%s, %s, %s)
                ''', [data['username'], data['password'], data['email']])
            return JsonResponse({'status': 'success'})
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    return JsonResponse({'error': 'Invalid method'}, status=405)

@csrf_exempt
def search_products(request):
    if request.method == 'GET':
        search_term = request.GET.get('q', '')
        try:
            with connection.cursor() as cursor:
                # Vulnerable SQL injection - direct string interpolation
                query = f"""
                    SELECT * FROM products 
                    WHERE name LIKE '%{search_term}%' 
                    OR description LIKE '%{search_term}%'
                    OR category LIKE '%{search_term}%'
                    ORDER BY price DESC
                """
                cursor.execute(query)
                columns = [col[0] for col in cursor.description]
                products = [dict(zip(columns, row)) for row in cursor.fetchall()]
                return JsonResponse({'products': products})
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    return JsonResponse({'error': 'Invalid method'}, status=405)

@csrf_exempt
def get_product(request, product_id):
    if request.method == 'GET':
        try:
            with connection.cursor() as cursor:
                cursor.execute('SELECT * FROM products WHERE id = %s', [product_id])
                columns = [col[0] for col in cursor.description]
                product = dict(zip(columns, cursor.fetchone()))
                return JsonResponse(product)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=404)
    return JsonResponse({'error': 'Invalid method'}, status=405)

@csrf_exempt
def update_stock(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            with connection.cursor() as cursor:
                cursor.execute('''
                    UPDATE products 
                    SET stock = %s 
                    WHERE id = %s
                ''', [data['stock'], data['product_id']])
                return JsonResponse({'status': 'success'})
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    return JsonResponse({'error': 'Invalid method'}, status=405)

def user_login(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            with connection.cursor() as cursor:
                cursor.execute('''
                    SELECT * FROM users 
                    WHERE username = %s AND password = %s
                ''', [data['username'], data['password']])
                columns = [col[0] for col in cursor.description]
                user = dict(zip(columns, cursor.fetchone()))
                return JsonResponse({'status': 'success', 'user': user})
        except Exception as e:
            return JsonResponse({'error': 'Invalid credentials'}, status=401)
    return JsonResponse({'error': 'Invalid method'}, status=405)

# Initialize database on startup
init_db()