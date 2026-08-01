from django.http import JsonResponse
from django.db import connection
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import get_object_or_404
import json

products = [
    {'id': 1, 'name': 'Laptop', 'price': 999.99, 'category': 'Electronics'},
    {'id': 2, 'name': 'Smartphone', 'price': 699.99, 'category': 'Electronics'},
    {'id': 3, 'name': 'Headphones', 'price': 149.99, 'category': 'Electronics'},
    {'id': 4, 'name': 'T-shirt', 'price': 19.99, 'category': 'Clothing'},
]

users = [
    {'id': 1, 'username': 'admin', 'password': 'admin123', 'is_admin': True},
    {'id': 2, 'username': 'user1', 'password': 'password1', 'is_admin': False},
]

orders = []

def init_db():
    with connection.cursor() as cursor:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                price REAL NOT NULL,
                category TEXT NOT NULL
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                is_admin BOOLEAN NOT NULL
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS orders (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                product_id INTEGER NOT NULL,
                quantity INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (product_id) REFERENCES products(id)
            )
        """)
        
        if not cursor.execute("SELECT COUNT(*) FROM products").fetchone()[0]:
            for product in products:
                cursor.execute(
                    "INSERT INTO products (id, name, price, category) VALUES (%s, %s, %s, %s)",
                    [product['id'], product['name'], product['price'], product['category']]
                )
        
        if not cursor.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
            for user in users:
                cursor.execute(
                    "INSERT INTO users (id, username, password, is_admin) VALUES (%s, %s, %s, %s)",
                    [user['id'], user['username'], user['password'], user['is_admin']]
                )

@csrf_exempt
def user_login(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        username = data.get('username')
        password = data.get('password')
        
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT * FROM users WHERE username = %s AND password = %s",
                [username, password]
            )
            user = cursor.fetchone()
            
            if user:
                return JsonResponse({
                    'status': 'success',
                    'user_id': user[0],
                    'is_admin': user[3]
                })
        
        return JsonResponse({'status': 'error', 'message': 'Invalid credentials'}, status=401)
    return JsonResponse({'status': 'error', 'message': 'Method not allowed'}, status=405)

@csrf_exempt
def search_products(request):
    if request.method == 'GET':
        search_term = request.GET.get('q', '')
        
        with connection.cursor() as cursor:
            # Fixed: Using parameterized query to prevent SQL injection
            query = "SELECT * FROM products WHERE name LIKE %s OR category LIKE %s"
            search_pattern = f"%{search_term}%"
            cursor.execute(query, [search_pattern, search_pattern])
            results = cursor.fetchall()
            
            products_list = []
            for row in results:
                products_list.append({
                    'id': row[0],
                    'name': row[1],
                    'price': row[2],
                    'category': row[3]
                })
            
            return JsonResponse({'products': products_list})
    return JsonResponse({'status': 'error', 'message': 'Method not allowed'}, status=405)

@csrf_exempt
def create_order(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        user_id = data.get('user_id')
        product_id = data.get('product_id')
        quantity = data.get('quantity', 1)
        
        with connection.cursor() as cursor:
            cursor.execute(
                "INSERT INTO orders (user_id, product_id, quantity) VALUES (%s, %s, %s)",
                [user_id, product_id, quantity]
            )
            
            return JsonResponse({'status': 'success', 'message': 'Order created'})
    return JsonResponse({'status': 'error', 'message': 'Method not allowed'}, status=405)

@csrf_exempt
def get_user_orders(request, user_id):
    if request.method == 'GET':
        with connection.cursor() as cursor:
            cursor.execute(
                """SELECT o.id, p.name, p.price, o.quantity 
                   FROM orders o JOIN products p ON o.product_id = p.id 
                   WHERE o.user_id = %s""",
                [user_id]
            )
            orders = cursor.fetchall()
            
            orders_list = []
            for row in orders:
                orders_list.append({
                    'order_id': row[0],
                    'product_name': row[1],
                    'price': row[2],
                    'quantity': row[3]
                })
            
            return JsonResponse({'orders': orders_list})
    return JsonResponse({'status': 'error', 'message': 'Method not allowed'}, status=405)

init_db()