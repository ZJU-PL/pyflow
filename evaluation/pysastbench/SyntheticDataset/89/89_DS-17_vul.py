from bottle import Bottle, run, request, response, abort
import sqlite3
import json

app = Bottle()

def init_db():
    conn = sqlite3.connect('inventory.db')
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS categories
                 (id INTEGER PRIMARY KEY, name TEXT)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS products
                 (id INTEGER PRIMARY KEY,
                 name TEXT,
                 price REAL,
                 category_id INTEGER,
                 stock INTEGER,
                 FOREIGN KEY(category_id) REFERENCES categories(id))''')
    
    # Insert sample data if empty
    c.execute("SELECT COUNT(*) FROM categories")
    if c.fetchone()[0] == 0:
        categories = [(1, 'Electronics'), (2, 'Clothing'), (3, 'Books')]
        c.executemany("INSERT INTO categories VALUES (?, ?)", categories)
        
        products = [
            (1, 'Laptop', 999.99, 1, 10),
            (2, 'T-Shirt', 19.99, 2, 50),
            (3, 'Python Cookbook', 39.99, 3, 20),
            (4, 'Smartphone', 699.99, 1, 15)
        ]
        c.executemany("INSERT INTO products VALUES (?, ?, ?, ?, ?)", products)
        conn.commit()
    conn.close()

@app.route('/products', method='GET')
def get_products():
    conn = sqlite3.connect('inventory.db')
    c = conn.cursor()
    
    category = request.query.get('category')
    min_price = request.query.get('min_price')
    max_price = request.query.get('max_price')
    in_stock = request.query.get('in_stock', 'true').lower() == 'true'
    
    base_query = "SELECT p.id, p.name, p.price, c.name as category, p.stock FROM products p JOIN categories c ON p.category_id = c.id"
    conditions = []
    params = []
    
    if category:
        conditions.append("c.name = ?")
        params.append(category)
    
    if min_price:
        conditions.append("p.price >= ?")
        params.append(float(min_price))
    
    if max_price:
        conditions.append("p.price <= ?")
        params.append(float(max_price))
    
    if in_stock:
        conditions.append("p.stock > 0")
    
    if conditions:
        base_query += " WHERE " + " AND ".join(conditions)
    
    c.execute(base_query, params)
    products = []
    for row in c.fetchall():
        products.append({
            'id': row[0],
            'name': row[1],
            'price': row[2],
            'category': row[3],
            'stock': row[4]
        })
    
    conn.close()
    response.content_type = 'application/json'
    return json.dumps(products)

@app.route('/products/search', method='GET')
def search_products():
    search_term = request.query.get('q')
    if not search_term:
        abort(400, "Search term required")
    
    conn = sqlite3.connect('inventory.db')
    c = conn.cursor()
    
    # Vulnerable SQL injection point
    query = f"SELECT p.id, p.name, p.price, c.name as category FROM products p JOIN categories c ON p.category_id = c.id WHERE p.name LIKE '%{search_term}%' OR c.name LIKE '%{search_term}%'"
    c.execute(query)
    
    results = []
    for row in c.fetchall():
        results.append({
            'id': row[0],
            'name': row[1],
            'price': row[2],
            'category': row[3]
        })
    
    conn.close()
    response.content_type = 'application/json'
    return json.dumps(results)

@app.route('/products/<product_id:int>', method='GET')
def get_product(product_id):
    conn = sqlite3.connect('inventory.db')
    c = conn.cursor()
    
    c.execute("SELECT p.id, p.name, p.price, c.name as category, p.stock FROM products p JOIN categories c ON p.category_id = c.id WHERE p.id = ?", (product_id,))
    product = c.fetchone()
    
    if not product:
        abort(404, "Product not found")
    
    result = {
        'id': product[0],
        'name': product[1],
        'price': product[2],
        'category': product[3],
        'stock': product[4]
    }
    
    conn.close()
    response.content_type = 'application/json'
    return json.dumps(result)

if __name__ == '__main__':
    init_db()
    run(app, host='localhost', port=8080, debug=True)