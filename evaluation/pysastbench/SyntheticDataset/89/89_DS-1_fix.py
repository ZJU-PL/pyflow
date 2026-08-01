import sqlite3
from flask import Flask, request, jsonify
from werkzeug.exceptions import BadRequest
import re

app = Flask(__name__)
app.config['DEBUG'] = False  # Disable debug mode in production

def init_db():
    conn = sqlite3.connect('inventory.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            price REAL,
            quantity INTEGER,
            category TEXT
        )
    ''')
    conn.commit()
    conn.close()

def validate_product_data(data, required_fields):
    """Validate product data and check for required fields"""
    if not isinstance(data, dict):
        raise BadRequest("Invalid data format")
    
    missing_fields = [field for field in required_fields if field not in data]
    if missing_fields:
        raise BadRequest(f"Missing required fields: {', '.join(missing_fields)}")
    
    # Additional validation
    if not isinstance(data.get('name'), str) or len(data['name']) > 100:
        raise BadRequest("Invalid product name")
    
    try:
        price = float(data['price'])
        if price <= 0:
            raise BadRequest("Price must be positive")
    except (ValueError, TypeError):
        raise BadRequest("Invalid price format")
    
    try:
        quantity = int(data['quantity'])
        if quantity < 0:
            raise BadRequest("Quantity cannot be negative")
    except (ValueError, TypeError):
        raise BadRequest("Invalid quantity format")
    
    if not isinstance(data.get('category'), str) or len(data['category']) > 50:
        raise BadRequest("Invalid category")

def sanitize_search_term(term):
    """Sanitize search term to prevent SQL injection"""
    if not isinstance(term, str):
        return ""
    # Remove potentially dangerous characters
    return re.sub(r'[;\'"\\]', '', term)[:100]

@app.route('/add_product', methods=['POST'])
def add_product():
    try:
        data = request.get_json()
        validate_product_data(data, ['name', 'price', 'quantity', 'category'])
        
        conn = sqlite3.connect('inventory.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO products (name, price, quantity, category)
            VALUES (?, ?, ?, ?)
        ''', (data['name'], data['price'], data['quantity'], data['category']))
        conn.commit()
        conn.close()
        return jsonify({"message": "Product added successfully"}), 201
    except BadRequest as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": "Internal server error"}), 500

@app.route('/search_product', methods=['GET'])
def search_product():
    try:
        search_term = request.args.get('query', '')
        safe_search_term = sanitize_search_term(search_term)
        
        conn = sqlite3.connect('inventory.db')
        cursor = conn.cursor()
        # Use parameterized queries to prevent SQL injection
        cursor.execute('''
            SELECT * FROM products 
            WHERE name LIKE ? OR category LIKE ?
        ''', (f'%{safe_search_term}%', f'%{safe_search_term}%'))
        results = cursor.fetchall()
        conn.close()
        
        products = []
        for row in results:
            products.append({
                'id': row[0],
                'name': row[1],
                'price': row[2],
                'quantity': row[3],
                'category': row[4]
            })
        return jsonify(products)
    except Exception as e:
        return jsonify({"error": "Internal server error"}), 500

@app.route('/update_quantity', methods=['PUT'])
def update_quantity():
    try:
        data = request.get_json()
        if not isinstance(data, dict) or 'id' not in data or 'quantity' not in data:
            raise BadRequest("Missing required fields: id and quantity")
        
        try:
            product_id = int(data['id'])
            quantity = int(data['quantity'])
            if quantity < 0:
                raise BadRequest("Quantity cannot be negative")
        except (ValueError, TypeError):
            raise BadRequest("Invalid ID or quantity format")
        
        conn = sqlite3.connect('inventory.db')
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE products SET quantity = ? WHERE id = ?
        ''', (quantity, product_id))
        conn.commit()
        conn.close()
        return jsonify({"message": "Quantity updated successfully"})
    except BadRequest as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": "Internal server error"}), 500

@app.route('/delete_product/<int:product_id>', methods=['DELETE'])
def delete_product(product_id):
    try:
        conn = sqlite3.connect('inventory.db')
        cursor = conn.cursor()
        cursor.execute('DELETE FROM products WHERE id = ?', (product_id,))
        conn.commit()
        conn.close()
        return jsonify({"message": "Product deleted successfully"})
    except Exception as e:
        return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    init_db()
    app.run(debug=False)  # Debug mode should be off in production