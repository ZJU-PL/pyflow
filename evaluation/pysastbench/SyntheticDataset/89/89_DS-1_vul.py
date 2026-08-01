import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

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

@app.route('/add_product', methods=['POST'])
def add_product():
    data = request.get_json()
    try:
        conn = sqlite3.connect('inventory.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO products (name, price, quantity, category)
            VALUES (?, ?, ?, ?)
        ''', (data['name'], data['price'], data['quantity'], data['category']))
        conn.commit()
        conn.close()
        return jsonify({"message": "Product added successfully"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/search_product', methods=['GET'])
def search_product():
    search_term = request.args.get('query', '')
    try:
        conn = sqlite3.connect('inventory.db')
        cursor = conn.cursor()
        # Vulnerable SQL injection - concatenating user input directly
        query = f"SELECT * FROM products WHERE name LIKE '%{search_term}%' OR category LIKE '%{search_term}%'"
        cursor.execute(query)
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
        return jsonify({"error": str(e)}), 500

@app.route('/update_quantity', methods=['PUT'])
def update_quantity():
    data = request.get_json()
    try:
        conn = sqlite3.connect('inventory.db')
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE products SET quantity = ? WHERE id = ?
        ''', (data['quantity'], data['id']))
        conn.commit()
        conn.close()
        return jsonify({"message": "Quantity updated successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

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
        return jsonify({"error": str(e)}), 400

if __name__ == '__main__':
    init_db()
    app.run(debug=True)