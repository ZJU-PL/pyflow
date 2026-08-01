from flask import Flask, request, jsonify
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import re

app = Flask(__name__)

def init_db():
    conn = sqlite3.connect('books.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, 
                  username TEXT UNIQUE, 
                  password TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS books
                 (id INTEGER PRIMARY KEY, 
                  title TEXT, 
                  author TEXT, 
                  genre TEXT, 
                  price REAL)''')
    conn.commit()
    conn.close()

def get_db_connection():
    return sqlite3.connect('books.db')

def validate_username(username):
    """Validate username format"""
    if not re.match(r'^[a-zA-Z0-9_]{4,20}$', username):
        raise ValueError("Username must be 4-20 alphanumeric characters")
    return username

def validate_password(password):
    """Validate password meets complexity requirements"""
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters")
    return password

def validate_book_data(data):
    """Validate book data"""
    if not all(field in data for field in ['title', 'author', 'genre', 'price']):
        raise ValueError("Missing required fields")
    try:
        float(data['price'])
    except ValueError:
        raise ValueError("Invalid price format")
    if float(data['price']) <= 0:
        raise ValueError("Price must be positive")
    return data

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        username = validate_username(data.get('username'))
        password = generate_password_hash(validate_password(data.get('password')))
        
        conn = get_db_connection()
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", 
                     (username, password))
            conn.commit()
            return jsonify({"message": "User created"}), 201
        except sqlite3.IntegrityError:
            return jsonify({"error": "Username already exists"}), 400
        finally:
            conn.close()
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": "Registration failed"}), 500

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({"error": "Username and password required"}), 400
        
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()
        
        if user and check_password_hash(user[0], password):
            return jsonify({"message": "Login successful"}), 200
        return jsonify({"error": "Invalid credentials"}), 401
    except Exception as e:
        return jsonify({"error": "Login failed"}), 500

@app.route('/books/search', methods=['GET'])
def search_books():
    search_term = request.args.get('query')
    if not search_term:
        return jsonify({"error": "Query parameter required"}), 400
    
    # Sanitize search term
    search_term = re.sub(r'[;\'"\\]', '', search_term)
    
    conn = get_db_connection()
    c = conn.cursor()
    
    # Fixed SQL injection using parameterized queries
    query = "SELECT * FROM books WHERE title LIKE ? OR author LIKE ?"
    c.execute(query, (f"%{search_term}%", f"%{search_term}%"))
    
    books = []
    for row in c.fetchall():
        books.append({
            'id': row[0],
            'title': row[1],
            'author': row[2],
            'genre': row[3],
            'price': row[4]
        })
    
    conn.close()
    return jsonify(books)

@app.route('/books/add', methods=['POST'])
def add_book():
    try:
        data = validate_book_data(request.get_json())
        
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("INSERT INTO books (title, author, genre, price) VALUES (?, ?, ?, ?)",
                 (data['title'], data['author'], data['genre'], float(data['price'])))
        conn.commit()
        conn.close()
        return jsonify({"message": "Book added"}), 201
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        conn.close() if 'conn' in locals() else None
        return jsonify({"error": "Failed to add book"}), 500

@app.route('/books/delete/<int:book_id>', methods=['DELETE'])
def delete_book(book_id):
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("DELETE FROM books WHERE id = ?", (book_id,))
        affected = c.rowcount
        conn.commit()
        conn.close()
        
        if affected == 0:
            return jsonify({"error": "Book not found"}), 404
        return jsonify({"message": "Book deleted"}), 200
    except Exception as e:
        conn.close() if 'conn' in locals() else None
        return jsonify({"error": "Failed to delete book"}), 500

if __name__ == '__main__':
    init_db()
    app.run(debug=False)  # Disable debug mode in production