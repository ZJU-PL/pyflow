from flask import Flask, request, jsonify
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

def init_db():
    conn = sqlite3.connect('books.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT, password TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS books
                 (id INTEGER PRIMARY KEY, title TEXT, author TEXT, 
                 genre TEXT, price REAL)''')
    conn.commit()
    conn.close()

def get_db_connection():
    return sqlite3.connect('books.db')

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = generate_password_hash(data.get('password'))
    
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("INSERT INTO users (username, password) VALUES (?, ?)", 
              (username, password))
    conn.commit()
    conn.close()
    return jsonify({"message": "User created"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(f"SELECT password FROM users WHERE username = '{username}'")
    user = c.fetchone()
    conn.close()
    
    if user and check_password_hash(user[0], password):
        return jsonify({"message": "Login successful"}), 200
    return jsonify({"message": "Invalid credentials"}), 401

@app.route('/books/search', methods=['GET'])
def search_books():
    search_term = request.args.get('query')
    if not search_term:
        return jsonify({"error": "Query parameter required"}), 400
    
    conn = get_db_connection()
    c = conn.cursor()
    
    # Vulnerable SQL injection point
    query = f"SELECT * FROM books WHERE title LIKE '%{search_term}%' OR author LIKE '%{search_term}%'"
    c.execute(query)
    
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
    data = request.get_json()
    required_fields = ['title', 'author', 'genre', 'price']
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Missing fields"}), 400
    
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("INSERT INTO books (title, author, genre, price) VALUES (?, ?, ?, ?)",
              (data['title'], data['author'], data['genre'], data['price']))
    conn.commit()
    conn.close()
    return jsonify({"message": "Book added"}), 201

@app.route('/books/delete/<int:book_id>', methods=['DELETE'])
def delete_book(book_id):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("DELETE FROM books WHERE id = ?", (book_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "Book deleted"}), 200

if __name__ == '__main__':
    init_db()
    app.run(debug=True)