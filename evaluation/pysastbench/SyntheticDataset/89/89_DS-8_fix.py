import cherrypy
import sqlite3
import json
from datetime import datetime, timedelta
import re

class LibrarySystem:
    def __init__(self):
        self.conn = sqlite3.connect('library.db')
        self.init_db()

    def init_db(self):
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS books (
                book_id INTEGER PRIMARY KEY,
                title TEXT NOT NULL,
                author TEXT NOT NULL,
                isbn TEXT UNIQUE NOT NULL,
                published_date TEXT,
                genre TEXT,
                available_copies INTEGER DEFAULT 1
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS members (
                member_id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                join_date TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS loans (
                loan_id INTEGER PRIMARY KEY,
                book_id INTEGER NOT NULL,
                member_id INTEGER NOT NULL,
                loan_date TEXT NOT NULL,
                due_date TEXT NOT NULL,
                return_date TEXT,
                FOREIGN KEY(book_id) REFERENCES books(book_id),
                FOREIGN KEY(member_id) REFERENCES members(member_id)
            )
        ''')

        # Insert sample data if empty
        cursor.execute("SELECT COUNT(*) FROM books")
        if cursor.fetchone()[0] == 0:
            cursor.executemany('''
                INSERT INTO books (title, author, isbn, published_date, genre, available_copies)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', [
                ('Python Programming', 'John Smith', '978-0123456789', '2020-01-15', 'Technology', 3),
                ('Data Science Basics', 'Alice Johnson', '978-9876543210', '2019-05-20', 'Technology', 2),
                ('History of Art', 'Robert Brown', '978-5555555555', '2018-11-30', 'Art', 1)
            ])
            cursor.executemany('''
                INSERT INTO members (name, email)
                VALUES (?, ?)
            ''', [
                ('Tom Wilson', 'tom@example.com'),
                ('Sarah Davis', 'sarah@example.com')
            ])
        self.conn.commit()

    def validate_id(self, id_str):
        """Validate that ID is a positive integer"""
        if not id_str or not id_str.isdigit():
            raise ValueError("Invalid ID format")
        return int(id_str)

    def validate_search_input(self, input_str):
        """Sanitize search input to prevent SQL injection"""
        if not input_str:
            return ""
        # Remove potentially dangerous characters
        return re.sub(r'[;\'"\\]', '', input_str)

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def search_books(self, **params):
        try:
            title = self.validate_search_input(params.get('title', ''))
            author = self.validate_search_input(params.get('author', ''))
            genre = self.validate_search_input(params.get('genre', ''))
            available_only = params.get('available_only', 'false').lower() == 'true'

            # Fixed SQL injection using parameterized queries
            query = "SELECT * FROM books WHERE 1=1"
            query_params = []

            if title:
                query += " AND title LIKE ?"
                query_params.append(f"%{title}%")
            if author:
                query += " AND author LIKE ?"
                query_params.append(f"%{author}%")
            if genre:
                query += " AND genre LIKE ?"
                query_params.append(f"%{genre}%")
            if available_only:
                query += " AND available_copies > 0"

            cursor = self.conn.cursor()
            cursor.execute(query, query_params)
            books = []
            for row in cursor.fetchall():
                books.append({
                    'book_id': row[0],
                    'title': row[1],
                    'author': row[2],
                    'isbn': row[3],
                    'published_date': row[4],
                    'genre': row[5],
                    'available_copies': row[6]
                })
            return {'books': books}
        except Exception as e:
            cherrypy.response.status = 500
            return {'error': 'Internal server error'}

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def borrow_book(self, **params):
        try:
            # Validate input
            if not all(key in params for key in ['book_id', 'member_id']):
                raise ValueError("Missing required parameters")

            book_id = self.validate_id(params['book_id'])
            member_id = self.validate_id(params['member_id'])
            loan_date = datetime.now().strftime('%Y-%m-%d')
            due_date = (datetime.now() + timedelta(days=14)).strftime('%Y-%m-%d')

            cursor = self.conn.cursor()
            
            # Check book availability
            cursor.execute('SELECT available_copies FROM books WHERE book_id = ?', (book_id,))
            result = cursor.fetchone()
            if not result or result[0] <= 0:
                raise ValueError("Book not available for borrowing")
            
            # Check member exists
            cursor.execute('SELECT 1 FROM members WHERE member_id = ?', (member_id,))
            if not cursor.fetchone():
                raise ValueError("Member not found")

            cursor.execute('''
                INSERT INTO loans (book_id, member_id, loan_date, due_date)
                VALUES (?, ?, ?, ?)
            ''', (book_id, member_id, loan_date, due_date))
            
            cursor.execute('''
                UPDATE books SET available_copies = available_copies - 1
                WHERE book_id = ?
            ''', (book_id,))
            
            self.conn.commit()
            return {'status': 'success', 'loan_id': cursor.lastrowid}
        except ValueError as e:
            cherrypy.response.status = 400
            return {'error': str(e)}
        except Exception as e:
            self.conn.rollback()
            cherrypy.response.status = 500
            return {'error': 'Failed to process book loan'}

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def return_book(self, **params):
        try:
            if 'loan_id' not in params:
                raise ValueError("Missing loan_id parameter")

            loan_id = self.validate_id(params['loan_id'])
            return_date = datetime.now().strftime('%Y-%m-%d')

            cursor = self.conn.cursor()
            
            # Get book_id from loan
            cursor.execute('SELECT book_id FROM loans WHERE loan_id = ? AND return_date IS NULL', (loan_id,))
            result = cursor.fetchone()
            if not result:
                raise ValueError("Loan not found or already returned")
            
            book_id = result[0]
            
            cursor.execute('''
                UPDATE loans SET return_date = ?
                WHERE loan_id = ?
            ''', (return_date, loan_id))
            
            cursor.execute('''
                UPDATE books SET available_copies = available_copies + 1
                WHERE book_id = ?
            ''', (book_id,))
            
            self.conn.commit()
            return {'status': 'success'}
        except ValueError as e:
            cherrypy.response.status = 400
            return {'error': str(e)}
        except Exception as e:
            self.conn.rollback()
            cherrypy.response.status = 500
            return {'error': 'Failed to process book return'}

if __name__ == '__main__':
    cherrypy.config.update({
        'server.socket_port': 8080,
        'environment': 'production',  # Disable debug mode
        'tools.sessions.on': True,   # Enable session management
        'tools.sessions.secure': True
    })
    cherrypy.quickstart(LibrarySystem())