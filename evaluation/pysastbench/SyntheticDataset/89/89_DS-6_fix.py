import tornado.ioloop
import tornado.web
import sqlite3
import json
from datetime import datetime
import re

class BankApplication:
    def __init__(self):
        self.conn = sqlite3.connect('bank.db')
        self.init_db()

    def init_db(self):
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS accounts (
                account_id INTEGER PRIMARY KEY,
                customer_name TEXT NOT NULL,
                balance REAL DEFAULT 0,
                account_type TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS transactions (
                transaction_id INTEGER PRIMARY KEY,
                account_id INTEGER NOT NULL,
                amount REAL NOT NULL,
                transaction_type TEXT NOT NULL,
                description TEXT,
                timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(account_id) REFERENCES accounts(account_id)
            )
        ''')
        
        # Insert sample data if empty
        cursor.execute("SELECT COUNT(*) FROM accounts")
        if cursor.fetchone()[0] == 0:
            cursor.executemany('''
                INSERT INTO accounts (customer_name, balance, account_type)
                VALUES (?, ?, ?)
            ''', [
                ('John Smith', 5000.0, 'checking'),
                ('Alice Johnson', 12000.0, 'savings'),
                ('Bob Williams', 750.0, 'checking')
            ])
            cursor.executemany('''
                INSERT INTO transactions (account_id, amount, transaction_type, description)
                VALUES (?, ?, ?, ?)
            ''', [
                (1, 500.0, 'deposit', 'Initial deposit'),
                (1, -50.0, 'withdrawal', 'ATM withdrawal'),
                (2, 1000.0, 'deposit', 'Paycheck deposit')
            ])
        self.conn.commit()

    def validate_account_id(self, account_id):
        """Validate account ID is a positive integer"""
        if not account_id or not account_id.isdigit():
            raise ValueError("Invalid account ID")
        return int(account_id)

    def validate_date(self, date_str):
        """Validate date format (YYYY-MM-DD)"""
        if not re.match(r'^\d{4}-\d{2}-\d{2}$', date_str):
            raise ValueError("Invalid date format. Use YYYY-MM-DD")
        return date_str

class AccountHandler(tornado.web.RequestHandler):
    def initialize(self, bank_app):
        self.bank = bank_app

    def get(self):
        try:
            account_id = self.bank.validate_account_id(self.get_argument('account_id'))
            cursor = self.bank.conn.cursor()
            
            # Fixed SQL injection using parameterized query
            query = "SELECT * FROM accounts WHERE account_id = ?"
            
            cursor.execute(query, (account_id,))
            account = cursor.fetchone()
            if account:
                self.write({
                    'account_id': account[0],
                    'customer_name': account[1],
                    'balance': account[2],
                    'account_type': account[3],
                    'created_at': account[4]
                })
            else:
                self.set_status(404)
                self.write({'error': 'Account not found'})
        except ValueError as e:
            self.set_status(400)
            self.write({'error': str(e)})
        except Exception as e:
            self.set_status(500)
            self.write({'error': 'Internal server error'})

class TransactionHandler(tornado.web.RequestHandler):
    def initialize(self, bank_app):
        self.bank = bank_app

    def get(self):
        try:
            account_id = self.bank.validate_account_id(self.get_argument('account_id'))
            start_date = self.get_argument('start_date', None)
            end_date = self.get_argument('end_date', None)
            
            # Validate dates if provided
            if start_date:
                start_date = self.bank.validate_date(start_date)
            if end_date:
                end_date = self.bank.validate_date(end_date)
            
            cursor = self.bank.conn.cursor()
            
            # Fixed SQL injection using parameterized queries
            query = "SELECT * FROM transactions WHERE account_id = ?"
            params = [account_id]
            
            if start_date:
                query += " AND timestamp >= ?"
                params.append(start_date)
            if end_date:
                query += " AND timestamp <= ?"
                params.append(end_date)
            
            cursor.execute(query, params)
            transactions = []
            for row in cursor.fetchall():
                transactions.append({
                    'transaction_id': row[0],
                    'amount': row[2],
                    'type': row[3],
                    'description': row[4],
                    'timestamp': row[5]
                })
            self.write({'transactions': transactions})
        except ValueError as e:
            self.set_status(400)
            self.write({'error': str(e)})
        except Exception as e:
            self.set_status(500)
            self.write({'error': 'Internal server error'})

    def post(self):
        try:
            data = json.loads(self.request.body)
            
            # Validate required fields
            if not all(key in data for key in ['account_id', 'amount', 'type']):
                raise ValueError("Missing required fields")
            
            # Validate account ID
            account_id = self.bank.validate_account_id(str(data['account_id']))
            
            # Validate amount is numeric and positive
            try:
                amount = float(data['amount'])
                if amount <= 0:
                    raise ValueError("Amount must be positive")
            except ValueError:
                raise ValueError("Invalid amount")
            
            # Validate transaction type
            if data['type'] not in ['deposit', 'withdrawal']:
                raise ValueError("Invalid transaction type")
            
            cursor = self.bank.conn.cursor()
            
            # Check account exists
            cursor.execute("SELECT 1 FROM accounts WHERE account_id = ?", (account_id,))
            if not cursor.fetchone():
                raise ValueError("Account not found")
            
            # Check sufficient balance for withdrawals
            if data['type'] == 'withdrawal':
                cursor.execute("SELECT balance FROM accounts WHERE account_id = ?", (account_id,))
                balance = cursor.fetchone()[0]
                if balance < amount:
                    raise ValueError("Insufficient funds")
            
            # Insert transaction
            cursor.execute('''
                INSERT INTO transactions (account_id, amount, transaction_type, description)
                VALUES (?, ?, ?, ?)
            ''', (account_id, amount, data['type'], data.get('description', '')))
            
            # Update account balance
            if data['type'] == 'deposit':
                cursor.execute('''
                    UPDATE accounts SET balance = balance + ? WHERE account_id = ?
                ''', (amount, account_id))
            else:
                cursor.execute('''
                    UPDATE accounts SET balance = balance - ? WHERE account_id = ?
                ''', (amount, account_id))
            
            self.bank.conn.commit()
            self.write({'status': 'success', 'transaction_id': cursor.lastrowid})
        except ValueError as e:
            self.set_status(400)
            self.write({'error': str(e)})
        except Exception as e:
            self.bank.conn.rollback()
            self.set_status(500)
            self.write({'error': 'Transaction failed'})

def make_app():
    bank_app = BankApplication()
    return tornado.web.Application([
        (r"/account", AccountHandler, dict(bank_app=bank_app)),
        (r"/transactions", TransactionHandler, dict(bank_app=bank_app))
    ])

if __name__ == "__main__":
    app = make_app()
    app.listen(8888)
    tornado.ioloop.IOLoop.current().start()