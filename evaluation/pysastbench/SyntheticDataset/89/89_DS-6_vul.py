import tornado.ioloop
import tornado.web
import sqlite3
import json
from datetime import datetime

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

class AccountHandler(tornado.web.RequestHandler):
    def initialize(self, bank_app):
        self.bank = bank_app

    def get(self):
        account_id = self.get_argument('account_id')
        cursor = self.bank.conn.cursor()
        
        # Vulnerable SQL injection - direct string interpolation
        query = f"SELECT * FROM accounts WHERE account_id = {account_id}"
        
        try:
            cursor.execute(query)
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
        except Exception as e:
            self.set_status(500)
            self.write({'error': str(e)})

class TransactionHandler(tornado.web.RequestHandler):
    def initialize(self, bank_app):
        self.bank = bank_app

    def get(self):
        account_id = self.get_argument('account_id')
        start_date = self.get_argument('start_date', None)
        end_date = self.get_argument('end_date', None)
        cursor = self.bank.conn.cursor()
        
        # Vulnerable SQL injection - multiple injection points
        query = f"SELECT * FROM transactions WHERE account_id = {account_id}"
        
        if start_date:
            query += f" AND timestamp >= '{start_date}'"
        if end_date:
            query += f" AND timestamp <= '{end_date}'"
        
        try:
            cursor.execute(query)
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
        except Exception as e:
            self.set_status(500)
            self.write({'error': str(e)})

    def post(self):
        try:
            data = json.loads(self.request.body)
            cursor = self.bank.conn.cursor()
            cursor.execute('''
                INSERT INTO transactions (account_id, amount, transaction_type, description)
                VALUES (?, ?, ?, ?)
            ''', (data['account_id'], data['amount'], data['type'], data.get('description', '')))
            
            # Update account balance
            if data['type'] == 'deposit':
                cursor.execute('''
                    UPDATE accounts SET balance = balance + ? WHERE account_id = ?
                ''', (data['amount'], data['account_id']))
            else:
                cursor.execute('''
                    UPDATE accounts SET balance = balance - ? WHERE account_id = ?
                ''', (data['amount'], data['account_id']))
            
            self.bank.conn.commit()
            self.write({'status': 'success', 'transaction_id': cursor.lastrowid})
        except Exception as e:
            self.set_status(400)
            self.write({'error': str(e)})

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