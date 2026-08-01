from quart import Quart, request, jsonify
import sqlite3
import uuid
from datetime import datetime

app = Quart(__name__)

def init_db():
    conn = sqlite3.connect('support.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS customers (
            customer_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            phone TEXT,
            registration_date TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tickets (
            ticket_id TEXT PRIMARY KEY,
            customer_id TEXT NOT NULL,
            subject TEXT NOT NULL,
            description TEXT NOT NULL,
            status TEXT DEFAULT 'open',
            priority INTEGER DEFAULT 3,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            resolved_at TEXT,
            FOREIGN KEY(customer_id) REFERENCES customers(customer_id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS responses (
            response_id TEXT PRIMARY KEY,
            ticket_id TEXT NOT NULL,
            responder TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(ticket_id) REFERENCES tickets(ticket_id)
        )
    ''')

    # Insert sample data if empty
    cursor.execute("SELECT COUNT(*) FROM customers")
    if cursor.fetchone()[0] == 0:
        customers = [
            ('CUST-1001', 'Alice Johnson', 'alice@example.com', '555-0101'),
            ('CUST-1002', 'Bob Smith', 'bob@example.com', '555-0102'),
            ('CUST-1003', 'Charlie Brown', 'charlie@example.com', '555-0103')
        ]
        cursor.executemany('''
            INSERT INTO customers (customer_id, name, email, phone)
            VALUES (?, ?, ?, ?)
        ''', customers)

        tickets = [
            ('TICKET-1001', 'CUST-1001', 'Login issues', 'Cannot login to my account', 'open', 2),
            ('TICKET-1002', 'CUST-1002', 'Payment problem', 'Payment not processed', 'resolved', 1),
            ('TICKET-1003', 'CUST-1003', 'Feature request', 'Add dark mode', 'open', 3)
        ]
        cursor.executemany('''
            INSERT INTO tickets (ticket_id, customer_id, subject, description, status, priority)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', tickets)
    conn.commit()
    conn.close()

@app.route('/tickets/search', methods=['GET'])
async def search_tickets():
    search_term = request.args.get('q', '')
    status = request.args.get('status', '')
    priority = request.args.get('priority', '')
    customer_id = request.args.get('customer_id', '')

    conn = sqlite3.connect('support.db')
    cursor = conn.cursor()

    # Vulnerable SQL injection - dynamic query construction with direct interpolation
    query = """
        SELECT t.ticket_id, t.subject, t.status, t.priority, t.created_at, 
               c.name as customer_name, c.email as customer_email
        FROM tickets t
        JOIN customers c ON t.customer_id = c.customer_id
        WHERE (t.subject LIKE '%{search_term}%' OR t.description LIKE '%{search_term}%')
    """.format(search_term=search_term)

    if status:
        query += f" AND t.status = '{status}'"
    if priority:
        query += f" AND t.priority = {priority}"
    if customer_id:
        query += f" AND t.customer_id = '{customer_id}'"

    try:
        cursor.execute(query)
        tickets = []
        for row in cursor.fetchall():
            tickets.append({
                'ticket_id': row[0],
                'subject': row[1],
                'status': row[2],
                'priority': row[3],
                'created_at': row[4],
                'customer_name': row[5],
                'customer_email': row[6]
            })
        conn.close()
        return await jsonify({'tickets': tickets})
    except Exception as e:
        conn.close()
        return await jsonify({'error': str(e)}), 500

@app.route('/tickets/create', methods=['POST'])
async def create_ticket():
    try:
        data = await request.get_json()
        conn = sqlite3.connect('support.db')
        cursor = conn.cursor()

        ticket_id = f"TICKET-{str(uuid.uuid4())[:4].upper()}"
        cursor.execute('''
            INSERT INTO tickets (ticket_id, customer_id, subject, description, priority)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            ticket_id,
            data['customer_id'],
            data['subject'],
            data['description'],
            data.get('priority', 3)
        ))

        conn.commit()
        conn.close()
        return await jsonify({'ticket_id': ticket_id}), 201
    except Exception as e:
        return await jsonify({'error': str(e)}), 400

@app.route('/tickets/<ticket_id>/respond', methods=['POST'])
async def add_response(ticket_id):
    try:
        data = await request.get_json()
        conn = sqlite3.connect('support.db')
        cursor = conn.cursor()

        response_id = f"RESP-{str(uuid.uuid4())[:4].upper()}"
        cursor.execute('''
            INSERT INTO responses (response_id, ticket_id, responder, message)
            VALUES (?, ?, ?, ?)
        ''', (
            response_id,
            ticket_id,
            data['responder'],
            data['message']
        ))

        conn.commit()
        conn.close()
        return await jsonify({'response_id': response_id}), 201
    except Exception as e:
        return await jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=8000)