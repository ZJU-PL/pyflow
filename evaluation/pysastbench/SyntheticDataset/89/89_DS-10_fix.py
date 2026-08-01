from quart import Quart, request, jsonify
import sqlite3
import uuid
from datetime import datetime
import re

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

def validate_customer_id(customer_id):
    """Validate customer ID format"""
    if not re.match(r'^CUST-\d{4}$', customer_id):
        raise ValueError("Invalid customer ID format")
    return customer_id

def validate_ticket_id(ticket_id):
    """Validate ticket ID format"""
    if not re.match(r'^TICKET-\d{4}$', ticket_id):
        raise ValueError("Invalid ticket ID format")
    return ticket_id

def validate_priority(priority):
    """Validate priority is between 1 and 5"""
    try:
        priority = int(priority)
        if priority < 1 or priority > 5:
            raise ValueError("Priority must be between 1 and 5")
        return priority
    except ValueError:
        raise ValueError("Invalid priority value")

def validate_status(status):
    """Validate ticket status"""
    if status.lower() not in ['open', 'in_progress', 'resolved', 'closed']:
        raise ValueError("Invalid status value")
    return status.lower()

def sanitize_search_term(term):
    """Sanitize search term to prevent SQL injection"""
    if not term:
        return ""
    return re.sub(r'[;\'"\\]', '', term)

@app.route('/tickets/search', methods=['GET'])
async def search_tickets():
    try:
        search_term = sanitize_search_term(request.args.get('q', ''))
        status = request.args.get('status', '')
        priority = request.args.get('priority', '')
        customer_id = request.args.get('customer_id', '')

        # Validate inputs
        if status:
            status = validate_status(status)
        if priority:
            priority = validate_priority(priority)
        if customer_id:
            customer_id = validate_customer_id(customer_id)

        conn = sqlite3.connect('support.db')
        cursor = conn.cursor()

        # Fixed SQL injection using parameterized queries
        query = """
            SELECT t.ticket_id, t.subject, t.status, t.priority, t.created_at, 
                   c.name as customer_name, c.email as customer_email
            FROM tickets t
            JOIN customers c ON t.customer_id = c.customer_id
            WHERE (t.subject LIKE ? OR t.description LIKE ?)
        """
        params = [f"%{search_term}%", f"%{search_term}%"]

        if status:
            query += " AND t.status = ?"
            params.append(status)
        if priority:
            query += " AND t.priority = ?"
            params.append(priority)
        if customer_id:
            query += " AND t.customer_id = ?"
            params.append(customer_id)

        cursor.execute(query, params)
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
    except ValueError as e:
        return await jsonify({'error': str(e)}), 400
    except Exception as e:
        conn.close() if 'conn' in locals() else None
        return await jsonify({'error': 'Internal server error'}), 500

@app.route('/tickets/create', methods=['POST'])
async def create_ticket():
    try:
        data = await request.get_json()
        # Validate required fields
        required_fields = ['customer_id', 'subject', 'description']
        if not all(field in data for field in required_fields):
            return await jsonify({'error': 'Missing required fields'}), 400

        # Validate inputs
        customer_id = validate_customer_id(data['customer_id'])
        priority = validate_priority(data.get('priority', 3))

        # Validate subject and description length
        if len(data['subject']) > 200:
            return await jsonify({'error': 'Subject too long'}), 400
        if len(data['description']) > 2000:
            return await jsonify({'error': 'Description too long'}), 400

        conn = sqlite3.connect('support.db')
        cursor = conn.cursor()

        # Check customer exists
        cursor.execute('SELECT 1 FROM customers WHERE customer_id = ?', (customer_id,))
        if not cursor.fetchone():
            conn.close()
            return await jsonify({'error': 'Customer not found'}), 404

        ticket_id = f"TICKET-{str(uuid.uuid4())[:4].upper()}"
        cursor.execute('''
            INSERT INTO tickets (ticket_id, customer_id, subject, description, priority)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            ticket_id,
            customer_id,
            data['subject'],
            data['description'],
            priority
        ))

        conn.commit()
        conn.close()
        return await jsonify({'ticket_id': ticket_id}), 201
    except ValueError as e:
        return await jsonify({'error': str(e)}), 400
    except Exception as e:
        conn.close() if 'conn' in locals() else None
        return await jsonify({'error': 'Failed to create ticket'}), 500

@app.route('/tickets/<ticket_id>/respond', methods=['POST'])
async def add_response(ticket_id):
    try:
        data = await request.get_json()
        # Validate required fields
        if not all(field in data for field in ['responder', 'message']):
            return await jsonify({'error': 'Missing required fields'}), 400

        # Validate inputs
        ticket_id = validate_ticket_id(ticket_id)
        if len(data['responder']) > 100:
            return await jsonify({'error': 'Responder name too long'}), 400
        if len(data['message']) > 2000:
            return await jsonify({'error': 'Message too long'}), 400

        conn = sqlite3.connect('support.db')
        cursor = conn.cursor()

        # Check ticket exists
        cursor.execute('SELECT 1 FROM tickets WHERE ticket_id = ?', (ticket_id,))
        if not cursor.fetchone():
            conn.close()
            return await jsonify({'error': 'Ticket not found'}), 404

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
    except ValueError as e:
        return await jsonify({'error': str(e)}), 400
    except Exception as e:
        conn.close() if 'conn' in locals() else None
        return await jsonify({'error': 'Failed to add response'}), 500

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=8000, debug=False)  # Disable debug in production