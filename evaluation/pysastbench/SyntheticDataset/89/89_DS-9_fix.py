from sanic import Sanic, response
from sanic.response import json
import sqlite3
import datetime
from dateutil.parser import parse
import re

app = Sanic("MedicalRecordsSystem")

def init_db():
    conn = sqlite3.connect('medical.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS patients (
            patient_id INTEGER PRIMARY KEY,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            dob TEXT NOT NULL,
            ssn TEXT UNIQUE NOT NULL,
            insurance_id TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS records (
            record_id INTEGER PRIMARY KEY,
            patient_id INTEGER NOT NULL,
            visit_date TEXT NOT NULL,
            diagnosis TEXT,
            treatment TEXT,
            physician TEXT,
            FOREIGN KEY(patient_id) REFERENCES patients(patient_id)
        )
    ''')
    
    # Insert sample data if empty
    cursor.execute("SELECT COUNT(*) FROM patients")
    if cursor.fetchone()[0] == 0:
        cursor.executemany('''
            INSERT INTO patients (first_name, last_name, dob, ssn, insurance_id)
            VALUES (?, ?, ?, ?, ?)
        ''', [
            ('John', 'Smith', '1980-05-15', '123-45-6789', 'INS123456'),
            ('Sarah', 'Johnson', '1975-11-22', '987-65-4321', 'INS789012'),
            ('Michael', 'Williams', '1990-02-10', '456-78-9012', 'INS345678')
        ])
        cursor.executemany('''
            INSERT INTO records (patient_id, visit_date, diagnosis, treatment, physician)
            VALUES (?, ?, ?, ?, ?)
        ''', [
            (1, '2023-01-10', 'Hypertension', 'Prescribed medication', 'Dr. Anderson'),
            (1, '2023-03-15', 'Annual checkup', 'Routine tests', 'Dr. Brown'),
            (2, '2023-02-20', 'Diabetes', 'Insulin therapy', 'Dr. Carter')
        ])
    conn.commit()
    conn.close()

def validate_name(name):
    """Validate name contains only letters and basic punctuation"""
    if not re.match(r'^[a-zA-Z\-\'\s]{1,50}$', name):
        raise ValueError("Invalid name format")
    return name

def validate_date(date_str):
    """Validate date format (YYYY-MM-DD)"""
    try:
        datetime.datetime.strptime(date_str, '%Y-%m-%d')
        return date_str
    except ValueError:
        raise ValueError("Invalid date format. Use YYYY-MM-DD")

def validate_ssn(ssn):
    """Validate SSN format (digits only)"""
    if not re.match(r'^\d{3}-\d{2}-\d{4}$', ssn):
        raise ValueError("Invalid SSN format. Use XXX-XX-XXXX")
    return ssn

def sanitize_input(input_str):
    """Sanitize input to prevent SQL injection"""
    if not input_str:
        return ""
    return re.sub(r'[;\'"\\]', '', input_str)

@app.route('/records/search', methods=['GET'])
async def search_patient_records(request):
    try:
        first_name = sanitize_input(request.args.get('first_name', ''))
        last_name = sanitize_input(request.args.get('last_name', ''))
        diagnosis = sanitize_input(request.args.get('diagnosis', ''))
        start_date = request.args.get('start_date', '')
        end_date = request.args.get('end_date', '')

        conn = sqlite3.connect('medical.db')
        cursor = conn.cursor()
        
        # Fixed SQL injection using parameterized queries
        query = """
            SELECT p.patient_id, p.first_name, p.last_name, p.dob, 
                   r.visit_date, r.diagnosis, r.treatment, r.physician
            FROM patients p
            JOIN records r ON p.patient_id = r.patient_id
            WHERE p.first_name LIKE ?
            AND p.last_name LIKE ?
        """
        params = [f"%{first_name}%", f"%{last_name}%"]
        
        if diagnosis:
            query += " AND r.diagnosis LIKE ?"
            params.append(f"%{diagnosis}%")
        if start_date:
            try:
                validate_date(start_date)
                query += " AND r.visit_date >= ?"
                params.append(start_date)
            except ValueError as e:
                conn.close()
                return json({'error': str(e)}, status=400)
        if end_date:
            try:
                validate_date(end_date)
                query += " AND r.visit_date <= ?"
                params.append(end_date)
            except ValueError as e:
                conn.close()
                return json({'error': str(e)}, status=400)
        
        cursor.execute(query, params)
        records = []
        for row in cursor.fetchall():
            records.append({
                'patient_id': row[0],
                'patient_name': f"{row[1]} {row[2]}",
                'dob': row[3],
                'visit_date': row[4],
                'diagnosis': row[5],
                'treatment': row[6],
                'physician': row[7]
            })
        conn.close()
        return json({'records': records})
    except Exception as e:
        conn.close() if 'conn' in locals() else None
        return json({'error': 'Internal server error'}, status=500)

@app.route('/records/add', methods=['POST'])
async def add_patient_record(request):
    try:
        data = request.json
        # Validate required fields
        if not all(key in data for key in ['patient_id', 'visit_date', 'diagnosis', 'physician']):
            return json({'error': 'Missing required fields'}, status=400)
        
        # Validate input
        try:
            validate_date(data['visit_date'])
            if not str(data['patient_id']).isdigit():
                raise ValueError("Invalid patient ID")
        except ValueError as e:
            return json({'error': str(e)}, status=400)
            
        conn = sqlite3.connect('medical.db')
        cursor = conn.cursor()
        
        # Check patient exists
        cursor.execute('SELECT 1 FROM patients WHERE patient_id = ?', (data['patient_id'],))
        if not cursor.fetchone():
            conn.close()
            return json({'error': 'Patient not found'}, status=404)
        
        cursor.execute('''
            INSERT INTO records (patient_id, visit_date, diagnosis, treatment, physician)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            data['patient_id'],
            data['visit_date'],
            data['diagnosis'],
            data.get('treatment', ''),
            data['physician']
        ))
        
        conn.commit()
        record_id = cursor.lastrowid
        conn.close()
        return json({'record_id': record_id})
    except Exception as e:
        conn.close() if 'conn' in locals() else None
        return json({'error': 'Failed to add record'}, status=500)

@app.route('/patients/register', methods=['POST'])
async def register_patient(request):
    try:
        data = request.json
        # Validate required fields
        required_fields = ['first_name', 'last_name', 'dob', 'ssn']
        if not all(key in data for key in required_fields):
            return json({'error': 'Missing required fields'}, status=400)
        
        # Validate input
        try:
            validate_name(data['first_name'])
            validate_name(data['last_name'])
            validate_date(data['dob'])
            validate_ssn(data['ssn'])
        except ValueError as e:
            return json({'error': str(e)}, status=400)
            
        conn = sqlite3.connect('medical.db')
        cursor = conn.cursor()
        
        # Check SSN uniqueness
        cursor.execute('SELECT 1 FROM patients WHERE ssn = ?', (data['ssn'],))
        if cursor.fetchone():
            conn.close()
            return json({'error': 'SSN already registered'}, status=400)
        
        cursor.execute('''
            INSERT INTO patients (first_name, last_name, dob, ssn, insurance_id)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            data['first_name'],
            data['last_name'],
            data['dob'],
            data['ssn'],
            data.get('insurance_id', '')
        ))
        
        conn.commit()
        patient_id = cursor.lastrowid
        conn.close()
        return json({'patient_id': patient_id})
    except Exception as e:
        conn.close() if 'conn' in locals() else None
        return json({'error': 'Failed to register patient'}, status=500)

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=8000, access_log=False)  # Disable access log in production