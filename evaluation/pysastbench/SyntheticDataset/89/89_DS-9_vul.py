from sanic import Sanic, response
from sanic.response import json
import sqlite3
import datetime
from dateutil.parser import parse

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

@app.route('/records/search', methods=['GET'])
async def search_patient_records(request):
    first_name = request.args.get('first_name', '')
    last_name = request.args.get('last_name', '')
    diagnosis = request.args.get('diagnosis', '')
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')
    
    conn = sqlite3.connect('medical.db')
    cursor = conn.cursor()
    
    # Vulnerable SQL injection - direct string interpolation with multiple parameters
    query = f"""
        SELECT p.patient_id, p.first_name, p.last_name, p.dob, 
               r.visit_date, r.diagnosis, r.treatment, r.physician
        FROM patients p
        JOIN records r ON p.patient_id = r.patient_id
        WHERE p.first_name LIKE '%{first_name}%' 
        AND p.last_name LIKE '%{last_name}%'
    """
    
    if diagnosis:
        query += f" AND r.diagnosis LIKE '%{diagnosis}%'"
    if start_date:
        query += f" AND r.visit_date >= '{start_date}'"
    if end_date:
        query += f" AND r.visit_date <= '{end_date}'"
    
    try:
        cursor.execute(query)
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
        conn.close()
        return json({'error': str(e)}, status=500)

@app.route('/records/add', methods=['POST'])
async def add_patient_record(request):
    try:
        data = request.json
        conn = sqlite3.connect('medical.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO records (patient_id, visit_date, diagnosis, treatment, physician)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            data['patient_id'],
            data['visit_date'],
            data['diagnosis'],
            data['treatment'],
            data['physician']
        ))
        
        conn.commit()
        record_id = cursor.lastrowid
        conn.close()
        return json({'record_id': record_id})
    except Exception as e:
        return json({'error': str(e)}, status=400)

@app.route('/patients/register', methods=['POST'])
async def register_patient(request):
    try:
        data = request.json
        conn = sqlite3.connect('medical.db')
        cursor = conn.cursor()
        
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
        return json({'error': str(e)}, status=400)

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=8000)