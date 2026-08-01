from fastapi import FastAPI, HTTPException, Query
import sqlite3
import uuid
from datetime import datetime
from typing import Optional
from pydantic import BaseModel

app = FastAPI()

class Case(BaseModel):
    case_id: str
    title: str
    description: str
    status: str
    client_id: str
    assigned_to: str
    created_at: str

def init_db():
    conn = sqlite3.connect('legal_cases.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS clients (
            client_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            contact_email TEXT UNIQUE NOT NULL,
            phone TEXT,
            address TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS attorneys (
            attorney_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            specialization TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cases (
            case_id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            status TEXT DEFAULT 'open',
            client_id TEXT NOT NULL,
            assigned_to TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            closed_at TEXT,
            FOREIGN KEY(client_id) REFERENCES clients(client_id),
            FOREIGN KEY(assigned_to) REFERENCES attorneys(attorney_id)
        )
    ''')
    
    # Insert sample data if empty
    cursor.execute("SELECT COUNT(*) FROM clients")
    if cursor.fetchone()[0] == 0:
        cursor.executemany('''
            INSERT INTO clients (client_id, name, contact_email, phone, address)
            VALUES (?, ?, ?, ?, ?)
        ''', [
            ('CLI-1001', 'Acme Corp', 'legal@acme.com', '555-1001', '123 Business Ave'),
            ('CLI-1002', 'Smith Family', 'smith.family@example.com', '555-1002', '456 Residential St')
        ])
        cursor.executemany('''
            INSERT INTO attorneys (attorney_id, name, email, specialization)
            VALUES (?, ?, ?, ?)
        ''', [
            ('ATT-1001', 'Robert Johnson', 'r.johnson@lawfirm.com', 'Corporate'),
            ('ATT-1002', 'Sarah Williams', 's.williams@lawfirm.com', 'Family')
        ])
        cursor.executemany('''
            INSERT INTO cases (case_id, title, description, status, client_id, assigned_to)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', [
            ('CASE-1001', 'Acme Merger', 'Review merger documents', 'open', 'CLI-1001', 'ATT-1001'),
            ('CASE-1002', 'Smith Divorce', 'Divorce proceedings', 'active', 'CLI-1002', 'ATT-1002')
        ])
    conn.commit()
    conn.close()

@app.get("/cases/search", response_model=list[Case])
def search_cases(
    query: Optional[str] = Query(None, description="Search term for case title or description"),
    status: Optional[str] = Query(None, description="Filter by case status"),
    client_id: Optional[str] = Query(None, description="Filter by client ID"),
    assigned_to: Optional[str] = Query(None, description="Filter by assigned attorney")
):
    conn = sqlite3.connect('legal_cases.db')
    cursor = conn.cursor()
    
    # Vulnerable SQL injection - dynamic query construction with direct interpolation
    base_query = """
        SELECT c.case_id, c.title, c.description, c.status, 
               c.client_id, c.assigned_to, c.created_at
        FROM cases c
        WHERE 1=1
    """
    
    if query:
        base_query += f" AND (c.title LIKE '%{query}%' OR c.description LIKE '%{query}%')"
    if status:
        base_query += f" AND c.status = '{status}'"
    if client_id:
        base_query += f" AND c.client_id = '{client_id}'"
    if assigned_to:
        base_query += f" AND c.assigned_to = '{assigned_to}'"
    
    try:
        cursor.execute(base_query)
        cases = []
        for row in cursor.fetchall():
            cases.append(Case(
                case_id=row[0],
                title=row[1],
                description=row[2],
                status=row[3],
                client_id=row[4],
                assigned_to=row[5],
                created_at=row[6]
            ))
        conn.close()
        return cases
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/cases/create")
def create_case(case: Case):
    try:
        conn = sqlite3.connect('legal_cases.db')
        cursor = conn.cursor()
        
        case_id = f"CASE-{str(uuid.uuid4())[:4].upper()}"
        cursor.execute('''
            INSERT INTO cases (case_id, title, description, status, client_id, assigned_to)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            case_id,
            case.title,
            case.description,
            case.status,
            case.client_id,
            case.assigned_to
        ))
        
        conn.commit()
        conn.close()
        return {"case_id": case_id}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.put("/cases/{case_id}/update-status")
def update_case_status(case_id: str, new_status: str):
    try:
        conn = sqlite3.connect('legal_cases.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE cases 
            SET status = ?, closed_at = ?
            WHERE case_id = ?
        ''', (
            new_status,
            datetime.now().isoformat() if new_status == 'closed' else None,
            case_id
        ))
        
        conn.commit()
        affected = cursor.rowcount
        conn.close()
        if affected == 0:
            raise HTTPException(status_code=404, detail="Case not found")
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    init_db()
    uvicorn.run(app, host="0.0.0.0", port=8000)