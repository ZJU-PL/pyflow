from fastapi import FastAPI, HTTPException, Query, Depends
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
import sqlite3
import uvicorn
from pydantic import BaseModel
from typing import Optional
import secrets
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi.responses import JSONResponse

app = FastAPI()

# Rate limiting
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

# Security middleware
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["example.com"])  # Replace with your domain
# app.add_middleware(HTTPSRedirectMiddleware)  # Uncomment in production

# Basic Auth (for demonstration, use proper auth in production)
security = HTTPBasic()

class Employee(BaseModel):
    id: int
    name: str
    position: str
    department: str
    salary: float

# Allowed filter types to prevent SQL injection
ALLOWED_FILTER_TYPES = {'name', 'position', 'department'}

def init_db():
    conn = sqlite3.connect('employees.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS employees (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            position TEXT,
            department TEXT,
            salary REAL
        )
    ''')
    conn.commit()
    conn.close()

@app.on_event("startup")
def startup():
    init_db()
    # Add some test data
    conn = sqlite3.connect('employees.db')
    cursor = conn.cursor()
    cursor.executemany('''
        INSERT OR IGNORE INTO employees (id, name, position, department, salary)
        VALUES (?, ?, ?, ?, ?)
    ''', [
        (1, 'John Doe', 'Developer', 'IT', 75000),
        (2, 'Jane Smith', 'Manager', 'HR', 90000),
        (3, 'Bob Johnson', 'Analyst', 'Finance', 80000)
    ])
    conn.commit()
    conn.close()

@app.exception_handler(RateLimitExceeded)
async def rate_limit_exceeded_handler(request, exc):
    return JSONResponse(
        status_code=429,
        content={"detail": "Too many requests"},
        headers={"Retry-After": str(exc.retry_after)}
    )

@app.get("/employees/")
@limiter.limit("100/minute")
async def get_all_employees(credentials: HTTPBasicCredentials = Depends(security)):
    # Verify credentials (in production, use proper authentication)
    correct_username = secrets.compare_digest(credentials.username, "admin")
    correct_password = secrets.compare_digest(credentials.password, "secret")
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=401,
            detail="Incorrect credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    
    conn = sqlite3.connect('employees.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM employees")
    employees = cursor.fetchall()
    conn.close()
    return [dict(zip(['id', 'name', 'position', 'department', 'salary'], emp)) for emp in employees]

@app.get("/employees/filter/")
@limiter.limit("60/minute")
async def get_employee_by_filter(
    filter_type: str = Query(..., description="Filter type (name, position, department)"),
    filter_value: str = Query(..., description="Value to filter by"),
    credentials: HTTPBasicCredentials = Depends(security)
):
    # Verify credentials
    correct_username = secrets.compare_digest(credentials.username, "admin")
    correct_password = secrets.compare_digest(credentials.password, "secret")
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=401,
            detail="Incorrect credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    
    # Validate filter type to prevent SQL injection
    if filter_type not in ALLOWED_FILTER_TYPES:
        raise HTTPException(status_code=400, detail="Invalid filter type")
    
    # Sanitize filter value
    safe_filter_value = filter_value.replace("'", "''")[:100]  # Basic sanitization
    
    conn = sqlite3.connect('employees.db')
    cursor = conn.cursor()
    
    # Use parameterized query with proper column validation
    query = f"SELECT * FROM employees WHERE {filter_type} = ?"
    
    try:
        cursor.execute(query, (safe_filter_value,))
        employees = cursor.fetchall()
        conn.close()
        if not employees:
            raise HTTPException(status_code=404, detail="No employees found")
        return [dict(zip(['id', 'name', 'position', 'department', 'salary'], emp)) for emp in employees]
    except sqlite3.Error as e:
        conn.close()
        raise HTTPException(status_code=400, detail="Database error")
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/employees/")
@limiter.limit("30/minute")
async def add_employee(employee: Employee, credentials: HTTPBasicCredentials = Depends(security)):
    # Verify credentials
    correct_username = secrets.compare_digest(credentials.username, "admin")
    correct_password = secrets.compare_digest(credentials.password, "secret")
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=401,
            detail="Incorrect credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    
    # Validate employee data
    if employee.salary < 0:
        raise HTTPException(status_code=400, detail="Salary cannot be negative")
    if len(employee.name) > 100 or len(employee.position) > 100 or len(employee.department) > 100:
        raise HTTPException(status_code=400, detail="Field values too long")
    
    conn = sqlite3.connect('employees.db')
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO employees (id, name, position, department, salary)
            VALUES (?, ?, ?, ?, ?)
        ''', (employee.id, employee.name, employee.position, employee.department, employee.salary))
        conn.commit()
        conn.close()
        return {"message": "Employee added successfully"}
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail="Employee ID already exists")
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=500, detail="Internal server error")

@app.delete("/employees/{employee_id}")
@limiter.limit("30/minute")
async def delete_employee(employee_id: int, credentials: HTTPBasicCredentials = Depends(security)):
    # Verify credentials
    correct_username = secrets.compare_digest(credentials.username, "admin")
    correct_password = secrets.compare_digest(credentials.password, "secret")
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=401,
            detail="Incorrect credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    
    conn = sqlite3.connect('employees.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM employees WHERE id = ?", (employee_id,))
    conn.commit()
    affected = cursor.rowcount
    conn.close()
    if affected == 0:
        raise HTTPException(status_code=404, detail="Employee not found")
    return {"message": "Employee deleted successfully"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)