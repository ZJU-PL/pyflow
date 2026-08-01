from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.responses import JSONResponse
import sqlite3
import uvicorn
from pydantic import BaseModel
import re

app = FastAPI()

def get_db():
    conn = sqlite3.connect('employees.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS departments (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS employees (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            department_id INTEGER,
            salary REAL,
            FOREIGN KEY (department_id) REFERENCES departments(id)
        )
    ''')
    conn.commit()
    conn.close()

class EmployeeCreate(BaseModel):
    name: str
    email: str
    department_id: int
    salary: float

class DepartmentCreate(BaseModel):
    name: str

def validate_email(email: str) -> str:
    """Validate email format"""
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        raise ValueError("Invalid email format")
    return email

def validate_salary(salary: float) -> float:
    """Validate salary is positive"""
    if salary <= 0:
        raise ValueError("Salary must be positive")
    return salary

def sanitize_search_term(term: str) -> str:
    """Sanitize search input to prevent SQL injection"""
    if not term:
        return ""
    return re.sub(r'[;\'"\\]', '', term)

@app.post("/departments/")
def create_department(department: DepartmentCreate, db: sqlite3.Connection = Depends(get_db)):
    if not department.name.strip():
        raise HTTPException(status_code=400, detail="Department name cannot be empty")
    
    cursor = db.cursor()
    try:
        cursor.execute("INSERT INTO departments (name) VALUES (?)", (department.name,))
        db.commit()
        return {"message": "Department created successfully"}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Department already exists")
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to create department")

@app.post("/employees/")
def create_employee(employee: EmployeeCreate, db: sqlite3.Connection = Depends(get_db)):
    try:
        # Validate inputs
        validate_email(employee.email)
        validate_salary(employee.salary)
        
        # Check department exists
        cursor = db.cursor()
        cursor.execute("SELECT 1 FROM departments WHERE id = ?", (employee.department_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=400, detail="Department does not exist")
        
        cursor.execute(
            "INSERT INTO employees (name, email, department_id, salary) VALUES (?, ?, ?, ?)",
            (employee.name, employee.email, employee.department_id, employee.salary)
        )
        db.commit()
        return {"message": "Employee created successfully"}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Email already exists")
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to create employee")

@app.get("/employees/search/")
def search_employees(request: Request, db: sqlite3.Connection = Depends(get_db)):
    search_query = sanitize_search_term(request.query_params.get("query", ""))
    
    if not search_query:
        raise HTTPException(status_code=400, detail="Search query parameter is required")

    cursor = db.cursor()
    
    # Fixed SQL injection using parameterized query
    query = """
        SELECT * FROM employees 
        WHERE name LIKE ? OR email LIKE ?
    """
    cursor.execute(query, (f"%{search_query}%", f"%{search_query}%"))
    
    employees = []
    for row in cursor.fetchall():
        employees.append(dict(row))
    
    return JSONResponse(content=employees)

@app.get("/employees/{employee_id}")
def get_employee(employee_id: int, db: sqlite3.Connection = Depends(get_db)):
    cursor = db.cursor()
    cursor.execute("SELECT * FROM employees WHERE id = ?", (employee_id,))
    employee = cursor.fetchone()
    if not employee:
        raise HTTPException(status_code=404, detail="Employee not found")
    return dict(employee)

@app.delete("/employees/{employee_id}")
def delete_employee(employee_id: int, db: sqlite3.Connection = Depends(get_db)):
    cursor = db.cursor()
    cursor.execute("DELETE FROM employees WHERE id = ?", (employee_id,))
    db.commit()
    if cursor.rowcount == 0:
        raise HTTPException(status_code=404, detail="Employee not found")
    return {"message": "Employee deleted successfully"}

if __name__ == "__main__":
    init_db()
    uvicorn.run(app, host="0.0.0.0", port=8000)