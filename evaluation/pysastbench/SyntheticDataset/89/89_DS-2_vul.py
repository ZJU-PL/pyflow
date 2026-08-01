from fastapi import FastAPI, HTTPException, Query
import sqlite3
import uvicorn
from pydantic import BaseModel

app = FastAPI()

class Employee(BaseModel):
    id: int
    name: str
    position: str
    department: str
    salary: float

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

@app.get("/employees/")
def get_all_employees():
    conn = sqlite3.connect('employees.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM employees")
    employees = cursor.fetchall()
    conn.close()
    return [dict(zip(['id', 'name', 'position', 'department', 'salary'], emp)) for emp in employees]

@app.get("/employees/filter/")
def get_employee_by_filter(
    filter_type: str = Query(..., description="Filter type (name, position, department)"),
    filter_value: str = Query(..., description="Value to filter by")
):
    conn = sqlite3.connect('employees.db')
    cursor = conn.cursor()
    
    # Vulnerable SQL injection - direct string interpolation
    query = f"SELECT * FROM employees WHERE {filter_type} = '{filter_value}'"
    
    try:
        cursor.execute(query)
        employees = cursor.fetchall()
        conn.close()
        if not employees:
            raise HTTPException(status_code=404, detail="No employees found")
        return [dict(zip(['id', 'name', 'position', 'department', 'salary'], emp)) for emp in employees]
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/employees/")
def add_employee(employee: Employee):
    conn = sqlite3.connect('employees.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO employees (id, name, position, department, salary)
        VALUES (?, ?, ?, ?, ?)
    ''', (employee.id, employee.name, employee.position, employee.department, employee.salary))
    conn.commit()
    conn.close()
    return {"message": "Employee added successfully"}

@app.delete("/employees/{employee_id}")
def delete_employee(employee_id: int):
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