from fastapi import FastAPI, HTTPException, Request, Form, Depends
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import sqlite3
import uvicorn
from typing import Optional
import re

app = FastAPI()
templates = Jinja2Templates(directory="templates")

# Safe list of allowed sort columns
ALLOWED_SORT_COLUMNS = ['id', 'username', 'email']
ALLOWED_ORDERS = ['ASC', 'DESC']

def init_db():
    conn = sqlite3.connect('user_profiles.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, 
                 username TEXT UNIQUE, 
                 email TEXT, 
                 full_name TEXT, 
                 credit_card TEXT)''')
    
    # Add test data if empty
    c.execute("SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        test_users = [
            (1, 'jdoe', 'jdoe@example.com', 'John Doe', '4111111111111111'),
            (2, 'asmith', 'asmith@example.com', 'Alice Smith', '5555555555554444'),
            (3, 'bjones', 'bjones@example.com', 'Bob Jones', '378282246310005')
        ]
        c.executemany("INSERT INTO users VALUES (?, ?, ?, ?, ?)", test_users)
        conn.commit()
    conn.close()

def get_db_connection():
    conn = sqlite3.connect('user_profiles.db')
    conn.row_factory = sqlite3.Row
    return conn

def sanitize_search_input(input_str: Optional[str]) -> Optional[str]:
    """Sanitize search input to prevent SQL injection"""
    if not input_str:
        return None
    return re.sub(r'[;\'"\\]', '', input_str)

@app.on_event("startup")
async def startup():
    init_db()

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("home.html", {"request": request})

@app.post("/search", response_class=HTMLResponse)
async def search_users(
    request: Request,
    username: Optional[str] = Form(None),
    email: Optional[str] = Form(None)
):
    # Sanitize inputs
    username = sanitize_search_input(username)
    email = sanitize_search_input(email)
    
    conn = get_db_connection()
    query = "SELECT id, username, email FROM users WHERE 1=1"
    params = []
    
    if username:
        query += " AND username LIKE ?"
        params.append(f"%{username}%")
    if email:
        query += " AND email LIKE ?"
        params.append(f"%{email}%")
    
    try:
        users = conn.execute(query, params).fetchall()
        return templates.TemplateResponse(
            "search_results.html",
            {"request": request, "users": users}
        )
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail="Database error")
    finally:
        conn.close()

@app.get("/admin/users", response_class=HTMLResponse)
async def admin_view(
    request: Request,
    sort_by: str = "id",
    order: str = "ASC"
):
    # Validate sort parameters against safe list
    if sort_by not in ALLOWED_SORT_COLUMNS:
        sort_by = "id"
    if order not in ALLOWED_ORDERS:
        order = "ASC"
    
    conn = get_db_connection()
    # Safe parameterized query with validated inputs
    query = f"SELECT id, username, email FROM users ORDER BY {sort_by} {order}"
    
    try:
        users = conn.execute(query).fetchall()
        return templates.TemplateResponse(
            "admin.html",
            {"request": request, "users": users}
        )
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail="Database error")
    finally:
        conn.close()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)