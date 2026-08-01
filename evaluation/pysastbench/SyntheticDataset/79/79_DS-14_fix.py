from fastapi import FastAPI, UploadFile, Form, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import os
import sqlite3
import uuid
from typing import List
from pathlib import Path
import html
import re

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Configuration
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
UPLOAD_DIR = "uploads"

# Database setup
def init_db():
    conn = sqlite3.connect('file_storage.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS files
                 (id TEXT PRIMARY KEY,
                 filename TEXT,
                 description TEXT,
                 uploader TEXT,
                 path TEXT)''')
    conn.commit()
    conn.close()

init_db()

def save_file_info(file_id: str, filename: str, description: str, uploader: str, path: str):
    # Sanitize inputs before storage
    sanitized_desc = html.escape(description)
    sanitized_uploader = html.escape(uploader)
    
    conn = sqlite3.connect('file_storage.db')
    c = conn.cursor()
    c.execute("INSERT INTO files VALUES (?, ?, ?, ?, ?)",
              (file_id, filename, sanitized_desc, sanitized_uploader, path))
    conn.commit()
    conn.close()

def get_all_files():
    conn = sqlite3.connect('file_storage.db')
    c = conn.cursor()
    c.execute("SELECT id, filename, description, uploader FROM files")
    files = c.fetchall()
    conn.close()
    return files

def get_file(file_id: str):
    conn = sqlite3.connect('file_storage.db')
    c = conn.cursor()
    c.execute("SELECT * FROM files WHERE id=?", (file_id,))
    file = c.fetchone()
    conn.close()
    return file

def is_allowed_file(filename: str):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def sanitize_filename(filename: str):
    # Remove any path components and special characters
    filename = Path(filename).name
    return re.sub(r'[^\w\.-]', '_', filename)

# Routes
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    files = get_all_files()
    return templates.TemplateResponse("index.html", {"request": request, "files": files})

@app.post("/upload")
async def upload_file(
    request: Request,
    file: UploadFile,
    description: str = Form(...),
    uploader: str = Form(...)
):
    # Validate file
    if not file:
        raise HTTPException(status_code=400, detail="No file uploaded")
    
    if not is_allowed_file(file.filename):
        raise HTTPException(status_code=400, detail="File type not allowed")
    
    # Create upload directory if it doesn't exist
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    
    # Sanitize filename
    safe_filename = sanitize_filename(file.filename)
    file_id = str(uuid.uuid4())
    file_path = os.path.join(UPLOAD_DIR, f"{file_id}_{safe_filename}")
    
    # Save file with size limit
    try:
        contents = await file.read()
        if len(contents) > MAX_FILE_SIZE:
            raise HTTPException(status_code=413, detail="File too large")
        
        with open(file_path, "wb") as buffer:
            buffer.write(contents)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
    save_file_info(file_id, safe_filename, description, uploader, file_path)
    
    return {"message": "File uploaded successfully", "file_id": file_id}

@app.get("/file/{file_id}", response_class=HTMLResponse)
async def view_file(request: Request, file_id: str):
    file = get_file(file_id)
    if not file:
        raise HTTPException(status_code=404, detail="File not found")
    
    return templates.TemplateResponse("file.html", {
        "request": request,
        "file_id": file[0],
        "filename": file[1],
        "description": file[2],  # Already escaped in storage
        "uploader": file[3],     # Already escaped in storage
        "file_path": file[4]
    })

# HTML Templates
if not os.path.exists("templates"):
    os.makedirs("templates")

with open("templates/index.html", "w") as f:
    f.write('''
<!DOCTYPE html>
<html>
<head>
    <title>File Storage</title>
</head>
<body>
    <h1>File Storage System</h1>
    <form action="/upload" method="post" enctype="multipart/form-data">
        <input type="file" name="file" required><br>
        Description: <input type="text" name="description" required><br>
        Your Name: <input type="text" name="uploader" required><br>
        <button type="submit">Upload</button>
    </form>
    <h2>Uploaded Files</h2>
    <ul>
        {% for file in files %}
            <li>
                <a href="/file/{{ file[0] }}">{{ file[1] }}</a>
                (Uploaded by {{ file[3] }})
                <p>{{ file[2] }}</p>
            </li>
        {% endfor %}
    </ul>
</body>
</html>
''')

with open("templates/file.html", "w") as f:
    f.write('''
<!DOCTYPE html>
<html>
<head>
    <title>{{ filename }}</title>
</head>
<body>
    <h1>{{ filename }}</h1>
    <p>Uploaded by: {{ uploader }}</p>
    <div>
        <h3>Description:</h3>
        <div>{{ description }}</div>  <!-- Removed | safe filter -->
    </div>
    <a href="/">Back to files</a>
</body>
</html>
''')

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)