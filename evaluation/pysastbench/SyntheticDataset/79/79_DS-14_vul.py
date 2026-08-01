from fastapi import FastAPI, UploadFile, Form, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import os
import sqlite3
import uuid
from typing import List

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

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
    conn = sqlite3.connect('file_storage.db')
    c = conn.cursor()
    c.execute("INSERT INTO files VALUES (?, ?, ?, ?, ?)",
              (file_id, filename, description, uploader, path))
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
    if not os.path.exists("uploads"):
        os.makedirs("uploads")
    
    file_id = str(uuid.uuid4())
    file_path = f"uploads/{file_id}_{file.filename}"
    
    with open(file_path, "wb") as buffer:
        buffer.write(await file.read())
    
    # Vulnerable function - stores raw user input without sanitization
    save_file_info(file_id, file.filename, description, uploader, file_path)
    
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
        "description": file[2],
        "uploader": file[3],
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
        <div>{{ description | safe }}</div>  <!-- XSS vulnerability here -->
    </div>
    <a href="/">Back to files</a>
</body>
</html>
''')

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)