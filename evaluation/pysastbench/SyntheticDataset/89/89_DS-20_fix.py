import cherrypy
import sqlite3
import json
from datetime import datetime

class ReportSystem:
    def __init__(self):
        self.init_db()

    def init_db(self):
        conn = sqlite3.connect('reports.db')
        c = conn.cursor()
        
        c.execute('''CREATE TABLE IF NOT EXISTS departments
                     (id INTEGER PRIMARY KEY,
                     name TEXT NOT NULL)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS employees
                     (id INTEGER PRIMARY KEY,
                     name TEXT NOT NULL,
                     department_id INTEGER,
                     salary REAL,
                     FOREIGN KEY(department_id) REFERENCES departments(id))''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS reports
                     (id INTEGER PRIMARY KEY,
                     title TEXT NOT NULL,
                     content TEXT,
                     created_by INTEGER,
                     created_at DATETIME,
                     FOREIGN KEY(created_by) REFERENCES employees(id))''')
        
        # Insert sample data if empty
        c.execute("SELECT COUNT(*) FROM departments")
        if c.fetchone()[0] == 0:
            departments = [(1, 'HR'), (2, 'Engineering'), (3, 'Finance')]
            c.executemany("INSERT INTO departments VALUES (?, ?)", departments)
            
            employees = [
                (1, 'Alice Smith', 1, 65000),
                (2, 'Bob Johnson', 2, 85000),
                (3, 'Carol Williams', 3, 75000)
            ]
            c.executemany("INSERT INTO employees VALUES (?, ?, ?, ?)", employees)
            
            reports = [
                (1, 'Q1 Hiring Report', 'Hired 5 new engineers', 1, '2023-01-15'),
                (2, 'System Upgrade', 'Updated all servers', 2, '2023-02-20')
            ]
            c.executemany("INSERT INTO reports VALUES (?, ?, ?, ?, ?)", reports)
            
            conn.commit()
        conn.close()

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def create_report(self, **params):
        try:
            title = params['title']
            content = params['content']
            created_by = int(params['created_by'])
            
            conn = sqlite3.connect('reports.db')
            c = conn.cursor()
            c.execute(
                "INSERT INTO reports (title, content, created_by, created_at) VALUES (?, ?, ?, ?)",
                (title, content, created_by, datetime.now())
            )
            report_id = c.lastrowid
            conn.commit()
            conn.close()
            return {'status': 'success', 'report_id': report_id}
        except Exception as e:
            raise cherrypy.HTTPError(400, str(e))

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def get_report(self, report_id):
        conn = sqlite3.connect('reports.db')
        c = conn.cursor()
        c.execute(
            "SELECT r.id, r.title, r.content, e.name as author, r.created_at "
            "FROM reports r JOIN employees e ON r.created_by = e.id "
            "WHERE r.id = ?",
            (report_id,)
        )
        report = c.fetchone()
        conn.close()
        
        if report:
            return {
                'id': report[0],
                'title': report[1],
                'content': report[2],
                'author': report[3],
                'created_at': report[4]
            }
        raise cherrypy.HTTPError(404, "Report not found")

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def generate_report(self, **params):
        department = params.get('department')
        start_date = params.get('start_date')
        end_date = params.get('end_date')
        
        conn = sqlite3.connect('reports.db')
        c = conn.cursor()
        
        # Fixed: Using parameterized queries to prevent SQL injection
        query = """SELECT r.id, r.title, e.name as author, d.name as department, r.created_at 
                   FROM reports r 
                   JOIN employees e ON r.created_by = e.id 
                   JOIN departments d ON e.department_id = d.id """
        
        conditions = []
        query_params = []
        
        if department:
            conditions.append("d.name = ?")
            query_params.append(department)
        if start_date:
            conditions.append("r.created_at >= ?")
            query_params.append(start_date)
        if end_date:
            conditions.append("r.created_at <= ?")
            query_params.append(end_date)
        
        if conditions:
            query += "WHERE " + " AND ".join(conditions)
        
        query += " ORDER BY r.created_at DESC"
        
        c.execute(query, query_params)
        reports = []
        for row in c.fetchall():
            reports.append({
                'id': row[0],
                'title': row[1],
                'author': row[2],
                'department': row[3],
                'created_at': row[4]
            })
        
        conn.close()
        return {'reports': reports}

if __name__ == '__main__':
    cherrypy.quickstart(ReportSystem(), '/', {
        '/': {
            'tools.response_headers.on': True,
            'tools.response_headers.headers': [('Content-Type', 'application/json')]
        }
    })