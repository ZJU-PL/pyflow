import falcon
import json
import uuid
from datetime import datetime
from wsgiref import simple_server
import html  # Import the html module for escaping

class ReportStorage:
    def __init__(self):
        self.reports = {}
    
    def create_report(self, title, content, author):
        report_id = str(uuid.uuid4())
        self.reports[report_id] = {
            'id': report_id,
            'title': title,
            'content': content,
            'author': author,
            'created_at': datetime.now().isoformat()
        }
        return report_id
    
    def get_report(self, report_id):
        return self.reports.get(report_id)
    
    def get_all_reports(self):
        return list(self.reports.values())

report_storage = ReportStorage()

class ReportResource:
    def on_get(self, req, resp, report_id=None):
        if report_id:
            report = report_storage.get_report(report_id)
            if report:
                # Fixed function - now properly escapes HTML content
                def render_report_html(report):
                    escaped_title = html.escape(report['title'])
                    escaped_author = html.escape(report['author'])
                    escaped_created_at = html.escape(report['created_at'])
                    escaped_content = html.escape(report['content'])
                    
                    return f"""
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <title>{escaped_title}</title>
                        <style>
                            .report {{ max-width: 800px; margin: 0 auto; }}
                            .report-header {{ border-bottom: 1px solid #eee; padding-bottom: 10px; }}
                            .report-content {{ margin-top: 20px; }}
                        </style>
                    </head>
                    <body>
                        <div class="report">
                            <div class="report-header">
                                <h1>{escaped_title}</h1>
                                <p>By {escaped_author} | Created at {escaped_created_at}</p>
                            </div>
                            <div class="report-content">
                                {escaped_content}
                            </div>
                        </div>
                    </body>
                    </html>
                    """
                
                resp.content_type = 'text/html'
                resp.text = render_report_html(report)
            else:
                resp.status = falcon.HTTP_404
        else:
            resp.media = report_storage.get_all_reports()
    
    def on_post(self, req, resp):
        try:
            data = json.loads(req.stream.read().decode('utf-8'))
            report_id = report_storage.create_report(
                data['title'],
                data['content'],
                data.get('author', 'Anonymous')
            )
            resp.media = {'id': report_id}
        except Exception as e:
            raise falcon.HTTPBadRequest('Invalid request', str(e))

class ReportFormResource:
    def on_get(self, req, resp):
        resp.content_type = 'text/html'
        resp.text = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Create New Report</title>
        </head>
        <body>
            <h1>Create New Report</h1>
            <form id="reportForm">
                <label>Title: <input type="text" name="title" required></label><br>
                <label>Content (HTML): <textarea name="content" required></textarea></label><br>
                <label>Author: <input type="text" name="author"></label><br>
                <button type="submit">Create Report</button>
            </form>
            <div id="result"></div>
            <script>
                document.getElementById('reportForm').addEventListener('submit', async (e) => {
                    e.preventDefault();
                    const formData = {
                        title: e.target.title.value,
                        content: e.target.content.value,
                        author: e.target.author.value || 'Anonymous'
                    };
                    
                    const response = await fetch('/reports', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(formData)
                    });
                    
                    const result = await response.json();
                    document.getElementById('result').innerHTML = 
                        `Report created! <a href="/reports/${result.id}">View report</a>`;
                });
            </script>
        </body>
        </html>
        """

app = falcon.App()
app.add_route('/reports', ReportResource())
app.add_route('/reports/{report_id}', ReportResource())
app.add_route('/create-report', ReportFormResource())

if __name__ == '__main__':
    httpd = simple_server.make_server('0.0.0.0', 8000, app)
    httpd.serve_forever()