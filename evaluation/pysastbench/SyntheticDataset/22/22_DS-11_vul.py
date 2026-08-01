import os
from http.server import BaseHTTPRequestHandler, HTTPServer

class FileServerHandler(BaseHTTPRequestHandler):
    BASE_DIR = os.path.join(os.path.dirname(__file__), 'files')
    
    def do_GET(self):
        if self.path.startswith('/download'):
            file_path = self.path.split('/download/')[-1]
            self.serve_file(file_path)
        else:
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'''
                <html>
                <body>
                    <h1>File Server</h1>
                    <form action="/download" method="get">
                        <input type="text" name="file" placeholder="Filename">
                        <button type="submit">Download</button>
                    </form>
                </body>
                </html>
            ''')

    def serve_file(self, file_path):
        try:
            # Vulnerable path traversal - no sanitization of file_path
            full_path = os.path.join(self.BASE_DIR, file_path)
            
            if not os.path.exists(full_path):
                self.send_error(404, "File not found")
                return
                
            if not os.path.isfile(full_path):
                self.send_error(400, "Not a file")
                return
                
            with open(full_path, 'rb') as f:
                self.send_response(200)
                self.send_header('Content-type', 'application/octet-stream')
                self.send_header('Content-Disposition', f'attachment; filename="{os.path.basename(file_path)}"')
                self.end_headers()
                self.wfile.write(f.read())
                
        except Exception as e:
            self.send_error(500, f"Server error: {str(e)}")

def run_server():
    server_address = ('', 8000)
    httpd = HTTPServer(server_address, FileServerHandler)
    print('Server running on port 8000...')
    httpd.serve_forever()

if __name__ == '__main__':
    if not os.path.exists(FileServerHandler.BASE_DIR):
        os.makedirs(FileServerHandler.BASE_DIR)
        with open(os.path.join(FileServerHandler.BASE_DIR, 'test.txt'), 'w') as f:
            f.write('Sample file content')
    run_server()