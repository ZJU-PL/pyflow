import os
import posixpath
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import unquote

class FileServerHandler(BaseHTTPRequestHandler):
    BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), 'files'))
    ALLOWED_EXTENSIONS = {'.txt', '.pdf', '.docx'}  # Restrict to safe file types
    
    def is_safe_path(self, path):
        """Check if the path is within the allowed directory"""
        # Normalize and resolve the path
        requested_path = os.path.normpath(os.path.join(self.BASE_DIR, path))
        # Ensure it's within BASE_DIR and doesn't contain any traversal
        return (os.path.commonpath([requested_path, self.BASE_DIR]) == self.BASE_DIR and
                not os.path.islink(requested_path))  # Prevent symlink attacks

    def sanitize_filename(self, filename):
        """Sanitize the filename and check extension"""
        if not filename:
            return None
        filename = os.path.basename(filename)  # Remove any path components
        _, ext = os.path.splitext(filename)
        return filename if ext.lower() in self.ALLOWED_EXTENSIONS else None

    def do_GET(self):
        if self.path.startswith('/download'):
            try:
                # Parse the file path safely
                file_path = unquote(self.path.split('/download/')[-1])
                safe_filename = self.sanitize_filename(file_path)
                if not safe_filename:
                    self.send_error(400, "Invalid file type")
                    return
                self.serve_file(safe_filename)
            except IndexError:
                self.send_error(400, "Invalid request")
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
                    <p>Allowed file types: %s</p>
                </body>
                </html>
            ''' % ', '.join(self.ALLOWED_EXTENSIONS).encode())

    def serve_file(self, filename):
        try:
            full_path = os.path.join(self.BASE_DIR, filename)
            
            if not self.is_safe_path(filename):
                self.send_error(403, "Access denied")
                return
                
            if not os.path.exists(full_path):
                self.send_error(404, "File not found")
                return
                
            if not os.path.isfile(full_path):
                self.send_error(400, "Not a file")
                return
                
            # Check file size before serving
            file_size = os.path.getsize(full_path)
            if file_size > 10 * 1024 * 1024:  # 10MB limit
                self.send_error(413, "File too large")
                return

            with open(full_path, 'rb') as f:
                self.send_response(200)
                self.send_header('Content-type', 'application/octet-stream')
                self.send_header('Content-Disposition', 
                               f'attachment; filename="{filename}"')
                self.send_header('Content-Length', str(file_size))
                self.end_headers()
                
                # Stream the file in chunks instead of reading all at once
                chunk_size = 8192
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                
        except PermissionError:
            self.send_error(403, "Permission denied")
        except Exception:
            self.send_error(500, "Internal server error")

def run_server():
    server_address = ('', 8000)
    httpd = HTTPServer(server_address, FileServerHandler)
    print('Server running on port 8000...')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        httpd.server_close()

if __name__ == '__main__':
    if not os.path.exists(FileServerHandler.BASE_DIR):
        os.makedirs(FileServerHandler.BASE_DIR, mode=0o750)  # Secure directory permissions
        with open(os.path.join(FileServerHandler.BASE_DIR, 'test.txt'), 'w') as f:
            f.write('Sample file content')
    run_server()