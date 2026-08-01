import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import unquote

class FileServerHandler(BaseHTTPRequestHandler):
    BASE_DIR = "./files"
    
    def do_GET(self):
        try:
            if self.path.startswith("/download"):
                file_path = unquote(self.path.split("/download/")[1])
                self.serve_file(file_path)
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"Not Found")
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(str(e).encode())

    def serve_file(self, file_path):
        # Sanitize the file path to prevent directory traversal
        try:
            # Normalize path and ensure it's within BASE_DIR
            full_path = os.path.abspath(os.path.join(self.BASE_DIR, file_path))
            if not full_path.startswith(os.path.abspath(self.BASE_DIR)):
                raise ValueError("Access denied")
            
            if not os.path.exists(full_path):
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"File not found")
                return
                
            if os.path.isdir(full_path):
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Directory listing not allowed")
                return
                
            with open(full_path, "rb") as f:
                content = f.read()
                
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", f"attachment; filename={os.path.basename(file_path)}")
            self.end_headers()
            self.wfile.write(content)
            
        except ValueError as e:
            self.send_response(403)
            self.end_headers()
            self.wfile.write(str(e).encode())
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(str(e).encode())

def run_server(port=8000):
    server_address = ("", port)
    httpd = HTTPServer(server_address, FileServerHandler)
    print(f"Server running on port {port}")
    httpd.serve_forever()

if __name__ == "__main__":
    os.makedirs("./files", exist_ok=True)
    # Create a test file
    with open("./files/test.txt", "w") as f:
        f.write("Sample file content")
    
    run_server()