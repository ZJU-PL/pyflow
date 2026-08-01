import pickle
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

class AnalyticsConfig:
    def __init__(self):
        self.tracking_id = ""
        self.endpoints = []
        self.filters = {}
    
    def load_from_pickle(self, config_data):
        try:
            # Restrict allowed classes during unpickling
            safe_classes = {'AnalyticsConfig': AnalyticsConfig}
            def restricted_unpickler(pickle_data):
                import copyreg
                import builtins
                safe_builtins = {
                    'object': object,
                    'dict': dict,
                    'list': list,
                    'str': str,
                }
                
                def safe_find_class(module, name):
                    if module == '__main__':
                        if name in safe_classes:
                            return safe_classes[name]
                    elif module == 'builtins':
                        if name in safe_builtins:
                            return safe_builtins[name]
                    raise pickle.UnpicklingError(f"Attempt to unpickle unsafe class {module}.{name}")
                
                unpickler = pickle.Unpickler(pickle_data)
                unpickler.find_class = safe_find_class
                return unpickler.load()
            
            config = restricted_unpickler(config_data)
            self.tracking_id = config.tracking_id
            self.endpoints = config.endpoints
            self.filters = config.filters
            return True
        except Exception as e:
            print(f"Error loading config: {e}")
            return False

class AnalyticsService:
    def __init__(self):
        self.config = AnalyticsConfig()
        self.analytics_data = []
    
    def process_config_upload(self, config_file):
        if not config_file:
            return False
        
        # Now uses safe deserialization
        success = self.config.load_from_pickle(config_file)
        if success:
            print("Config loaded successfully!")
            return True
        return False
    
    def record_event(self, event_data):
        if not self.validate_event(event_data):
            return False
        self.analytics_data.append(event_data)
        return True
    
    def validate_event(self, event_data):
        required_fields = ['user_id', 'event_type', 'timestamp']
        return all(field in event_data for field in required_fields)

class RequestHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.analytics = AnalyticsService()
        super().__init__(*args, **kwargs)
    
    def do_POST(self):
        if self.path == '/upload_config':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            
            if self.analytics.process_config_upload(post_data):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'Config uploaded successfully')
            else:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b'Failed to upload config')
        
        elif self.path == '/record':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            event_data = json.loads(post_data.decode())
            
            if self.analytics.record_event(event_data):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'Event recorded')
            else:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b'Invalid event data')
        
        else:
            self.send_response(404)
            self.end_headers()

def run_server():
    port = 8080
    server_address = ('', port)
    httpd = HTTPServer(server_address, RequestHandler)
    print(f'Starting analytics server on port {port}...')
    httpd.serve_forever()

if __name__ == '__main__':
    run_server()