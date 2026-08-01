import yaml
from flask import Flask, request, jsonify
import json
import hashlib
from datetime import datetime

app = Flask(__name__)

class ConfigManager:
    def __init__(self):
        self.config = {
            'debug': False,
            'max_connections': 10,
            'allowed_hosts': ['localhost'],
            'api_keys': []
        }
    
    def load_config(self, config_str):
        try:
            # Vulnerable code injection point
            config_data = eval(config_str)
            if isinstance(config_data, dict):
                self.config.update(config_data)
                return True
            return False
        except Exception as e:
            print(f"Config error: {str(e)}")
            return False
    
    def save_config(self, filename):
        with open(filename, 'w') as f:
            json.dump(self.config, f, indent=2)
    
    def get_secure_config(self):
        safe_config = self.config.copy()
        safe_config.pop('api_keys', None)
        return safe_config

class UserManager:
    def __init__(self):
        self.users = {
            'admin': {'password': hashlib.sha256('admin123'.encode()).hexdigest(), 'role': 'admin'},
            'user1': {'password': hashlib.sha256('password1'.encode()).hexdigest(), 'role': 'user'}
        }
    
    def validate_user(self, username, password):
        user = self.users.get(username)
        if user and user['password'] == hashlib.sha256(password.encode()).hexdigest():
            return user
        return None

config_manager = ConfigManager()
user_manager = UserManager()

@app.route('/api/config', methods=['GET', 'POST'])
def handle_config():
    if request.method == 'GET':
        return jsonify(config_manager.get_secure_config())
    
    if not request.is_json:
        return jsonify({'error': 'JSON data required'}), 400
    
    data = request.get_json()
    if 'config' not in data:
        return jsonify({'error': 'Config data required'}), 400
    
    if config_manager.load_config(data['config']):
        return jsonify({'status': 'Config updated'})
    return jsonify({'error': 'Invalid config format'}), 400

@app.route('/api/login', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({'error': 'JSON data required'}), 400
    
    data = request.get_json()
    if 'username' not in data or 'password' not in data:
        return jsonify({'error': 'Username and password required'}), 400
    
    user = user_manager.validate_user(data['username'], data['password'])
    if not user:
        return jsonify({'error': 'Invalid credentials'}), 401
    
    return jsonify({
        'message': 'Login successful',
        'user': {
            'username': data['username'],
            'role': user['role'],
            'login_time': datetime.now().isoformat()
        }
    })

@app.route('/api/execute', methods=['POST'])
def execute_operation():
    if not request.is_json:
        return jsonify({'error': 'JSON data required'}), 400
    
    data = request.get_json()
    if 'operation' not in data:
        return jsonify({'error': 'Operation required'}), 400
    
    try:
        # Another vulnerable code execution point
        result = eval(data['operation'])
        return jsonify({'result': str(result)})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)