import os
import json
from flask import Flask, request, jsonify, render_template, abort
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['CONFIG_DIR'] = os.path.abspath('/etc/app_configs')
app.config['TEMPLATE_DIR'] = os.path.abspath(os.path.join(os.path.dirname(__file__), 'templates'))
app.config['MAX_CONFIG_SIZE'] = 1024 * 1024  # 1MB config size limit

class ConfigManager:
    def __init__(self):
        os.makedirs(app.config['CONFIG_DIR'], mode=0o750, exist_ok=True)
    
    def is_safe_path(self, path):
        """Validate path is within CONFIG_DIR"""
        base_path = os.path.abspath(app.config['CONFIG_DIR'])
        requested_path = os.path.abspath(path)
        return requested_path.startswith(base_path + os.sep)
    
    def list_configs(self):
        try:
            return [f for f in os.listdir(app.config['CONFIG_DIR']) 
                   if f.endswith('.json') and
                   self.is_safe_path(os.path.join(app.config['CONFIG_DIR'], f))]
        except Exception as e:
            app.logger.error(f"Error listing configs: {e}")
            return []
    
    def load_config(self, config_name):
        try:
            # Validate and secure filename
            if not config_name or not isinstance(config_name, str):
                raise ValueError("Invalid config name")
            
            safe_name = secure_filename(config_name)
            if not safe_name.endswith('.json'):
                raise ValueError("Only JSON config files are supported")
                
            config_path = os.path.join(app.config['CONFIG_DIR'], safe_name)
            
            # Validate path is safe
            if not self.is_safe_path(config_path):
                raise PermissionError("Access denied")
                
            if not os.path.exists(config_path):
                raise FileNotFoundError(f"Config {safe_name} not found")
                
            # Check file size before reading
            if os.path.getsize(config_path) > app.config['MAX_CONFIG_SIZE']:
                raise ValueError("Config file too large")
                
            with open(config_path, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            raise ValueError("Invalid JSON format")
    
    def save_config(self, config_name, config_data):
        try:
            # Validate and secure filename
            if not config_name or not isinstance(config_name, str):
                raise ValueError("Invalid config name")
            
            safe_name = secure_filename(config_name)
            if not safe_name.endswith('.json'):
                raise ValueError("Config must be a JSON file")
                
            config_path = os.path.join(app.config['CONFIG_DIR'], safe_name)
            
            # Validate path is safe
            if not self.is_safe_path(config_path):
                raise PermissionError("Access denied")
                
            # Validate config data
            if not isinstance(config_data, dict):
                raise ValueError("Config data must be a dictionary")
                
            # Secure dump with no HTML escaping
            with open(config_path, 'w') as f:
                json.dump(config_data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            app.logger.error(f"Error saving config: {e}")
            raise

@app.route('/api/config/<config_name>', methods=['GET'])
def get_config(config_name):
    try:
        manager = ConfigManager()
        config = manager.load_config(config_name)
        return jsonify(config)
    except FileNotFoundError:
        return jsonify({'error': 'Config not found'}), 404
    except PermissionError:
        return jsonify({'error': 'Access denied'}), 403
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception:
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/config', methods=['POST'])
def create_config():
    try:
        if not request.is_json:
            return jsonify({'error': 'Request must be JSON'}), 400
            
        config_name = request.json.get('name')
        config_data = request.json.get('data')
        
        if not config_name or not config_data:
            return jsonify({'error': 'Missing name or data'}), 400
            
        manager = ConfigManager()
        manager.save_config(config_name, config_data)
        return jsonify({'status': 'success'})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except PermissionError:
        return jsonify({'error': 'Access denied'}), 403
    except Exception:
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/')
def index():
    try:
        manager = ConfigManager()
        configs = manager.list_configs()
        return render_template('config_manager.html', configs=configs)
    except Exception:
        abort(500)

@app.route('/view/<config_name>')
def view_config(config_name):
    try:
        manager = ConfigManager()
        config = manager.load_config(config_name)
        return render_template('view_config.html', 
                            config_name=secure_filename(config_name),
                            config_data=config)
    except FileNotFoundError:
        abort(404, 'Config not found')
    except PermissionError:
        abort(403, 'Access denied')
    except ValueError as e:
        abort(400, str(e))
    except Exception:
        abort(500, 'Internal server error')

if __name__ == '__main__':
    # Create directories with secure permissions
    os.makedirs(app.config['CONFIG_DIR'], mode=0o750, exist_ok=True)
    os.makedirs(app.config['TEMPLATE_DIR'], mode=0o750, exist_ok=True)
    
    # Create sample configs with validation
    sample_configs = {
        'database.json': {'host': 'localhost', 'port': 5432},
        'app_settings.json': {'debug': False, 'timeout': 30}
    }
    
    for name, data in sample_configs.items():
        path = os.path.join(app.config['CONFIG_DIR'], name)
        if not os.path.exists(path):
            try:
                with open(path, 'w') as f:
                    json.dump(data, f, indent=2)
                os.chmod(path, 0o640)  # Secure permissions
            except Exception as e:
                app.logger.error(f"Error creating sample config {name}: {e}")
    
    # Create basic templates
    templates = {
        'config_manager.html': '''
            <h1>Config Manager</h1>
            <ul>{% for config in configs %}
                <li><a href="/view/{{ config }}">{{ config }}</a></li>
            {% endfor %}</ul>
        ''',
        'view_config.html': '''
            <h1>Config: {{ config_name }}</h1>
            <pre>{{ config_data }}</pre>
        '''
    }
    
    for name, content in templates.items():
        path = os.path.join(app.config['TEMPLATE_DIR'], name)
        if not os.path.exists(path):
            try:
                with open(path, 'w') as f:
                    f.write(content)
                os.chmod(path, 0o640)  # Secure permissions
            except Exception as e:
                app.logger.error(f"Error creating template {name}: {e}")
    
    app.run(host='0.0.0.0', port=8080)