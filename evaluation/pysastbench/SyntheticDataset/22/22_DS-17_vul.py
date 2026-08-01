import os
import json
from flask import Flask, request, jsonify, render_template, abort

app = Flask(__name__)
app.config['CONFIG_DIR'] = '/etc/app_configs'
app.config['TEMPLATE_DIR'] = os.path.join(os.path.dirname(__file__), 'templates')

class ConfigManager:
    def __init__(self):
        if not os.path.exists(app.config['CONFIG_DIR']):
            os.makedirs(app.config['CONFIG_DIR'])
    
    def list_configs(self):
        return [f for f in os.listdir(app.config['CONFIG_DIR']) 
               if f.endswith('.json')]
    
    def load_config(self, config_name):
        # Vulnerable path traversal - no proper sanitization of config_name
        config_path = os.path.join(app.config['CONFIG_DIR'], config_name)
        
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Config {config_name} not found")
            
        if not config_path.endswith('.json'):
            raise ValueError("Only JSON config files are supported")
            
        with open(config_path, 'r') as f:
            return json.load(f)
    
    def save_config(self, config_name, config_data):
        config_path = os.path.join(app.config['CONFIG_DIR'], config_name)
        
        if not config_name.endswith('.json'):
            raise ValueError("Config must be a JSON file")
            
        with open(config_path, 'w') as f:
            json.dump(config_data, f, indent=2)

@app.route('/api/config/<config_name>', methods=['GET'])
def get_config(config_name):
    try:
        manager = ConfigManager()
        config = manager.load_config(config_name)
        return jsonify(config)
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/config', methods=['POST'])
def create_config():
    try:
        config_name = request.json.get('name')
        config_data = request.json.get('data')
        
        if not config_name or not config_data:
            return jsonify({'error': 'Missing name or data'}), 400
            
        manager = ConfigManager()
        manager.save_config(config_name, config_data)
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/')
def index():
    manager = ConfigManager()
    configs = manager.list_configs()
    return render_template('config_manager.html', configs=configs)

@app.route('/view/<config_name>')
def view_config(config_name):
    try:
        manager = ConfigManager()
        config = manager.load_config(config_name)
        return render_template('view_config.html', 
                            config_name=config_name,
                            config_data=config)
    except Exception as e:
        abort(400, str(e))

if __name__ == '__main__':
    # Create sample config directory and files
    os.makedirs(app.config['CONFIG_DIR'], exist_ok=True)
    os.makedirs(app.config['TEMPLATE_DIR'], exist_ok=True)
    
    sample_configs = {
        'database.json': {'host': 'localhost', 'port': 5432},
        'app_settings.json': {'debug': True, 'timeout': 30}
    }
    
    for name, data in sample_configs.items():
        path = os.path.join(app.config['CONFIG_DIR'], name)
        if not os.path.exists(path):
            with open(path, 'w') as f:
                json.dump(data, f, indent=2)
    
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
            with open(path, 'w') as f:
                f.write(content)
    
    app.run(host='0.0.0.0', port=8080)