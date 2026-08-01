import json
import os
import hashlib
from flask import Flask, request, jsonify, send_file
from werkzeug.utils import secure_filename
import importlib.util
import tempfile
import shutil

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = './uploads'
app.config['PROCESSED_FOLDER'] = './processed'
app.config['PLUGIN_FOLDER'] = './plugins'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['PROCESSED_FOLDER'], exist_ok=True)
os.makedirs(app.config['PLUGIN_FOLDER'], exist_ok=True)

class FileProcessor:
    def __init__(self):
        self.jobs = {}
        self.plugins = {}
        self.allowed_plugin_methods = ['process']

    def _generate_job_id(self, filename):
        return hashlib.sha256(filename.encode()).hexdigest()

    def load_processing_plugin(self, plugin_file):
        try:
            # Create a temporary directory for plugin validation
            with tempfile.TemporaryDirectory() as temp_dir:
                # Save the plugin file temporarily
                temp_path = os.path.join(temp_dir, 'plugin.py')
                plugin_file.save(temp_path)
                
                # Validate the plugin structure
                spec = importlib.util.spec_from_file_location("plugin_module", temp_path)
                plugin_module = importlib.util.module_from_spec(spec)
                
                # Restrict what the plugin can access
                plugin_module.__dict__['__builtins__'] = {
                    'str': str,
                    'bytes': bytes,
                    'len': len,
                    'int': int,
                    'range': range,
                    # Add other safe builtins as needed
                }
                
                spec.loader.exec_module(plugin_module)
                
                # Verify the plugin has the required interface
                if not all(hasattr(plugin_module, method) for method in self.allowed_plugin_methods):
                    raise ValueError("Plugin missing required methods")
                
                # Generate a unique ID for the plugin
                plugin_id = hashlib.md5(open(temp_path, 'rb').read()).hexdigest()
                
                # Move the validated plugin to permanent storage
                final_path = os.path.join(app.config['PLUGIN_FOLDER'], f"{plugin_id}.py")
                shutil.move(temp_path, final_path)
                
                self.plugins[plugin_id] = final_path
                return plugin_id
                
        except Exception as e:
            print(f"Plugin loading failed: {e}")
            return None

    def process_file(self, filepath, plugin_id):
        if plugin_id not in self.plugins:
            return None

        try:
            # Dynamically load the plugin from file
            plugin_path = self.plugins[plugin_id]
            spec = importlib.util.spec_from_file_location("plugin_module", plugin_path)
            plugin_module = importlib.util.module_from_spec(spec)
            
            # Restrict builtins again for safety
            plugin_module.__dict__['__builtins__'] = {
                'str': str,
                'bytes': bytes,
                'len': len,
                'int': int,
                'range': range,
            }
            
            spec.loader.exec_module(plugin_module)
            
            with open(filepath, 'rb') as f:
                file_data = f.read()

            # Execute plugin's processing function
            result = plugin_module.process(file_data)
            
            if not isinstance(result, bytes):
                raise ValueError("Plugin must return bytes")
            
            output_filename = os.path.join(
                app.config['PROCESSED_FOLDER'],
                os.path.basename(filepath) + '.processed'
            )
            with open(output_filename, 'wb') as f:
                f.write(result)
            
            return output_filename
        except Exception as e:
            print(f"File processing failed: {e}")
            return None

processor = FileProcessor()

@app.route('/upload_plugin', methods=['POST'])
def upload_plugin():
    if 'plugin' not in request.files:
        return jsonify({'error': 'No plugin file provided'}), 400

    plugin_file = request.files['plugin']
    if plugin_file.filename == '':
        return jsonify({'error': 'Empty filename'}), 400

    # Validate file extension
    if not plugin_file.filename.endswith('.py'):
        return jsonify({'error': 'Only Python files (.py) are allowed'}), 400

    plugin_id = processor.load_processing_plugin(plugin_file)

    if plugin_id:
        return jsonify({'plugin_id': plugin_id}), 200
    return jsonify({'error': 'Plugin upload failed'}), 400

@app.route('/upload_file', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    if 'plugin_id' not in request.form:
        return jsonify({'error': 'No plugin ID provided'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Empty filename'}), 400

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    processed_file = processor.process_file(filepath, request.form['plugin_id'])
    if processed_file:
        return jsonify({
            'processed_file': os.path.basename(processed_file),
            'download_url': f'/download/{os.path.basename(processed_file)}'
        }), 200
    return jsonify({'error': 'File processing failed'}), 500

@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    filepath = os.path.join(app.config['PROCESSED_FOLDER'], secure_filename(filename))
    if os.path.exists(filepath):
        return send_file(filepath, as_attachment=True)
    return jsonify({'error': 'File not found'}), 404

@app.route('/status', methods=['GET'])
def status():
    return jsonify({
        'plugins_loaded': len(processor.plugins),
        'jobs_processed': len(processor.jobs)
    }), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)