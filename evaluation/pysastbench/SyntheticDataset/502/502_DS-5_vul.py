import pickle
import json
import os
import hashlib
from flask import Flask, request, jsonify, send_file
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = './uploads'
app.config['PROCESSED_FOLDER'] = './processed'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['PROCESSED_FOLDER'], exist_ok=True)

class FileProcessor:
    def __init__(self):
        self.jobs = {}
        self.plugins = {}

    def _generate_job_id(self, filename):
        return hashlib.sha256(filename.encode()).hexdigest()

    def load_processing_plugin(self, plugin_data):
        try:
            # Vulnerable deserialization - accepts arbitrary pickled plugins
            plugin = pickle.loads(plugin_data)
            plugin_id = hashlib.md5(plugin_data).hexdigest()
            self.plugins[plugin_id] = plugin
            return plugin_id
        except Exception as e:
            print(f"Plugin loading failed: {e}")
            return None

    def process_file(self, filepath, plugin_id):
        if plugin_id not in self.plugins:
            return None

        try:
            plugin = self.plugins[plugin_id]
            with open(filepath, 'rb') as f:
                file_data = f.read()

            # Execute plugin's processing function
            result = plugin.process(file_data)
            
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

    plugin_file = request.files['plugin'].read()
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
    filepath = os.path.join(app.config['PROCESSED_FOLDER'], filename)
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