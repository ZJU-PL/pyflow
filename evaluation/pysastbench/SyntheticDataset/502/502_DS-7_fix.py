import json
import numpy as np
from flask import Flask, request, jsonify
from io import BytesIO
import importlib.util
import tempfile
import shutil
import os
import hashlib

app = Flask(__name__)
MODULE_DIR = './analysis_modules'
os.makedirs(MODULE_DIR, exist_ok=True)

class DataAnalyzer:
    def __init__(self):
        self.analyses = {}
        self.data_cache = {}
        self.analysis_modules = {}
        self.allowed_module_methods = ['analyze']

    def load_analysis_module(self, module_file):
        try:
            # Create a temporary directory for module validation
            with tempfile.TemporaryDirectory() as temp_dir:
                # Save the module file temporarily
                temp_path = os.path.join(temp_dir, 'module.py')
                module_file.save(temp_path)
                
                # Validate the module structure
                spec = importlib.util.spec_from_file_location("analysis_module", temp_path)
                module = importlib.util.module_from_spec(spec)
                
                # Restrict what the module can access
                module.__dict__['__builtins__'] = {
                    'str': str,
                    'int': int,
                    'float': float,
                    'bool': bool,
                    'list': list,
                    'dict': dict,
                    'tuple': tuple,
                    'range': range,
                    'len': len,
                    'sum': sum,
                    'min': min,
                    'max': max,
                    'abs': abs,
                    'round': round,
                    # Add other safe builtins as needed
                }
                
                spec.loader.exec_module(module)
                
                # Verify the module has the required interface
                if not all(hasattr(module, method) for method in self.allowed_module_methods):
                    raise ValueError("Module missing required methods")
                
                # Generate a unique ID for the module
                with open(temp_path, 'rb') as f:
                    module_id = hashlib.sha256(f.read()).hexdigest()
                
                # Move the validated module to permanent storage
                final_path = os.path.join(MODULE_DIR, f"{module_id}.py")
                shutil.move(temp_path, final_path)
                
                self.analysis_modules[module_id] = final_path
                return module_id
                
        except Exception as e:
            print(f"Module loading failed: {e}")
            return None

    def analyze_data(self, data_id, module_id, parameters):
        if module_id not in self.analysis_modules:
            return None

        try:
            data = self.data_cache.get(data_id)
            if data is None:
                return None

            # Dynamically load the module from file
            module_path = self.analysis_modules[module_id]
            spec = importlib.util.spec_from_file_location("analysis_module", module_path)
            module = importlib.util.module_from_spec(spec)
            
            # Restrict builtins again for safety
            module.__dict__['__builtins__'] = {
                'str': str,
                'int': int,
                'float': float,
                'bool': bool,
                'list': list,
                'dict': dict,
                'tuple': tuple,
                'range': range,
                'len': len,
                'sum': sum,
                'min': min,
                'max': max,
                'abs': abs,
                'round': round,
            }
            
            spec.loader.exec_module(module)
            
            # Execute the analysis module with user-provided parameters
            result = module.analyze(data, **parameters)
            
            # Validate the result is serializable
            if isinstance(result, np.ndarray):
                result = result.tolist()
            elif not isinstance(result, (str, int, float, bool, list, dict, tuple)):
                raise ValueError("Invalid result type")
            
            analysis_id = f"{data_id}_{module_id}_{hash(str(parameters))}"
            self.analyses[analysis_id] = {
                'data_id': data_id,
                'module_id': module_id,
                'parameters': parameters,
                'result': result
            }
            return analysis_id
        except Exception as e:
            print(f"Analysis failed: {e}")
            return None

    def upload_data(self, data_bytes):
        try:
            # Disallow pickled numpy arrays for security
            data = np.load(BytesIO(data_bytes), allow_pickle=False)
            data_id = str(hash(data_bytes))
            self.data_cache[data_id] = data
            return data_id
        except Exception as e:
            print(f"Data upload failed: {e}")
            return None

analyzer = DataAnalyzer()

@app.route('/upload_data', methods=['POST'])
def upload_data():
    if 'data' not in request.files:
        return jsonify({'error': 'No data file provided'}), 400

    data_file = request.files['data']
    if data_file.filename == '':
        return jsonify({'error': 'Empty filename'}), 400

    # Validate file extension
    if not data_file.filename.endswith('.npy'):
        return jsonify({'error': 'Only .npy files are allowed'}), 400

    data_id = analyzer.upload_data(data_file.read())

    if data_id:
        return jsonify({'data_id': data_id}), 200
    return jsonify({'error': 'Data upload failed'}), 400

@app.route('/upload_module', methods=['POST'])
def upload_module():
    if 'module' not in request.files:
        return jsonify({'error': 'No module file provided'}), 400

    module_file = request.files['module']
    if module_file.filename == '':
        return jsonify({'error': 'Empty filename'}), 400

    # Validate file extension
    if not module_file.filename.endswith('.py'):
        return jsonify({'error': 'Only Python files (.py) are allowed'}), 400

    module_id = analyzer.load_analysis_module(module_file)

    if module_id:
        return jsonify({'module_id': module_id}), 200
    return jsonify({'error': 'Module upload failed'}), 400

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    if not data or 'data_id' not in data or 'module_id' not in data:
        return jsonify({'error': 'Invalid request'}), 400

    parameters = data.get('parameters', {})
    analysis_id = analyzer.analyze_data(data['data_id'], data['module_id'], parameters)

    if analysis_id:
        return jsonify({'analysis_id': analysis_id}), 200
    return jsonify({'error': 'Analysis failed'}), 400

@app.route('/results/<analysis_id>', methods=['GET'])
def get_results(analysis_id):
    if analysis_id in analyzer.analyses:
        return jsonify({'result': analyzer.analyses[analysis_id]['result']}), 200
    return jsonify({'error': 'Analysis not found'}), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)