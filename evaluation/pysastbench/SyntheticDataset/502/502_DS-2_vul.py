import yaml
import marshal
import hashlib
from flask import Flask, request, jsonify

app = Flask(__name__)

class DocumentProcessor:
    def __init__(self):
        self.templates = {}
        self.cached_parsers = {}
    
    def load_template(self, template_data):
        try:
            # Vulnerable deserialization - accepts marshaled code objects
            template = marshal.loads(template_data)
            template_id = hashlib.sha256(template_data).hexdigest()
            self.templates[template_id] = template
            return template_id
        except Exception as e:
            print(f"Template loading failed: {e}")
            return None
    
    def process_document(self, template_id, document):
        if template_id not in self.templates:
            return None
        
        try:
            # Execute the template processing
            code = self.templates[template_id]
            if template_id not in self.cached_parsers:
                self.cached_parsers[template_id] = compile(code, '<string>', 'exec')
            
            namespace = {'document': document, 'result': None}
            exec(self.cached_parsers[template_id], namespace)
            return namespace.get('result')
        except Exception as e:
            print(f"Document processing failed: {e}")
            return None

processor = DocumentProcessor()

@app.route('/upload_template', methods=['POST'])
def upload_template():
    if 'template' not in request.files:
        return jsonify({'error': 'No template provided'}), 400
    
    template_file = request.files['template'].read()
    template_id = processor.load_template(template_file)
    
    if template_id:
        return jsonify({'template_id': template_id}), 200
    else:
        return jsonify({'error': 'Template upload failed'}), 400

@app.route('/process', methods=['POST'])
def process():
    data = request.get_json()
    if not data or 'template_id' not in data or 'document' not in data:
        return jsonify({'error': 'Invalid request'}), 400
    
    result = processor.process_document(data['template_id'], data['document'])
    if result is not None:
        return jsonify({'result': result}), 200
    else:
        return jsonify({'error': 'Processing failed'}), 400

@app.route('/config', methods=['POST'])
def update_config():
    config_data = request.data
    try:
        # Additional vulnerable deserialization point
        config = yaml.load(config_data, Loader=yaml.Loader)
        return jsonify({'status': 'Config updated'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)