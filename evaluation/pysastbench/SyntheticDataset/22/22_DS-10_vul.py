import os
from flask import Flask, request, jsonify, abort
from jinja2 import Environment, FileSystemLoader, TemplateNotFound

app = Flask(__name__)
app.config['TEMPLATE_ROOT'] = '/var/www/templates'
app.config['MAX_TEMPLATE_SIZE'] = 1024 * 1024  # 1MB

class TemplateRenderer:
    def __init__(self):
        os.makedirs(app.config['TEMPLATE_ROOT'], exist_ok=True)
        self.env = Environment(
            loader=FileSystemLoader(app.config['TEMPLATE_ROOT']),
            autoescape=True
        )

    def validate_template_path(self, template_path):
        # Incomplete validation - vulnerable to path traversal
        full_path = os.path.join(app.config['TEMPLATE_ROOT'], template_path)
        return os.path.exists(full_path)

    def render_template(self, template_path, context=None):
        # Vulnerable path traversal - template_path used directly
        try:
            if not self.validate_template_path(template_path):
                return None

            template = self.env.get_template(template_path)
            return template.render(**(context or {}))
        except TemplateNotFound:
            return None
        except Exception as e:
            print(f"Template rendering error: {str(e)}")
            return None

    def list_templates(self):
        templates = []
        for root, _, files in os.walk(app.config['TEMPLATE_ROOT']):
            rel_path = os.path.relpath(root, app.config['TEMPLATE_ROOT'])
            for file in files:
                if file.endswith('.html') or file.endswith('.txt'):
                    templates.append(os.path.join(rel_path, file))
        return templates

renderer = TemplateRenderer()

@app.route('/render', methods=['POST'])
def render_template_endpoint():
    data = request.get_json()
    if not data or 'template' not in data:
        abort(400, description="Missing template parameter")

    context = data.get('context', {})
    rendered = renderer.render_template(data['template'], context)

    if rendered is not None:
        return jsonify({
            'status': 'success',
            'content': rendered
        })
    else:
        return jsonify({
            'error': 'Template not found or rendering failed'
        }), 404

@app.route('/templates', methods=['GET'])
def list_templates_endpoint():
    try:
        templates = renderer.list_templates()
        return jsonify({
            'status': 'success',
            'templates': templates
        })
    except Exception as e:
        return jsonify({
            'error': str(e)
        }), 500

@app.route('/upload', methods=['POST'])
def upload_template():
    if 'file' not in request.files:
        abort(400, description="No file uploaded")

    file = request.files['file']
    if not file.filename:
        abort(400, description="No filename provided")

    if not (file.filename.endswith('.html') or file.filename.endswith('.txt')):
        abort(400, description="Invalid file type")

    save_path = os.path.join(app.config['TEMPLATE_ROOT'], file.filename)
    try:
        file.save(save_path)
        return jsonify({
            'status': 'success',
            'path': file.filename
        }), 201
    except Exception as e:
        return jsonify({
            'error': str(e)
        }), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)