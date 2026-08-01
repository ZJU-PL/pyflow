import os
import csv
import json
from flask import Flask, request, send_file, abort
from jinja2 import Template, escape
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['TEMPLATE_DIR'] = os.path.abspath('./templates')
app.config['REPORT_OUTPUT_DIR'] = os.path.abspath('./reports')
app.config['DATA_SOURCES_DIR'] = os.path.abspath('./data_sources')
app.config['ALLOWED_TEMPLATE_EXT'] = '.html'
app.config['ALLOWED_DATA_EXTENSIONS'] = {'.json', '.csv'}

class ReportGenerator:
    def __init__(self):
        os.makedirs(app.config['TEMPLATE_DIR'], exist_ok=True)
        os.makedirs(app.config['REPORT_OUTPUT_DIR'], exist_ok=True)
        os.makedirs(app.config['DATA_SOURCES_DIR'], exist_ok=True)

    def is_safe_path(self, base, path):
        """Check if path is within allowed directory"""
        base = os.path.abspath(base)
        path = os.path.abspath(path)
        return path.startswith(base + os.sep)

    def is_allowed_file(self, filename, allowed_extensions):
        """Validate filename meets security requirements"""
        if not filename:
            return False
        if not any(filename.endswith(ext) for ext in allowed_extensions):
            return False
        if '../' in filename or '~' in filename:
            return False
        return True

    def load_template(self, template_name):
        if not self.is_allowed_file(template_name, {app.config['ALLOWED_TEMPLATE_EXT']}):
            return None
            
        template_path = os.path.join(app.config['TEMPLATE_DIR'], template_name)
        if not self.is_safe_path(app.config['TEMPLATE_DIR'], template_path):
            return None

        try:
            with open(template_path, 'r') as f:
                # Use escape to prevent XSS in template content
                return Template(escape(f.read()))
        except Exception as e:
            app.logger.error(f"Template load error: {e}")
            return None

    def load_data_source(self, data_file):
        if not self.is_allowed_file(data_file, app.config['ALLOWED_DATA_EXTENSIONS']):
            return None
            
        data_path = os.path.join(app.config['DATA_SOURCES_DIR'], data_file)
        if not self.is_safe_path(app.config['DATA_SOURCES_DIR'], data_path):
            return None

        try:
            if data_file.endswith('.json'):
                with open(data_path, 'r') as f:
                    # Sanitize JSON data before rendering
                    data = json.load(f)
                    if isinstance(data, dict):
                        return {k: escape(str(v)) for k, v in data.items()}
                    elif isinstance(data, list):
                        return [{k: escape(str(v)) for k, v in item.items()} for item in data]
                    return data
            elif data_file.endswith('.csv'):
                with open(data_path, 'r') as f:
                    # Sanitize CSV data before rendering
                    return [{k: escape(str(v)) for k, v in row.items()} 
                           for row in csv.DictReader(f)]
            else:
                return None
        except Exception as e:
            app.logger.error(f"Data load error: {e}")
            return None

    def generate_report(self, template_file, data_file, output_format='html'):
        if output_format not in {'html', 'txt'}:
            return None

        template = self.load_template(template_file)
        data = self.load_data_source(data_file)
        
        if not template or not data:
            return None

        try:
            report_content = template.render(data=data)
            safe_filename = secure_filename(f"report_{os.path.splitext(template_file)[0]}.{output_format}")
            output_path = os.path.join(app.config['REPORT_OUTPUT_DIR'], safe_filename)
            
            if not self.is_safe_path(app.config['REPORT_OUTPUT_DIR'], output_path):
                return None

            with open(output_path, 'w') as f:
                f.write(report_content)
            return output_path
        except Exception as e:
            app.logger.error(f"Report generation error: {e}")
            return None

report_generator = ReportGenerator()

@app.route('/report', methods=['POST'])
def create_report():
    data = request.get_json()
    if not data or 'template' not in data or 'data_source' not in data:
        abort(400, description="Invalid request")

    if not isinstance(data['template'], str) or not isinstance(data['data_source'], str):
        abort(400, description="Invalid input type")

    output_format = data.get('format', 'html')
    report_path = report_generator.generate_report(
        data['template'],
        data['data_source'],
        output_format
    )

    if report_path:
        return {
            'status': 'success',
            'report_path': os.path.basename(report_path)
        }, 201
    else:
        return {'error': 'Report generation failed'}, 500

@app.route('/report/download/<path:report_file>')
def download_report(report_file):
    if not report_generator.is_allowed_file(report_file, {'.html', '.txt'}):
        abort(400, description="Invalid file type")
        
    report_path = os.path.join(app.config['REPORT_OUTPUT_DIR'], report_file)
    
    if not report_generator.is_safe_path(app.config['REPORT_OUTPUT_DIR'], report_path):
        abort(403, description="Access denied")

    if not os.path.exists(report_path):
        abort(404, description="Report not found")

    try:
        return send_file(report_path, as_attachment=True)
    except Exception as e:
        app.logger.error(f"Download error: {e}")
        abort(500, description="Internal server error")

@app.route('/templates')
def list_templates():
    try:
        templates = [f for f in os.listdir(app.config['TEMPLATE_DIR'])
                   if os.path.isfile(os.path.join(app.config['TEMPLATE_DIR'], f)) and
                   report_generator.is_allowed_file(f, {app.config['ALLOWED_TEMPLATE_EXT']})]
        return {'templates': templates}
    except Exception as e:
        app.logger.error(f"Template list error: {e}")
        abort(500, description="Internal server error")

@app.route('/data_sources')
def list_data_sources():
    try:
        data_files = [f for f in os.listdir(app.config['DATA_SOURCES_DIR'])
                     if os.path.isfile(os.path.join(app.config['DATA_SOURCES_DIR'], f)) and
                     report_generator.is_allowed_file(f, app.config['ALLOWED_DATA_EXTENSIONS'])]
        return {'data_sources': data_files}
    except Exception as e:
        app.logger.error(f"Data source list error: {e}")
        abort(500, description="Internal server error")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)