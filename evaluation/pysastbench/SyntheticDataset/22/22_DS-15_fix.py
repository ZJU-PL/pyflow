import os
import csv
from flask import Flask, request, send_file, render_template, abort, jsonify
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['REPORT_TEMPLATES'] = os.path.abspath(os.path.join(os.path.dirname(__file__), 'templates'))
app.config['DATA_SOURCES'] = os.path.abspath(os.path.join(os.path.dirname(__file__), 'data'))
app.config['OUTPUT_DIR'] = os.path.abspath(os.path.join(os.path.dirname(__file__), 'reports'))
app.config['ALLOWED_EXTENSIONS'] = {'.tpl', '.csv', '.txt'}

class ReportGenerator:
    def __init__(self):
        os.makedirs(app.config['OUTPUT_DIR'], exist_ok=True)

    def is_safe_path(self, base_path, requested_path):
        """Check if requested path is within base directory"""
        base_path = os.path.abspath(base_path)
        requested_path = os.path.abspath(requested_path)
        return requested_path.startswith(base_path + os.sep)

    def is_allowed_file(self, filename, allowed_extensions):
        """Validate filename meets security requirements"""
        if not filename or not isinstance(filename, str):
            return False
        if not any(filename.endswith(ext) for ext in allowed_extensions):
            return False
        if '../' in filename or '~' in filename:
            return False
        return True

    def load_template(self, template_name):
        if not self.is_allowed_file(template_name, {'.tpl'}):
            raise ValueError("Invalid template name")
            
        template_path = os.path.join(app.config['REPORT_TEMPLATES'], template_name)
        
        if not self.is_safe_path(app.config['REPORT_TEMPLATES'], template_path):
            raise ValueError("Invalid template path")
            
        if not os.path.exists(template_path):
            raise FileNotFoundError("Template not found")
            
        with open(template_path, 'r') as f:
            return f.read()

    def load_data(self, data_file):
        if not self.is_allowed_file(data_file, {'.csv'}):
            raise ValueError("Invalid data file name")
            
        data_path = os.path.join(app.config['DATA_SOURCES'], data_file)
        
        if not self.is_safe_path(app.config['DATA_SOURCES'], data_path):
            raise ValueError("Invalid data path")
            
        if not os.path.exists(data_path):
            raise FileNotFoundError("Data file not found")
            
        with open(data_path, 'r') as f:
            reader = csv.DictReader(f)
            return list(reader)

    def generate_report(self, template_name, data_file, output_name):
        try:
            # Validate output name
            if not self.is_allowed_file(output_name, {'.txt'}):
                raise ValueError("Invalid output file name")
                
            template = self.load_template(template_name)
            data = self.load_data(data_file)
            
            # Note: Template rendering is still vulnerable to XSS
            # Consider using a proper templating engine with auto-escaping
            report_content = template.format(data=data)
            
            output_path = os.path.join(app.config['OUTPUT_DIR'], secure_filename(output_name))
            
            if not self.is_safe_path(app.config['OUTPUT_DIR'], output_path):
                raise ValueError("Invalid output path")
                
            with open(output_path, 'w') as f:
                f.write(report_content)
            
            return output_path
        except Exception as e:
            raise RuntimeError(f"Report generation failed: {str(e)}")

@app.route('/api/generate', methods=['POST'])
def generate_report():
    try:
        data = request.get_json()
        if not data or not isinstance(data, dict):
            return jsonify({'error': 'Invalid request'}), 400
            
        template = data.get('template')
        data_file = data.get('data_file')
        output_name = secure_filename(data.get('output_name', 'report.txt'))
        
        if not template or not data_file:
            return jsonify({'error': 'Missing template or data file'}), 400
            
        generator = ReportGenerator()
        report_path = generator.generate_report(template, data_file, output_name)
        
        return jsonify({
            'status': 'success',
            'report_path': os.path.basename(report_path),
            'download_url': f'/api/download/{os.path.basename(report_path)}'
        })
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except FileNotFoundError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        app.logger.error(f"Report generation error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/download/<filename>')
def download_report(filename):
    try:
        if not filename or not isinstance(filename, str):
            abort(400, "Invalid filename")
            
        safe_filename = secure_filename(filename)
        report_path = os.path.join(app.config['OUTPUT_DIR'], safe_filename)
        
        if not os.path.exists(report_path):
            abort(404, "Report not found")
            
        return send_file(report_path, as_attachment=True)
    except Exception as e:
        app.logger.error(f"Download error: {e}")
        abort(500, "Internal server error")

@app.route('/')
def index():
    templates = []
    data_files = []
    
    try:
        templates = [f for f in os.listdir(app.config['REPORT_TEMPLATES'])
                   if f.endswith('.tpl') and
                   os.path.isfile(os.path.join(app.config['REPORT_TEMPLATES'], f))]
        data_files = [f for f in os.listdir(app.config['DATA_SOURCES']) 
                     if f.endswith('.csv') and
                     os.path.isfile(os.path.join(app.config['DATA_SOURCES'], f))]
    except Exception as e:
        app.logger.error(f"Directory listing error: {e}")
        
    return render_template('index.html', templates=templates, data_files=data_files)

if __name__ == '__main__':
    # Create sample directories and files with secure permissions
    os.makedirs(app.config['REPORT_TEMPLATES'], mode=0o750, exist_ok=True)
    os.makedirs(app.config['DATA_SOURCES'], mode=0o750, exist_ok=True)
    os.makedirs(app.config['OUTPUT_DIR'], mode=0o750, exist_ok=True)
    
    # Create sample template
    template_path = os.path.join(app.config['REPORT_TEMPLATES'], 'default.tpl')
    try:
        with open(template_path, 'w') as f:
            f.write("Report Data:\n\n{data}")
        os.chmod(template_path, 0o640)
    except Exception as e:
        app.logger.error(f"Error creating sample template: {e}")
    
    # Create sample data file
    data_path = os.path.join(app.config['DATA_SOURCES'], 'sample.csv')
    try:
        with open(data_path, 'w') as f:
            f.write("id,name,value\n1,Test,100\n2,Example,200")
        os.chmod(data_path, 0o640)
    except Exception as e:
        app.logger.error(f"Error creating sample data: {e}")
    
    app.run(host='0.0.0.0', port=5000)