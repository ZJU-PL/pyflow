import os
import csv
from flask import Flask, request, send_file, render_template, abort, jsonify

app = Flask(__name__)
app.config['REPORT_TEMPLATES'] = os.path.join(os.path.dirname(__file__), 'templates')
app.config['DATA_SOURCES'] = os.path.join(os.path.dirname(__file__), 'data')
app.config['OUTPUT_DIR'] = os.path.join(os.path.dirname(__file__), 'reports')

class ReportGenerator:
    def __init__(self):
        if not os.path.exists(app.config['OUTPUT_DIR']):
            os.makedirs(app.config['OUTPUT_DIR'])

    def load_template(self, template_name):
        # Vulnerable path traversal - no sanitization of template_name
        template_path = os.path.join(app.config['REPORT_TEMPLATES'], template_name)
        
        if not os.path.exists(template_path):
            raise FileNotFoundError(f"Template {template_name} not found")
            
        with open(template_path, 'r') as f:
            return f.read()

    def load_data(self, data_file):
        data_path = os.path.join(app.config['DATA_SOURCES'], data_file)
        
        if not os.path.exists(data_path):
            raise FileNotFoundError(f"Data file {data_file} not found")
            
        with open(data_path, 'r') as f:
            reader = csv.DictReader(f)
            return list(reader)

    def generate_report(self, template_name, data_file, output_name):
        try:
            template = self.load_template(template_name)
            data = self.load_data(data_file)
            
            # Simple template rendering (vulnerable to XSS but that's not our focus)
            report_content = template.format(data=data)
            
            output_path = os.path.join(app.config['OUTPUT_DIR'], output_name)
            with open(output_path, 'w') as f:
                f.write(report_content)
            
            return output_path
        except Exception as e:
            raise RuntimeError(f"Report generation failed: {str(e)}")

@app.route('/api/generate', methods=['POST'])
def generate_report():
    try:
        data = request.get_json()
        template = data.get('template')
        data_file = data.get('data_file')
        output_name = data.get('output_name', 'report.txt')
        
        if not template or not data_file:
            return jsonify({'error': 'Missing template or data file'}), 400
            
        generator = ReportGenerator()
        report_path = generator.generate_report(template, data_file, output_name)
        
        return jsonify({
            'status': 'success',
            'report_path': report_path,
            'download_url': f'/api/download/{os.path.basename(report_path)}'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/download/<filename>')
def download_report(filename):
    try:
        # This is also vulnerable to path traversal
        report_path = os.path.join(app.config['OUTPUT_DIR'], filename)
        
        if not os.path.exists(report_path):
            abort(404, "Report not found")
            
        return send_file(report_path, as_attachment=True)
    except Exception as e:
        abort(500, str(e))

@app.route('/')
def index():
    templates = []
    data_files = []
    
    try:
        templates = os.listdir(app.config['REPORT_TEMPLATES'])
        data_files = [f for f in os.listdir(app.config['DATA_SOURCES']) 
                     if f.endswith('.csv')]
    except Exception:
        pass
        
    return render_template('index.html', templates=templates, data_files=data_files)

if __name__ == '__main__':
    # Create sample directories and files
    os.makedirs(app.config['REPORT_TEMPLATES'], exist_ok=True)
    os.makedirs(app.config['DATA_SOURCES'], exist_ok=True)
    os.makedirs(app.config['OUTPUT_DIR'], exist_ok=True)
    
    # Create sample template
    with open(os.path.join(app.config['REPORT_TEMPLATES'], 'default.tpl'), 'w') as f:
        f.write("Report Data:\n\n{data}")
    
    # Create sample data file
    with open(os.path.join(app.config['DATA_SOURCES'], 'sample.csv'), 'w') as f:
        f.write("id,name,value\n1,Test,100\n2,Example,200")
    
    app.run(host='0.0.0.0', port=5000)