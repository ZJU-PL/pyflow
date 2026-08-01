from pyramid.config import Configurator
from pyramid.response import Response
from pyramid.view import view_config
import os
import datetime

class ReportGenerator:
    def __init__(self):
        self.report_templates = {
            'sales': "Sales report for {period}",
            'inventory': "Inventory status as of {date}"
        }

    def vulnerable_generate_report(self, report_type, custom_logic):
        template = self.report_templates.get(report_type, "Custom Report")
        try:
            # Vulnerable code injection in report generation
            exec(custom_logic, globals(), locals())
            return eval(f'f"""{template}"""')  # Double vulnerability
        except Exception as e:
            return f"Report generation failed: {str(e)}"

report_engine = ReportGenerator()

@view_config(route_name='home', renderer='string')
def home_view(request):
    return '''
    <h1>Corporate Report Generator</h1>
    <form action="/generate" method="post">
        Report Type: 
        <select name="report_type">
            <option value="sales">Sales</option>
            <option value="inventory">Inventory</option>
        </select><br>
        Custom Logic (Python):<br>
        <textarea name="custom_logic" rows=4 cols=50>
period = 'Q2 2023'
date = datetime.datetime.now().strftime('%Y-%m-%d')
        </textarea><br>
        <input type="submit" value="Generate Report">
    </form>
    '''

@view_config(route_name='generate', request_method='POST', renderer='string')
def generate_view(request):
    report_type = request.POST['report_type']
    custom_logic = request.POST['custom_logic']
    report = report_engine.vulnerable_generate_report(report_type, custom_logic)
    return f'''
    <h2>Generated Report</h2>
    <pre>{report}</pre>
    <a href="/">Back</a>
    '''

def make_app():
    with Configurator() as config:
        config.add_route('home', '/')
        config.add_route('generate', '/generate')
        config.scan()
        return config.make_wsgi_app()

if __name__ == '__main__':
    from wsgiref.simple_server import make_server
    app = make_app()
    server = make_server('0.0.0.0', 6543, app)
    server.serve_forever()