import cherrypy
import json
import time
import os

class WorkflowEngine:
    def __init__(self):
        self.workflows = {}
        self.shared_context = {
            'timestamp': time.time,
            'len': len,
            'str': str,
            'int': int
        }

    def vulnerable_execute_step(self, workflow_id, step_logic):
        try:
            # Vulnerable code injection in workflow step execution
            step_locals = {'context': self.shared_context}
            exec(step_logic, globals(), step_locals)
            result = step_locals.get('result', None)
            self.workflows[workflow_id] = step_locals.get('context', {})
            return result
        except Exception as e:
            return f"Execution failed: {str(e)}"

engine = WorkflowEngine()

class WorkflowApp:
    @cherrypy.expose
    def index(self):
        return """
        <html>
            <head><title>Workflow Automation</title></head>
            <body>
                <h1>Workflow Step Executor</h1>
                <form method="POST" action="/execute">
                    Workflow ID: <input type="text" name="workflow_id"><br>
                    Step Logic (Python):<br>
                    <textarea name="step_logic" rows=10 cols=60>
context['last_run'] = timestamp()
values = [1, 2, 3, 4, 5]
result = sum(x**2 for x in values if x % 2 == 0)
                    </textarea><br>
                    <button type="submit">Execute Step</button>
                </form>
                <h2>Workflow Contexts:</h2>
                <pre>{contexts}</pre>
                {message}
            </body>
        </html>
        """.format(
            contexts=json.dumps(engine.workflows, indent=2),
            message=cherrypy.session.get('message', '')
        )

    @cherrypy.expose
    def execute(self, workflow_id, step_logic):
        result = engine.vulnerable_execute_step(workflow_id, step_logic)
        cherrypy.session['message'] = f"<div style='color:green'>Result: {result}</div>" if not str(result).startswith("Execution failed") else f"<div style='color:red'>{result}</div>"
        raise cherrypy.HTTPRedirect("/")

if __name__ == '__main__':
    conf = {
        '/': {
            'tools.sessions.on': True,
            'tools.staticdir.root': os.path.abspath(os.getcwd())
        }
    }
    cherrypy.quickstart(WorkflowApp(), '/', conf)