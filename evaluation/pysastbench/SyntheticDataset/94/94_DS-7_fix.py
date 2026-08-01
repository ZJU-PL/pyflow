import cherrypy
import json
import time
import os
from enum import Enum
from dataclasses import dataclass
from typing import Dict, Any

class OperationType(str, Enum):
    SUM = "sum"
    AVERAGE = "average"
    MAX = "max"
    MIN = "min"

@dataclass
class WorkflowStep:
    operation: OperationType
    values: list
    filter_condition: str = None

class WorkflowEngine:
    def __init__(self):
        self.workflows: Dict[str, Dict[str, Any]] = {}
        self.shared_context = {
            'timestamp': time.time(),
            'last_run': None
        }

    def safe_execute_step(self, workflow_id: str, step_config: str):
        try:
            # Parse and validate the step configuration
            step_data = json.loads(step_config)
            step = WorkflowStep(
                operation=OperationType(step_data.get('operation')),
                values=step_data.get('values', []),
                filter_condition=step_data.get('filter')
            )

            # Validate values are numbers
            if not all(isinstance(x, (int, float)) for x in step.values):
                raise ValueError("All values must be numbers")

            # Execute the operation
            if step.filter_condition:
                filtered_values = [
                    x for x in step.values 
                    if self._evaluate_filter(x, step.filter_condition)
                ]
            else:
                filtered_values = step.values

            if step.operation == OperationType.SUM:
                result = sum(filtered_values)
            elif step.operation == OperationType.AVERAGE:
                result = sum(filtered_values) / len(filtered_values) if filtered_values else 0
            elif step.operation == OperationType.MAX:
                result = max(filtered_values) if filtered_values else 0
            elif step.operation == OperationType.MIN:
                result = min(filtered_values) if filtered_values else 0

            # Update context
            self.shared_context['last_run'] = time.time()
            self.workflows[workflow_id] = {
                'last_result': result,
                'last_run': self.shared_context['last_run']
            }

            return result

        except json.JSONDecodeError as e:
            return f"Invalid configuration: {str(e)}"
        except ValueError as e:
            return f"Validation error: {str(e)}"
        except Exception as e:
            return f"Execution failed: {str(e)}"

    def _evaluate_filter(self, value: float, condition: str) -> bool:
        """Safely evaluate simple filter conditions"""
        try:
            if condition == "even":
                return value % 2 == 0
            elif condition == "odd":
                return value % 2 != 0
            elif condition == "positive":
                return value > 0
            elif condition == "negative":
                return value < 0
            elif condition.startswith(">"):
                return value > float(condition[1:])
            elif condition.startswith("<"):
                return value < float(condition[1:])
            return True
        except:
            return False

engine = WorkflowEngine()

class WorkflowApp:
    @cherrypy.expose
    def index(self):
        return """
        <html>
            <head>
                <title>Workflow Automation</title>
                <style>
                    textarea { width: 100%; height: 150px; }
                    .example { color: #666; font-size: 0.9em; }
                </style>
            </head>
            <body>
                <h1>Workflow Step Executor</h1>
                <form method="POST" action="/execute">
                    Workflow ID: <input type="text" name="workflow_id" required><br>
                    Step Configuration (JSON):<br>
                    <textarea name="step_config" required>
{
    "operation": "sum",
    "values": [1, 2, 3, 4, 5],
    "filter": "even"
}
                    </textarea>
                    <div class="example">
                        Example: {"operation": "average", "values": [10, 20, 30], "filter": ">15"}
                    </div>
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
    def execute(self, workflow_id, step_config):
        result = engine.safe_execute_step(workflow_id, step_config)
        if not str(result).startswith("Execution failed"):
            cherrypy.session['message'] = f"<div style='color:green'>Result: {result}</div>"
        else:
            cherrypy.session['message'] = f"<div style='color:red'>{result}</div>"
        raise cherrypy.HTTPRedirect("/")

if __name__ == '__main__':
    conf = {
        '/': {
            'tools.sessions.on': True,
            'tools.staticdir.root': os.path.abspath(os.getcwd())
        }
    }
    cherrypy.quickstart(WorkflowApp(), '/', conf)