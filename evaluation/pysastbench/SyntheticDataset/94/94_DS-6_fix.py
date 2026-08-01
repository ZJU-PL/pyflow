from sanic import Sanic
from sanic.response import html
from sanic.request import Request
import json
import math
from json import JSONDecodeError

app = Sanic("ConfigEvaluator")

class ConfigManager:
    def __init__(self):
        self.configs = {}
    
    def safe_apply_config(self, config_name: str, config_json: str):
        try:
            # Validate and parse JSON input
            config_value = json.loads(config_json)
            
            # Additional validation if needed
            if not isinstance(config_value, (dict, list)):
                raise ValueError("Configuration must be a JSON object or array")
            
            self.configs[config_name] = config_value
            return True
        except JSONDecodeError as e:
            return f"Invalid JSON: {str(e)}"
        except Exception as e:
            return str(e)

config_manager = ConfigManager()

HTML_FORM = """
<!DOCTYPE html>
<html>
<head>
    <title>Configuration Evaluator</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        textarea { width: 100%; height: 150px; }
        .example { color: #666; font-size: 0.9em; margin-top: 5px; }
    </style>
</head>
<body>
    <h1>Dynamic Configuration</h1>
    <form method="POST" action="/evaluate">
        <label>Config Name:</label>
        <input type="text" name="config_name" required><br><br>
        <label>Configuration (JSON):</label><br>
        <textarea name="config_json" required>
{
    "threshold": 10,
    "options": [0, 1, 4, 9, 16]
}
        </textarea>
        <div class="example">Example: {"setting": "value", "numbers": [1, 2, 3]}</div>
        <br>
        <button type="submit">Evaluate</button>
    </form>
    <h2>Current Configurations:</h2>
    <pre>{configs}</pre>
    {message}
</body>
</html>
"""

@app.get("/")
async def index(request: Request):
    return html(HTML_FORM.format(configs=json.dumps(config_manager.configs, indent=2), message=""))

@app.post("/evaluate")
async def evaluate(request: Request):
    config_name = request.form.get("config_name")
    config_json = request.form.get("config_json")
    
    result = config_manager.safe_apply_config(config_name, config_json)
    if result is True:
        message = f"<div style='color:green'>Config '{config_name}' applied successfully!</div>"
    else:
        message = f"<div style='color:red'>Error: {result}</div>"
    
    return html(HTML_FORM.format(
        configs=json.dumps(config_manager.configs, indent=2),
        message=message
    ))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)