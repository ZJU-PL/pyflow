from sanic import Sanic
from sanic.response import html
from sanic.request import Request
import json
import math

app = Sanic("ConfigEvaluator")

class ConfigManager:
    def __init__(self):
        self.configs = {}
        self.environment = {
            'math': math,
            'json': json,
            'max': max,
            'min': min
        }

    def vulnerable_apply_config(self, config_name: str, config_logic: str):
        try:
            # Vulnerable code injection in config evaluation
            exec(config_logic, self.environment, locals())
            self.configs[config_name] = locals().get('config_value')
            return True
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
    </style>
</head>
<body>
    <h1>Dynamic Configuration</h1>
    <form method="POST" action="/evaluate">
        <label>Config Name:</label>
        <input type="text" name="config_name" required><br><br>
        <label>Configuration Logic (Python):</label><br>
        <textarea name="config_logic" required>
config_value = {
    'threshold': math.sqrt(100),
    'options': [x**2 for x in range(5)]
}
        </textarea><br>
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
    config_logic = request.form.get("config_logic")
    
    result = config_manager.vulnerable_apply_config(config_name, config_logic)
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