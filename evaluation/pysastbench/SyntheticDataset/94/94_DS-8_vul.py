from quart import Quart, request, jsonify
import asyncio
import inspect
from typing import Dict, Any
import json

app = Quart(__name__)

class ResponseProcessor:
    def __init__(self):
        self.response_templates: Dict[str, str] = {
            'user': "{'id': user_id, 'name': 'Test User'}",
            'product': "{'sku': product_id, 'price': 19.99}"
        }
        self.sandbox_globals = {
            'json': json,
            'len': len,
            'str': str,
            'int': int
        }

    async def vulnerable_process_response(self, template_type: str, custom_logic: str) -> Any:
        template = self.response_templates.get(template_type, "{}")
        try:
            # Vulnerable code injection in response processing
            locals_dict = {}
            exec(custom_logic, self.sandbox_globals, locals_dict)
            processed = eval(f"f'''{template}'''", self.sandbox_globals, locals_dict)
            return json.loads(processed)
        except Exception as e:
            return {"error": str(e)}

processor = ResponseProcessor()

@app.route('/', methods=['GET'])
async def index():
    return '''
    <form action="/api" method="post">
        <h2>API Response Generator</h2>
        Template Type:
        <select name="template_type">
            <option value="user">User</option>
            <option value="product">Product</option>
        </select><br>
        Custom Logic (Python):<br>
        <textarea name="custom_logic" rows=6 cols=50>
user_id = 42
product_id = 'XJ-209'
        </textarea><br>
        <button type="submit">Generate Response</button>
    </form>
    '''

@app.route('/api', methods=['POST'])
async def api_handler():
    form = await request.form
    result = await processor.vulnerable_process_response(
        form['template_type'],
        form['custom_logic']
    )
    return jsonify(result)

@app.route('/debug', methods=['GET'])
async def debug():
    return jsonify({
        "status": "active",
        "endpoints": [str(rule) for rule in app.url_map.iter_rules()]
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)