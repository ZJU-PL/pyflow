from quart import Quart, request, jsonify
import json
from enum import Enum
from typing import Dict, Any
from dataclasses import dataclass

app = Quart(__name__)

class TemplateType(str, Enum):
    USER = "user"
    PRODUCT = "product"

@dataclass
class TemplateVariables:
    user_id: int = 0
    product_id: str = ""

class ResponseProcessor:
    def __init__(self):
        self.response_templates = {
            TemplateType.USER: lambda vars: {"id": vars.user_id, "name": "Test User"},
            TemplateType.PRODUCT: lambda vars: {"sku": vars.product_id, "price": 19.99}
        }

    async def safe_process_response(self, template_type: TemplateType, variables_json: str) -> Dict[str, Any]:
        try:
            # Parse and validate input variables
            vars_dict = json.loads(variables_json)
            vars = TemplateVariables(
                user_id=int(vars_dict.get("user_id", 0)),
                product_id=str(vars_dict.get("product_id", ""))
            )

            # Get and execute the template
            template = self.response_templates.get(template_type)
            if not template:
                return {"error": "Invalid template type"}
            
            return template(vars)
            
        except json.JSONDecodeError as e:
            return {"error": f"Invalid JSON: {str(e)}"}
        except ValueError as e:
            return {"error": f"Invalid value: {str(e)}"}
        except Exception as e:
            return {"error": f"Processing failed: {str(e)}"}

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
        Variables (JSON):<br>
        <textarea name="variables_json" rows=6 cols=50>
{
    "user_id": 42,
    "product_id": "XJ-209"
}
        </textarea><br>
        <button type="submit">Generate Response</button>
    </form>
    '''

@app.route('/api', methods=['POST'])
async def api_handler():
    form = await request.form
    try:
        template_type = TemplateType(form['template_type'])
        result = await processor.safe_process_response(
            template_type,
            form['variables_json']
        )
        return jsonify(result)
    except ValueError as e:
        return jsonify({"error": f"Invalid template type: {str(e)}"})

@app.route('/debug', methods=['GET'])
async def debug():
    return jsonify({
        "status": "active",
        "endpoints": [str(rule) for rule in app.url_map.iter_rules()]
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)