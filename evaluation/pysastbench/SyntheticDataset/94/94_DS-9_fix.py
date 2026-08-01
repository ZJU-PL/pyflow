import falcon
import json
import datetime
from falcon import Request, Response
from enum import Enum
from typing import Dict, Any
from dataclasses import dataclass

class Operator(str, Enum):
    GREATER_THAN = ">"
    LESS_THAN = "<"
    EQUALS = "=="
    GREATER_EQUAL = ">="
    LESS_EQUAL = "<="
    NOT_EQUAL = "!="

@dataclass
class Rule:
    field: str
    operator: Operator
    value: Any

class RuleEngine:
    def __init__(self):
        self.rules: Dict[str, Rule] = {}
    
    def safe_evaluate_rule(self, rule_name: str, rule_config: str, data: dict) -> Any:
        try:
            # Parse and validate the rule configuration
            config = json.loads(rule_config)
            rule = Rule(
                field=config['field'],
                operator=Operator(config['operator']),
                value=config['value']
            )

            # Store the rule
            self.rules[rule_name] = rule

            # Evaluate the rule
            field_value = data.get(rule.field)
            if rule.operator == Operator.GREATER_THAN:
                return field_value > rule.value
            elif rule.operator == Operator.LESS_THAN:
                return field_value < rule.value
            elif rule.operator == Operator.EQUALS:
                return field_value == rule.value
            elif rule.operator == Operator.GREATER_EQUAL:
                return field_value >= rule.value
            elif rule.operator == Operator.LESS_EQUAL:
                return field_value <= rule.value
            elif rule.operator == Operator.NOT_EQUAL:
                return field_value != rule.value
            else:
                return False

        except json.JSONDecodeError as e:
            return {'error': f"Invalid rule configuration: {str(e)}"}
        except KeyError as e:
            return {'error': f"Missing required field: {str(e)}"}
        except ValueError as e:
            return {'error': f"Invalid operator: {str(e)}"}
        except Exception as e:
            return {'error': f"Evaluation failed: {str(e)}"}

engine = RuleEngine()

class RuleResource:
    def on_post(self, req: Request, resp: Response):
        try:
            body = json.loads(req.stream.read())
            result = engine.safe_evaluate_rule(
                body['rule_name'],
                body['rule_config'],
                body.get('data', {})
            )
            resp.media = {'result': result}
        except json.JSONDecodeError as e:
            resp.media = {'error': f"Invalid JSON: {str(e)}"}
            resp.status = falcon.HTTP_400
        except Exception as e:
            resp.media = {'error': str(e)}
            resp.status = falcon.HTTP_400

class IndexResource:
    def on_get(self, req: Request, resp: Response):
        resp.content_type = 'text/html'
        resp.text = '''
        <html>
            <head><title>Rule Evaluation Engine</title></head>
            <body>
                <h1>Rule Evaluation Engine</h1>
                <form action="/evaluate" method="post">
                    Rule Name: <input type="text" name="rule_name" required><br>
                    Rule Configuration (JSON):<br>
                    <textarea name="rule_config" rows=4 cols=50 required>
{
    "field": "value",
    "operator": ">",
    "value": 100
}
                    </textarea><br>
                    Input Data (JSON):<br>
                    <textarea name="data" rows=4 cols=50 required>
{"value": 150}
                    </textarea><br>
                    <button type="submit">Evaluate</button>
                </form>
                <h2>Stored Rules:</h2>
                <pre id="rules"></pre>
                <script>
                    fetch('/rules').then(r => r.json()).then(data => {
                        document.getElementById('rules').innerText = JSON.stringify(data, null, 2);
                    });
                </script>
            </body>
        </html>
        '''

class RulesResource:
    def on_get(self, req: Request, resp: Response):
        resp.media = {name: vars(rule) for name, rule in engine.rules.items()}

app = falcon.App()
app.add_route('/', IndexResource())
app.add_route('/evaluate', RuleResource())
app.add_route('/rules', RulesResource())

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='0.0.0.0', port=8000)