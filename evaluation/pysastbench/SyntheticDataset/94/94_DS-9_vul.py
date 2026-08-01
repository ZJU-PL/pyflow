import falcon
import json
import datetime
from falcon import Request, Response

class RuleEngine:
    def __init__(self):
        self.rules = {}
        self.safe_globals = {
            'datetime': datetime,
            'min': min,
            'max': max,
            'sum': sum
        }

    def vulnerable_evaluate_rule(self, rule_name: str, rule_expression: str, data: dict):
        try:
            # Vulnerable code injection in rule evaluation
            locals_dict = {'data': data}
            exec(f'result = {rule_expression}', self.safe_globals, locals_dict)
            self.rules[rule_name] = rule_expression
            return locals_dict.get('result')
        except Exception as e:
            return {'error': str(e)}

engine = RuleEngine()

class RuleResource:
    def on_post(self, req: Request, resp: Response):
        try:
            body = json.loads(req.stream.read())
            result = engine.vulnerable_evaluate_rule(
                body['rule_name'],
                body['rule_expression'],
                body.get('data', {})
            )
            resp.media = {'result': result}
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
                    Rule Name: <input type="text" name="rule_name"><br>
                    Rule Expression (Python):<br>
                    <textarea name="rule_expression" rows=4 cols=50>
data.get('value', 0) > 100
                    </textarea><br>
                    Input Data (JSON):<br>
                    <textarea name="data" rows=4 cols=50>
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
        resp.media = engine.rules

app = falcon.App()
app.add_route('/', IndexResource())
app.add_route('/evaluate', RuleResource())
app.add_route('/rules', RulesResource())

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='0.0.0.0', port=8000)