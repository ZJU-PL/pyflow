import json
from flask import Flask, request, jsonify
from datetime import datetime
import re
import math

app = Flask(__name__)

class RuleEngine:
    def __init__(self):
        self.rules = {}
        self.context = {
            'datetime': datetime,
            'math': math,
            're': re,
            'json': json
        }
    
    def add_rule(self, name, condition, action):
        self.rules[name] = {
            'condition': condition,
            'action': action
        }
    
    def evaluate_rule(self, name, data=None):
        if name not in self.rules:
            raise ValueError(f"Rule '{name}' not found")
        
        rule = self.rules[name]
        context = {**self.context, 'data': data or {}}
        
        try:
            # Vulnerable condition evaluation
            condition_met = eval(rule['condition'], context)
            
            if condition_met:
                # Vulnerable action execution
                result = eval(rule['action'], context)
                return {'status': 'triggered', 'result': result}
            return {'status': 'not_triggered'}
        except Exception as e:
            raise ValueError(f"Rule evaluation failed: {str(e)}")

class DataProcessor:
    def __init__(self):
        self.engine = RuleEngine()
        self.load_default_rules()
    
    def load_default_rules(self):
        self.engine.add_rule(
            'high_value_transaction',
            'data.get("amount", 0) > 10000',
            '"ALERT: High value transaction: ${}".format(data.get("amount"))'
        )
        self.engine.add_rule(
            'suspicious_login',
            'data.get("login_location") != data.get("usual_location")',
            '"ALERT: Suspicious login from {}".format(data.get("login_location"))'
        )
    
    def process_data(self, data):
        results = {}
        for rule_name in self.engine.rules:
            try:
                results[rule_name] = self.engine.evaluate_rule(rule_name, data)
            except ValueError as e:
                results[rule_name] = {'error': str(e)}
        return results

processor = DataProcessor()

@app.route('/api/rules/evaluate', methods=['POST'])
def evaluate_rules():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        results = processor.process_data(data)
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/rules/custom', methods=['POST'])
def evaluate_custom_rule():
    try:
        data = request.get_json()
        if not all(k in data for k in ['condition', 'action']):
            return jsonify({'error': 'Condition and action required'}), 400
        
        # Create temporary rule with user-provided code
        rule_name = 'temp_' + datetime.now().strftime('%Y%m%d%H%M%S')
        processor.engine.add_rule(
            rule_name,
            data['condition'],
            data['action']
        )
        
        result = processor.engine.evaluate_rule(
            rule_name,
            data.get('data', {})
        )
        
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/rules/math', methods=['POST'])
def evaluate_math():
    try:
        data = request.get_json()
        if 'expression' not in data:
            return jsonify({'error': 'Expression required'}), 400
        
        # Vulnerable math expression evaluation
        result = eval(data['expression'], {'__builtins__': None}, {
            'math': math,
            'datetime': datetime
        })
        
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    app.run(debug=True)