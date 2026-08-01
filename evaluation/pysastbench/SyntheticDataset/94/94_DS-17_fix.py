import json
from flask import Flask, request, jsonify
from datetime import datetime
import math
from enum import Enum
from typing import Dict, Any

app = Flask(__name__)

class RuleType(Enum):
    COMPARISON = "comparison"
    RANGE_CHECK = "range_check"
    STRING_MATCH = "string_match"

class SafeRuleEngine:
    def __init__(self):
        self.rules: Dict[str, Dict] = {}
        self.load_default_rules()
    
    def add_rule(self, name: str, rule_type: RuleType, params: Dict[str, Any]) -> None:
        """Add a rule with validated parameters"""
        if not isinstance(params, dict):
            raise ValueError("Rule params must be a dictionary")
        
        self.rules[name] = {
            'type': rule_type,
            'params': params
        }
    
    def load_default_rules(self) -> None:
        """Load predefined safe rules"""
        self.add_rule(
            'high_value_transaction',
            RuleType.RANGE_CHECK,
            {'field': 'amount', 'min': 10000}
        )
        self.add_rule(
            'suspicious_login',
            RuleType.COMPARISON,
            {'field1': 'login_location', 'field2': 'usual_location', 'operator': '!='}
        )
    
    def evaluate_rule(self, name: str, data: Dict[str, Any] = None) -> Dict[str, Any]:
        """Safely evaluate a rule against provided data"""
        if name not in self.rules:
            raise ValueError(f"Rule '{name}' not found")
        
        rule = self.rules[name]
        data = data or {}
        
        try:
            if rule['type'] == RuleType.COMPARISON:
                val1 = data.get(rule['params']['field1'])
                val2 = data.get(rule['params']['field2'])
                op = rule['params']['operator']
                
                if op == '==':
                    condition_met = val1 == val2
                elif op == '!=':
                    condition_met = val1 != val2
                elif op == '>':
                    condition_met = val1 > val2
                elif op == '<':
                    condition_met = val1 < val2
                elif op == '>=':
                    condition_met = val1 >= val2
                elif op == '<=':
                    condition_met = val1 <= val2
                else:
                    raise ValueError(f"Invalid operator: {op}")
                
                if condition_met:
                    return {
                        'status': 'triggered',
                        'message': f"Condition met: {rule['params']['field1']} {op} {rule['params']['field2']}"
                    }
            
            elif rule['type'] == RuleType.RANGE_CHECK:
                value = data.get(rule['params']['field'])
                if isinstance(value, (int, float)):
                    if 'min' in rule['params'] and value > rule['params']['min']:
                        return {
                            'status': 'triggered',
                            'message': f"Value exceeds threshold: {value} > {rule['params']['min']}"
                        }
                    if 'max' in rule['params'] and value < rule['params']['max']:
                        return {
                            'status': 'triggered',
                            'message': f"Value below threshold: {value} < {rule['params']['max']}"
                        }
            
            elif rule['type'] == RuleType.STRING_MATCH:
                value = data.get(rule['params']['field'])
                pattern = rule['params']['pattern']
                if isinstance(value, str) and pattern in value:
                    return {
                        'status': 'triggered',
                        'message': f"Pattern matched in field: {rule['params']['field']}"
                    }
            
            return {'status': 'not_triggered'}
        
        except Exception as e:
            raise ValueError(f"Rule evaluation error: {str(e)}")

class SafeMathEvaluator:
    @staticmethod
    def evaluate(expression: str) -> float:
        """Safely evaluate a mathematical expression"""
        allowed_ops = {
            'add': lambda a, b: a + b,
            'sub': lambda a, b: a - b,
            'mul': lambda a, b: a * b,
            'div': lambda a, b: a / b,
            'pow': lambda a, b: a ** b,
            'sqrt': math.sqrt,
            'sin': math.sin,
            'cos': math.cos,
            'tan': math.tan,
            'log': math.log,
            'log10': math.log10
        }
        
        try:
            # Parse the expression into tokens
            tokens = expression.split()
            if len(tokens) != 3 and len(tokens) != 2:
                raise ValueError("Invalid expression format")
            
            if len(tokens) == 3:
                op_name, a, b = tokens
                op = allowed_ops.get(op_name)
                if not op:
                    raise ValueError(f"Invalid operation: {op_name}")
                return op(float(a), float(b))
            else:
                op_name, a = tokens
                op = allowed_ops.get(op_name)
                if not op:
                    raise ValueError(f"Invalid operation: {op_name}")
                return op(float(a))
        
        except ValueError as e:
            raise ValueError(f"Math evaluation error: {str(e)}")

# Initialize the processors
rule_engine = SafeRuleEngine()
math_evaluator = SafeMathEvaluator()

@app.route('/api/rules/evaluate', methods=['POST'])
def evaluate_rules():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        results = {}
        for rule_name in rule_engine.rules:
            try:
                results[rule_name] = rule_engine.evaluate_rule(rule_name, data)
            except ValueError as e:
                results[rule_name] = {'error': str(e)}
        
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/rules/math', methods=['POST'])
def evaluate_math():
    try:
        data = request.get_json()
        if 'expression' not in data:
            return jsonify({'error': 'Expression required'}), 400
        
        result = math_evaluator.evaluate(data['expression'])
        return jsonify({'result': result})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception:
        return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    app.run(debug=False)  # Disable debug mode in production