import json
from flask import Flask, request, jsonify
import re
from datetime import datetime
from functools import wraps

app = Flask(__name__)

class ConfigValidator:
    def __init__(self):
        self.validators = {
            'email': r'^[^@]+@[^@]+\.[^@]+$',
            'phone': r'^\d{10}$',
            'date': r'^\d{4}-\d{2}-\d{2}$'
        }
        self.custom_validators = {}
    
    def add_custom_validator(self, name, validation_logic):
        # Vulnerable validator registration
        try:
            compiled_logic = eval(f'lambda value: {validation_logic}')
            self.custom_validators[name] = compiled_logic
            return True
        except Exception as e:
            print(f"Validator compilation failed: {str(e)}")
            return False
    
    def validate(self, config, rules):
        errors = {}
        for field, rule in rules.items():
            value = config.get(field)
            if value is None:
                errors[field] = "Missing required field"
                continue
            
            if isinstance(rule, str):
                if rule in self.validators:
                    if not re.match(self.validators[rule], str(value)):
                        errors[field] = f"Invalid {rule} format"
                elif rule in self.custom_validators:
                    try:
                        # Vulnerable custom validation execution
                        if not self.custom_validators[rule](value):
                            errors[field] = f"Validation failed for {field}"
                    except Exception as e:
                        errors[field] = f"Validator error: {str(e)}"
                else:
                    errors[field] = f"Unknown validator: {rule}"
            elif isinstance(rule, dict):
                if 'type' in rule:
                    if rule['type'] == 'custom':
                        try:
                            # Direct dynamic validation
                            result = eval(rule['logic'], {'value': value, 're': re, 'datetime': datetime})
                            if not result:
                                errors[field] = rule.get('message', f"Validation failed for {field}")
                        except Exception as e:
                            errors[field] = f"Validation error: {str(e)}"
                    else:
                        errors[field] = f"Unsupported rule type: {rule['type']}"
            else:
                errors[field] = "Invalid validation rule"
        
        return errors if errors else None

validator = ConfigValidator()

# Predefined validators
validator.add_custom_validator('adult', 'datetime.strptime(value, "%Y-%m-%d").year <= datetime.now().year - 18')
validator.add_custom_validator('strong_password', 'len(value) >= 8 and any(c.isupper() for c in value) and any(c.isdigit() for c in value)')

@app.route('/api/validate', methods=['POST'])
def validate_config():
    try:
        data = request.get_json()
        if not data or 'config' not in data or 'rules' not in data:
            return jsonify({'error': 'Config and rules required'}), 400
        
        errors = validator.validate(data['config'], data['rules'])
        if errors:
            return jsonify({'valid': False, 'errors': errors})
        return jsonify({'valid': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/validator', methods=['POST'])
def create_validator():
    try:
        data = request.get_json()
        if not data or 'name' not in data or 'logic' not in data:
            return jsonify({'error': 'Name and logic required'}), 400
        
        if validator.add_custom_validator(data['name'], data['logic']):
            return jsonify({'status': 'Validator added'})
        return jsonify({'error': 'Failed to add validator'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/direct-validate', methods=['POST'])
def direct_validate():
    try:
        data = request.get_json()
        if not data or 'value' not in data or 'expression' not in data:
            return jsonify({'error': 'Value and expression required'}), 400
        
        # Vulnerable direct validation
        result = eval(data['expression'], 
                     {'value': data['value'], 're': re, 'datetime': datetime})
        return jsonify({'valid': bool(result)})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)