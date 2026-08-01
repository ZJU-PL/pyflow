import json
from flask import Flask, request, jsonify
import re
from datetime import datetime
from enum import Enum
from typing import Dict, Any, Optional

app = Flask(__name__)

class ValidatorType(Enum):
    REGEX = "regex"
    COMPARISON = "comparison"
    DATE = "date"
    CUSTOM_LOGIC = "custom_logic"

class ConfigValidator:
    def __init__(self):
        self.validators = {
            'email': {
                'type': ValidatorType.REGEX.value,
                'pattern': r'^[^@]+@[^@]+\.[^@]+$'
            },
            'phone': {
                'type': ValidatorType.REGEX.value,
                'pattern': r'^\d{10}$'
            },
            'date': {
                'type': ValidatorType.REGEX.value,
                'pattern': r'^\d{4}-\d{2}-\d{2}$'
            },
            'adult': {
                'type': ValidatorType.DATE.value,
                'min_years': 18
            },
            'strong_password': {
                'type': ValidatorType.CUSTOM_LOGIC.value,
                'checks': [
                    {'type': 'length', 'min': 8},
                    {'type': 'has_upper'},
                    {'type': 'has_digit'}
                ]
            }
        }
    
    def add_custom_validator(self, name: str, validator_def: Dict) -> bool:
        """Safely add a custom validator with predefined checks"""
        try:
            if not isinstance(validator_def, dict) or 'type' not in validator_def:
                return False
            
            validator_type = ValidatorType(validator_def['type'])
            
            if validator_type == ValidatorType.REGEX:
                if not isinstance(validator_def.get('pattern'), str):
                    return False
                # Test compile the regex to ensure it's valid
                re.compile(validator_def['pattern'])
            
            elif validator_type == ValidatorType.COMPARISON:
                if not isinstance(validator_def.get('operator'), str):
                    return False
                if validator_def.get('value') is None:
                    return False
            
            elif validator_type == ValidatorType.DATE:
                if not isinstance(validator_def.get('min_years'), int):
                    return False
            
            elif validator_type == ValidatorType.CUSTOM_LOGIC:
                if not isinstance(validator_def.get('checks'), list):
                    return False
                for check in validator_def['checks']:
                    if not isinstance(check, dict) or 'type' not in check:
                        return False
            
            self.validators[name] = validator_def
            return True
        except (ValueError, re.error):
            return False
    
    def _validate_regex(self, value: Any, pattern: str) -> bool:
        """Validate a value against a regex pattern"""
        try:
            return bool(re.match(pattern, str(value)))
        except (TypeError, re.error):
            return False
    
    def _validate_comparison(self, value: Any, operator: str, compare_to: Any) -> bool:
        """Validate a comparison operation"""
        try:
            if operator == '==':
                return value == compare_to
            elif operator == '!=':
                return value != compare_to
            elif operator == '>':
                return value > compare_to
            elif operator == '<':
                return value < compare_to
            elif operator == '>=':
                return value >= compare_to
            elif operator == '<=':
                return value <= compare_to
            return False
        except TypeError:
            return False
    
    def _validate_date(self, value: Any, min_years: int) -> bool:
        """Validate a date is at least min_years years old"""
        try:
            birth_date = datetime.strptime(str(value), "%Y-%m-%d")
            age = datetime.now().year - birth_date.year
            return age >= min_years
        except (ValueError, TypeError):
            return False
    
    def _validate_custom_logic(self, value: Any, checks: List[Dict]) -> bool:
        """Validate using predefined custom logic checks"""
        str_value = str(value)
        for check in checks:
            check_type = check['type']
            if check_type == 'length':
                if len(str_value) < check.get('min', 0):
                    return False
            elif check_type == 'has_upper':
                if not any(c.isupper() for c in str_value):
                    return False
            elif check_type == 'has_digit':
                if not any(c.isdigit() for c in str_value):
                    return False
            elif check_type == 'has_special':
                if not any(not c.isalnum() for c in str_value):
                    return False
        return True
    
    def validate(self, config: Dict, rules: Dict) -> Optional[Dict]:
        """Validate configuration against rules"""
        errors = {}
        for field, rule in rules.items():
            value = config.get(field)
            if value is None:
                errors[field] = "Missing required field"
                continue
            
            if isinstance(rule, str):
                validator_def = self.validators.get(rule)
                if not validator_def:
                    errors[field] = f"Unknown validator: {rule}"
                    continue
                
                validator_type = ValidatorType(validator_def['type'])
                valid = False
                
                if validator_type == ValidatorType.REGEX:
                    valid = self._validate_regex(value, validator_def['pattern'])
                elif validator_type == ValidatorType.DATE:
                    valid = self._validate_date(value, validator_def['min_years'])
                elif validator_type == ValidatorType.CUSTOM_LOGIC:
                    valid = self._validate_custom_logic(value, validator_def['checks'])
                
                if not valid:
                    errors[field] = f"Validation failed for {rule}"
            
            elif isinstance(rule, dict):
                if 'type' not in rule:
                    errors[field] = "Missing validator type"
                    continue
                
                try:
                    validator_type = ValidatorType(rule['type'])
                    valid = False
                    
                    if validator_type == ValidatorType.REGEX:
                        valid = self._validate_regex(value, rule['pattern'])
                    elif validator_type == ValidatorType.COMPARISON:
                        valid = self._validate_comparison(
                            value, 
                            rule['operator'], 
                            rule['value']
                        )
                    elif validator_type == ValidatorType.DATE:
                        valid = self._validate_date(value, rule['min_years'])
                    
                    if not valid:
                        errors[field] = rule.get('message', f"Validation failed for {field}")
                except ValueError:
                    errors[field] = f"Unsupported validator type: {rule['type']}"
            else:
                errors[field] = "Invalid validation rule"
        
        return errors if errors else None

validator = ConfigValidator()

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
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/validator', methods=['POST'])
def create_validator():
    try:
        data = request.get_json()
        if not data or 'name' not in data or 'definition' not in data:
            return jsonify({'error': 'Name and definition required'}), 400
        
        if validator.add_custom_validator(data['name'], data['definition']):
            return jsonify({'status': 'Validator added'})
        return jsonify({'error': 'Invalid validator definition'}), 400
    except Exception:
        return jsonify({'error': 'Internal server error'}), 500

# Removed the vulnerable /api/direct-validate endpoint

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)