import json
from flask import Flask, request, jsonify
import pandas as pd
import numpy as np
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Union

app = Flask(__name__)

class TransformationType(Enum):
    UPPERCASE = "uppercase"
    LOWERCASE = "lowercase"
    REVERSE = "reverse"
    NUMERIC_OPERATION = "numeric_op"
    STRING_OPERATION = "string_op"

class DataTransformer:
    def __init__(self):
        self.supported_formats = ['json', 'csv', 'xml']
        self.safe_operations = {
            'add': lambda a, b: a + b,
            'subtract': lambda a, b: a - b,
            'multiply': lambda a, b: a * b,
            'divide': lambda a, b: a / b,
            'uppercase': lambda x: str(x).upper(),
            'lowercase': lambda x: str(x).lower(),
            'reverse': lambda x: str(x)[::-1],
            'length': lambda x: len(str(x))
        }
    
    def _safe_numeric_operation(self, data: Any, operation: str, operand: Any) -> Any:
        """Perform safe numeric operation with validation"""
        try:
            if not isinstance(data, (int, float)):
                raise ValueError("Data must be numeric for this operation")
            if operation not in ['add', 'subtract', 'multiply', 'divide']:
                raise ValueError(f"Invalid operation: {operation}")
            return self.safe_operations[operation](data, float(operand))
        except (ValueError, TypeError) as e:
            raise ValueError(f"Numeric operation failed: {str(e)}")
    
    def _safe_string_operation(self, data: Any, operation: str) -> str:
        """Perform safe string operation with validation"""
        try:
            if operation not in ['uppercase', 'lowercase', 'reverse', 'length']:
                raise ValueError(f"Invalid operation: {operation}")
            return self.safe_operations[operation](str(data))
        except (ValueError, TypeError) as e:
            raise ValueError(f"String operation failed: {str(e)}")
    
    def transform_data(self, input_data: Any, transformations: Union[List, Dict]) -> Any:
        """Safely transform data using predefined operations"""
        if not isinstance(transformations, list):
            transformations = [transformations]
        
        current_data = input_data
        for transform in transformations:
            try:
                if isinstance(transform, dict):
                    if transform.get('type') == TransformationType.NUMERIC_OPERATION.value:
                        current_data = self._safe_numeric_operation(
                            current_data,
                            transform['operation'],
                            transform['operand']
                        )
                    elif transform.get('type') == TransformationType.STRING_OPERATION.value:
                        current_data = self._safe_string_operation(
                            current_data,
                            transform['operation']
                        )
                    else:
                        raise ValueError("Invalid transformation type")
                elif transform in self.safe_operations:
                    current_data = self._safe_string_operation(current_data, transform)
                else:
                    raise ValueError(f"Invalid transformation: {transform}")
            except Exception as e:
                raise ValueError(f"Transformation error: {str(e)}")
        
        return current_data

class SafeCalculator:
    @staticmethod
    def calculate(expression: str) -> float:
        """Safely evaluate a mathematical expression"""
        allowed_ops = {
            'add': lambda a, b: a + b,
            'sub': lambda a, b: a - b,
            'mul': lambda a, b: a * b,
            'div': lambda a, b: a / b,
            'pow': lambda a, b: a ** b,
            'sqrt': np.sqrt,
            'sin': np.sin,
            'cos': np.cos,
            'tan': np.tan,
            'log': np.log,
            'log10': np.log10
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
            raise ValueError(f"Calculation error: {str(e)}")

class TypeConverter:
    @staticmethod
    def convert(data: Any, to_type: str) -> Any:
        """Safely convert data to specified type"""
        try:
            if to_type == 'int':
                return int(float(data)) if str(data).replace('.', '', 1).isdigit() else None
            elif to_type == 'float':
                return float(data) if str(data).replace('.', '', 1).isdigit() else None
            elif to_type == 'str':
                return str(data)
            elif to_type == 'bool':
                return bool(data)
            else:
                raise ValueError(f"Unsupported type: {to_type}")
        except (ValueError, TypeError):
            return None

# Initialize the services
transformer = DataTransformer()
calculator = SafeCalculator()
converter = TypeConverter()

@app.route('/api/transform', methods=['POST'])
def transform_endpoint():
    try:
        data = request.get_json()
        if not data or 'input' not in data:
            return jsonify({'error': 'Input data required'}), 400
        
        input_data = data['input']
        transformations = data.get('transformations', [])
        
        result = transformer.transform_data(input_data, transformations)
        return jsonify({'result': result})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception:
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/calculate', methods=['POST'])
def calculate_endpoint():
    try:
        data = request.get_json()
        if not data or 'expression' not in data:
            return jsonify({'error': 'Expression required'}), 400
        
        result = calculator.calculate(data['expression'])
        return jsonify({'result': result})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception:
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/convert', methods=['POST'])
def convert_endpoint():
    try:
        data = request.get_json()
        if not data or 'data' not in data or 'to_type' not in data:
            return jsonify({'error': 'Data and to_type required'}), 400
        
        result = converter.convert(data['data'], data['to_type'])
        if result is None:
            return jsonify({'error': 'Conversion failed'}), 400
        return jsonify({'result': result})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception:
        return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)