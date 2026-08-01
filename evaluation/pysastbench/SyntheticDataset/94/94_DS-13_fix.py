from flask import Flask, request, jsonify
import json
from enum import Enum
from typing import List, Dict, Any

app = Flask(__name__)

# Sample product data
products = [
    {"id": 1, "name": "Laptop", "price": 999.99, "category": "electronics"},
    {"id": 2, "name": "Smartphone", "price": 699.99, "category": "electronics"},
    {"id": 3, "name": "Desk Chair", "price": 199.99, "category": "furniture"}
]

class Operator(Enum):
    EQUAL = "=="
    NOT_EQUAL = "!="
    GREATER = ">"
    GREATER_EQUAL = ">="
    LESS = "<"
    LESS_EQUAL = "<="
    CONTAINS = "contains"
    STARTS_WITH = "startswith"
    ENDS_WITH = "endswith"

def safe_compare(value1: Any, operator: Operator, value2: Any) -> bool:
    """Perform safe comparison between two values"""
    try:
        if operator == Operator.EQUAL:
            return value1 == value2
        elif operator == Operator.NOT_EQUAL:
            return value1 != value2
        elif operator == Operator.GREATER:
            return value1 > value2
        elif operator == Operator.GREATER_EQUAL:
            return value1 >= value2
        elif operator == Operator.LESS:
            return value1 < value2
        elif operator == Operator.LESS_EQUAL:
            return value1 <= value2
        elif operator == Operator.CONTAINS:
            return str(value2) in str(value1)
        elif operator == Operator.STARTS_WITH:
            return str(value1).startswith(str(value2))
        elif operator == Operator.ENDS_WITH:
            return str(value1).endswith(str(value2))
        return False
    except (TypeError, ValueError):
        return False

def safe_filter_products(products: List[Dict], field: str, operator: str, value: Any) -> List[Dict]:
    """Safely filter products based on field, operator, and value"""
    try:
        op = Operator(operator)
        return [
            p for p in products 
            if field in p and safe_compare(p[field], op, value)
        ]
    except ValueError:
        return []

@app.route('/api/products/filter', methods=['POST'])
def filter_products():
    try:
        data = request.get_json()
        if not data or not all(k in data for k in ['field', 'operator', 'value']):
            return jsonify({"error": "Invalid filter format"}), 400
        
        field = str(data['field'])
        operator = str(data['operator'])
        value = data['value']
        
        # Safely filter products
        filtered = safe_filter_products(products, field, operator, value)
        
        return jsonify({
            "count": len(filtered),
            "results": filtered,
            "valid_operators": [op.value for op in Operator]
        })
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/products/search', methods=['POST'])
def search_products():
    """Alternative safe search endpoint"""
    try:
        data = request.get_json()
        if not data or 'query' not in data:
            return jsonify({"error": "Search query required"}), 400
        
        query = str(data['query']).lower()
        filtered = [
            p for p in products
            if any(query in str(v).lower() for k, v in p.items() if k != 'id')
        ]
        
        return jsonify({"count": len(filtered), "results": filtered})
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/products', methods=['GET'])
def list_products():
    """Get all products with optional simple filtering"""
    category = request.args.get('category')
    min_price = request.args.get('min_price', type=float)
    max_price = request.args.get('max_price', type=float)
    
    filtered = products
    if category:
        filtered = [p for p in filtered if p['category'] == category]
    if min_price is not None:
        filtered = [p for p in filtered if p['price'] >= min_price]
    if max_price is not None:
        filtered = [p for p in filtered if p['price'] <= max_price]
    
    return jsonify({"count": len(filtered), "results": filtered})

if __name__ == '__main__':
    app.run(debug=False)  # Disable debug mode in production