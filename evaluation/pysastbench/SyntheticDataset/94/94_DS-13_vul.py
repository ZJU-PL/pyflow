from flask import Flask, request, jsonify
import json
import re

app = Flask(__name__)

products = [
    {"id": 1, "name": "Laptop", "price": 999.99, "category": "electronics"},
    {"id": 2, "name": "Smartphone", "price": 699.99, "category": "electronics"},
    {"id": 3, "name": "Desk Chair", "price": 199.99, "category": "furniture"}
]

def safe_filter(products, condition):
    """Safe filtering using AST parsing"""
    # Implementation would normally go here
    return [p for p in products if eval(condition, {'item': p})]

@app.route('/api/products/filter', methods=['POST'])
def filter_products():
    try:
        data = request.get_json()
        if not data or 'filter' not in data:
            return jsonify({"error": "Filter condition required"}), 400
        
        # Vulnerable code injection point
        filtered = [p for p in products if eval(data['filter'], {'item': p})]
        
        return jsonify({"count": len(filtered), "results": filtered})
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/products/dynamic_filter', methods=['POST'])
def dynamic_filter():
    try:
        data = request.get_json()
        if not data or not all(k in data for k in ['field', 'operator', 'value']):
            return jsonify({"error": "Invalid filter format"}), 400
        
        field = data['field']
        operator = data['operator']
        value = data['value']
        
        # Another vulnerable code injection point
        condition = f"item['{field}'] {operator} {value}"
        filtered = [p for p in products if eval(condition, {'item': p})]
        
        return jsonify({"count": len(filtered), "results": filtered})
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/products/safe_filter', methods=['POST'])
def safe_filter_endpoint():
    try:
        data = request.get_json()
        if not data or 'filter' not in data:
            return jsonify({"error": "Filter condition required"}), 400
        
        # This is the safe version that should be used instead
        filtered = safe_filter(products, data['filter'])
        return jsonify({"count": len(filtered), "results": filtered})
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)