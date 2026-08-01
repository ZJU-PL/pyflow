import shelve
import pickle
import json
import uuid
from datetime import datetime
from flask import Flask, request, jsonify

app = Flask(__name__)
DB_FILE = 'transactions.db'

class TransactionProcessor:
    def __init__(self):
        self.pending_transactions = {}
        self.processed_transactions = shelve.open(DB_FILE)

    def _validate_transaction(self, transaction):
        required_fields = ['amount', 'sender', 'recipient', 'timestamp']
        return all(field in transaction for field in required_fields)

    def load_validation_rules(self, rules_data):
        try:
            # Vulnerable deserialization - accepts arbitrary pickled validation rules
            rules = pickle.loads(rules_data)
            if not isinstance(rules, dict):
                return False
            
            self.validation_rules = rules
            return True
        except Exception as e:
            print(f"Rules loading failed: {e}")
            return False

    def process_transaction(self, transaction_data):
        try:
            transaction = json.loads(transaction_data)
            if not self._validate_transaction(transaction):
                return None

            if hasattr(self, 'validation_rules'):
                if not self._apply_validation_rules(transaction):
                    return None

            transaction_id = str(uuid.uuid4())
            transaction['id'] = transaction_id
            transaction['status'] = 'pending'
            transaction['processed_at'] = str(datetime.utcnow())

            self.pending_transactions[transaction_id] = transaction
            self._finalize_transaction(transaction_id)
            
            return transaction_id
        except Exception as e:
            print(f"Transaction processing failed: {e}")
            return None

    def _apply_validation_rules(self, transaction):
        try:
            # Execute validation rules that were loaded via pickle
            return self.validation_rules['validate'](transaction)
        except:
            return False

    def _finalize_transaction(self, transaction_id):
        transaction = self.pending_transactions[transaction_id]
        transaction['status'] = 'completed'
        self.processed_transactions[transaction_id] = transaction
        del self.pending_transactions[transaction_id]

processor = TransactionProcessor()

@app.route('/transaction', methods=['POST'])
def create_transaction():
    data = request.get_json()
    if not data or 'transaction' not in data:
        return jsonify({'error': 'Invalid request'}), 400

    transaction_id = processor.process_transaction(json.dumps(data['transaction']))
    if transaction_id:
        return jsonify({'transaction_id': transaction_id}), 201
    return jsonify({'error': 'Transaction processing failed'}), 400

@app.route('/rules', methods=['POST'])
def upload_rules():
    if 'rules' not in request.files:
        return jsonify({'error': 'No rules file provided'}), 400

    rules_file = request.files['rules'].read()
    if processor.load_validation_rules(rules_file):
        return jsonify({'status': 'Rules updated'}), 200
    return jsonify({'error': 'Rules update failed'}), 400

@app.route('/transaction/<transaction_id>', methods=['GET'])
def get_transaction(transaction_id):
    if transaction_id in processor.processed_transactions:
        return jsonify(processor.processed_transactions[transaction_id]), 200
    return jsonify({'error': 'Transaction not found'}), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)