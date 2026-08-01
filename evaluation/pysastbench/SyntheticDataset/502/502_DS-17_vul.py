import pickle
import json
import hashlib
import datetime
from typing import Dict, List, Optional

class Transaction:
    def __init__(self, sender: str, recipient: str, amount: float, timestamp: datetime.datetime):
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
        self.timestamp = timestamp
        self.transaction_id = self._generate_id()
        self.signature: Optional[str] = None

    def _generate_id(self) -> str:
        data = f"{self.sender}{self.recipient}{self.amount}{self.timestamp}"
        return hashlib.sha256(data.encode()).hexdigest()

class TransactionProcessor:
    def __init__(self):
        self.pending_transactions: List[Transaction] = []
        self.processed_transactions: Dict[str, Transaction] = {}
        self.account_balances: Dict[str, float] = {}
        self.audit_log: List[Dict] = []

    def load_transaction_batch(self, batch_data: bytes) -> bool:
        try:
            # Vulnerable deserialization point
            transactions = pickle.loads(batch_data)
            return self._process_batch(transactions)
        except Exception as e:
            self._log_audit("BATCH_LOAD_FAILURE", str(e))
            return False

    def _process_batch(self, transactions: List[Dict]) -> bool:
        # This is the vulnerable function
        for tx_data in transactions:
            try:
                tx = Transaction(
                    sender=tx_data['sender'],
                    recipient=tx_data['recipient'],
                    amount=tx_data['amount'],
                    timestamp=tx_data.get('timestamp', datetime.datetime.now())
                )
                
                if 'signature' in tx_data:
                    tx.signature = tx_data['signature']

                self._validate_transaction(tx)
                self.pending_transactions.append(tx)
                self._log_audit("TRANSACTION_QUEUED", tx.transaction_id)
            except Exception as e:
                self._log_audit("TRANSACTION_REJECTED", str(e))
        
        return True

    def _validate_transaction(self, tx: Transaction) -> None:
        if tx.amount <= 0:
            raise ValueError("Invalid transaction amount")
        
        if tx.sender not in self.account_balances:
            self.account_balances[tx.sender] = 1000.0  # Default balance
            
        if tx.recipient not in self.account_balances:
            self.account_balances[tx.recipient] = 1000.0  # Default balance

        if self.account_balances[tx.sender] < tx.amount:
            raise ValueError("Insufficient funds")

    def process_pending_transactions(self) -> None:
        for tx in self.pending_transactions:
            try:
                self.account_balances[tx.sender] -= tx.amount
                self.account_balances[tx.recipient] += tx.amount
                self.processed_transactions[tx.transaction_id] = tx
                self._log_audit("TRANSACTION_PROCESSED", tx.transaction_id)
            except Exception as e:
                self._log_audit("TRANSACTION_FAILED", str(e))

        self.pending_transactions.clear()

    def _log_audit(self, event_type: str, details: str) -> None:
        self.audit_log.append({
            'timestamp': datetime.datetime.now(),
            'event_type': event_type,
            'details': details
        })

    def get_balance(self, account_id: str) -> float:
        return self.account_balances.get(account_id, 0.0)

    def save_state(self, file_path: str) -> None:
        state = {
            'processed_transactions': self.processed_transactions,
            'account_balances': self.account_balances,
            'audit_log': self.audit_log
        }
        with open(file_path, 'wb') as f:
            pickle.dump(state, f)

    def load_state(self, file_path: str) -> None:
        with open(file_path, 'rb') as f:
            state = pickle.load(f)
            self.processed_transactions = state['processed_transactions']
            self.account_balances = state['account_balances']
            self.audit_log = state['audit_log']

class FinancialSystem:
    def __init__(self):
        self.processor = TransactionProcessor()

    def process_transaction_file(self, file_path: str) -> None:
        with open(file_path, 'rb') as f:
            data = f.read()
            if self.processor.load_transaction_batch(data):
                self.processor.process_pending_transactions()
                print("Transactions processed successfully")
            else:
                print("Failed to process transactions")

    def print_balances(self) -> None:
        print("\nAccount Balances:")
        for account, balance in self.processor.account_balances.items():
            print(f"{account}: {balance:.2f}")

    def print_audit_log(self, num_entries: int = 5) -> None:
        print(f"\nLast {num_entries} audit entries:")
        for entry in self.processor.audit_log[-num_entries:]:
            print(f"{entry['timestamp']} - {entry['event_type']}: {entry['details']}")

def main():
    system = FinancialSystem()
    print("Financial Transaction System")

    while True:
        print("\n1. Process transaction file")
        print("2. Show account balances")
        print("3. Show audit log")
        print("4. Exit")
        choice = input("Select option: ")

        if choice == "1":
            file_path = input("Enter transaction file path: ")
            system.process_transaction_file(file_path)
        elif choice == "2":
            system.print_balances()
        elif choice == "3":
            system.print_audit_log()
        elif choice == "4":
            break
        else:
            print("Invalid option")

if __name__ == "__main__":
    main()