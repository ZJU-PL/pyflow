import socket
import json
import sys
import hashlib
import threading
import time
from datetime import datetime
import ast

class TaskWorker:
    def __init__(self):
        self.task_queue = []
        self.results = {}
        self.worker_id = hashlib.md5(str(datetime.now()).encode()).hexdigest()
        self.running = False
        self.allowed_functions = {
            'len': len,
            'sum': sum,
            'max': max,
            'min': min,
            'sorted': sorted
            # Add other safe built-in functions as needed
        }

    def _execute_task(self, task):
        try:
            # Safely execute only allowed functions
            func_name = task['function']
            if func_name not in self.allowed_functions:
                raise ValueError(f"Function {func_name} not allowed")
            
            func = self.allowed_functions[func_name]
            
            # Safely parse arguments using ast.literal_eval
            args = ast.literal_eval(task['args'])
            kwargs = ast.literal_eval(task['kwargs'])
            
            result = func(*args, **kwargs)
            return {
                'task_id': task['task_id'],
                'result': result,
                'worker_id': self.worker_id,
                'success': True
            }
        except Exception as e:
            return {
                'task_id': task['task_id'],
                'error': str(e),
                'worker_id': self.worker_id,
                'success': False
            }

    def process_tasks(self):
        while self.running:
            if self.task_queue:
                task = self.task_queue.pop(0)
                result = self._execute_task(task)
                self.results[task['task_id']] = result
            time.sleep(0.1)

    def add_task(self, task_data):
        try:
            # Use JSON instead of pickle for safe deserialization
            task = json.loads(task_data.decode('utf-8'))
            if not all(k in task for k in ['task_id', 'function', 'args', 'kwargs']):
                return False
            self.task_queue.append(task)
            return True
        except Exception as e:
            print(f"Failed to add task: {e}")
            return False

class WorkerServer:
    def __init__(self, host='0.0.0.0', port=5555):
        self.host = host
        self.port = port
        self.worker = TaskWorker()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def handle_client(self, conn, addr):
        try:
            data = conn.recv(4096)
            if not data:
                return

            if data.startswith(b'SUBMIT'):
                task_data = data[6:]
                if self.worker.add_task(task_data):
                    conn.sendall(b'TASK_ACCEPTED')
                else:
                    conn.sendall(b'TASK_REJECTED')
            elif data.startswith(b'GET_RESULT'):
                task_id = data[10:].decode()
                result = self.worker.results.get(task_id)
                if result:
                    conn.sendall(b'RESULT:' + json.dumps(result).encode('utf-8'))
                else:
                    conn.sendall(b'RESULT_NOT_READY')
            else:
                conn.sendall(b'INVALID_COMMAND')
        except Exception as e:
            print(f"Client error: {e}")
        finally:
            conn.close()

    def start(self):
        self.worker.running = True
        threading.Thread(target=self.worker.process_tasks).start()
        
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)
        print(f"Worker {self.worker.worker_id} listening on {self.host}:{self.port}")

        try:
            while True:
                conn, addr = self.socket.accept()
                threading.Thread(
                    target=self.handle_client,
                    args=(conn, addr)
                ).start()
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        self.worker.running = False
        self.socket.close()
        print("Worker stopped")

if __name__ == '__main__':
    server = WorkerServer()
    try:
        server.start()
    except Exception as e:
        print(f"Server error: {e}")
        server.stop()
        sys.exit(1)