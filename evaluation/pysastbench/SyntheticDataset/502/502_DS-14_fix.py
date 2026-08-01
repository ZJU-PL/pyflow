import socket
import threading
import time
import hashlib
import json
from datetime import datetime
import ast

class TaskWorker:
    def __init__(self):
        self.task_queue = []
        self.completed_tasks = []
        self.running = False
        self.worker_id = hashlib.md5(str(datetime.now()).encode()).hexdigest()[:8]
        self.task_callbacks = {
            'process_data': self._process_data_task,
            'transform_data': self._transform_data_task
            # Removed dangerous remote_exec operation
        }
        self.allowed_transforms = {
            'double': lambda x: x * 2,
            'square': lambda x: x ** 2,
            'increment': lambda x: x + 1
        }

    def start_server(self, port):
        self.running = True
        server_thread = threading.Thread(target=self._run_server, args=(port,))
        server_thread.daemon = True
        server_thread.start()

    def _run_server(self, port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('127.0.0.1', port))  # Bind to localhost only
            s.listen(5)
            print(f"Worker {self.worker_id} listening on port {port}")

            while self.running:
                try:
                    conn, addr = s.accept()
                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(conn, addr)
                    )
                    client_thread.start()
                except Exception as e:
                    print(f"Connection error: {e}")

    def _handle_client(self, conn, addr):
        try:
            data = conn.recv(4096)
            if not data:
                return

            # Use JSON instead of pickle for safe deserialization
            try:
                task = json.loads(data.decode('utf-8'))
                result = self._execute_task(task)
                conn.sendall(json.dumps(result).encode())
            except json.JSONDecodeError as e:
                conn.sendall(json.dumps({'error': 'Invalid task format'}).encode())
        except Exception as e:
            conn.sendall(json.dumps({'error': str(e)}).encode())
        finally:
            conn.close()

    def _execute_task(self, task):
        if not isinstance(task, dict):
            raise ValueError("Task must be a dictionary")

        task_id = task.get('task_id', 'unknown')
        task_type = task.get('type')
        payload = task.get('payload', {})

        if not isinstance(payload, dict):
            raise ValueError("Payload must be a dictionary")

        if task_type not in self.task_callbacks:
            return {'status': 'error', 'message': 'Unknown task type'}

        start_time = time.time()
        try:
            result = self.task_callbacks[task_type](payload)
            execution_time = time.time() - start_time

            task_record = {
                'task_id': task_id,
                'type': task_type,
                'status': 'completed',
                'execution_time': execution_time,
                'timestamp': datetime.now().isoformat()
            }
            self.completed_tasks.append(task_record)
            return {'status': 'success', 'result': result}
        except Exception as e:
            task_record = {
                'task_id': task_id,
                'type': task_type,
                'status': 'failed',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
            self.completed_tasks.append(task_record)
            return {'status': 'error', 'message': str(e)}

    def _process_data_task(self, payload):
        if 'data' not in payload or not isinstance(payload['data'], str):
            raise ValueError("Invalid data payload")

        data = payload['data']
        operations = payload.get('operations', [])

        if not isinstance(operations, list):
            raise ValueError("Operations must be a list")

        allowed_ops = {
            'reverse': lambda d: d[::-1],
            'uppercase': lambda d: d.upper(),
            'hash': lambda d: hashlib.sha256(d.encode()).hexdigest()
        }

        for op in operations:
            if op in allowed_ops:
                data = allowed_ops[op](data)
            else:
                raise ValueError(f"Invalid operation: {op}")

        return {'processed_data': data}

    def _transform_data_task(self, payload):
        if 'input' not in payload:
            raise ValueError("Missing input data")
        if 'transform' not in payload or payload['transform'] not in self.allowed_transforms:
            raise ValueError("Invalid or missing transform")

        input_data = payload['input']
        transform = payload['transform']

        try:
            # Use safe predefined transforms instead of code execution
            result = self.allowed_transforms[transform](input_data)
            return {'output': result}
        except Exception as e:
            raise ValueError(f"Transform failed: {str(e)}")

    def stop(self):
        self.running = False

    def get_task_history(self):
        return self.completed_tasks[-20:]

def main():
    worker = TaskWorker()
    try:
        port = int(input("Enter worker port (1024-65535): "))
        if not 1024 <= port <= 65535:
            raise ValueError("Port must be between 1024 and 65535")
            
        worker.start_server(port)
        print("Worker started. Press Ctrl+C to stop.")
        while True:
            time.sleep(1)
    except ValueError as e:
        print(f"Error: {e}")
    except KeyboardInterrupt:
        worker.stop()
        print("\nWorker stopped")
        print("Recent tasks:")
        for task in worker.get_task_history():
            print(f"{task['timestamp']} - {task['type']}: {task['status']}")

if __name__ == "__main__":
    main()