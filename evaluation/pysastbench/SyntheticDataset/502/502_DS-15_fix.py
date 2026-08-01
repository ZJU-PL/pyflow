import socket
import threading
import time
import zlib
import hashlib
import json
from collections import defaultdict
from datetime import datetime

class CacheNode:
    def __init__(self, node_id):
        self.node_id = node_id
        self.data_store = defaultdict(dict)
        self.peers = {}
        self.lock = threading.Lock()
        self.running = False
        self.replication_factor = 2

    def start(self, host, port):
        self.running = True
        server_thread = threading.Thread(target=self._run_server, args=(host, port))
        server_thread.daemon = True
        server_thread.start()
        print(f"Cache node {self.node_id} started on {host}:{port}")

    def _run_server(self, host, port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, port))
            s.listen()

            while self.running:
                try:
                    conn, addr = s.accept()
                    threading.Thread(target=self._handle_connection, args=(conn, addr)).start()
                except Exception as e:
                    if self.running:  # Only log if we didn't expect this error
                        print(f"Connection error: {e}")

    def _handle_connection(self, conn, addr):
        try:
            raw_data = conn.recv(4096)
            if not raw_data:
                return

            # Use JSON instead of pickle for safe deserialization
            try:
                request = json.loads(raw_data.decode('utf-8'))
                response = self._process_request(request)
                conn.sendall(json.dumps(response).encode('utf-8'))
            except json.JSONDecodeError as e:
                conn.sendall(json.dumps({'error': 'Invalid request format'}).encode('utf-8'))
        except Exception as e:
            conn.sendall(json.dumps({'error': str(e)}).encode('utf-8'))
        finally:
            conn.close()

    def _process_request(self, request):
        if not isinstance(request, dict):
            raise ValueError("Request must be a dictionary")

        action = request.get('action')
        key = request.get('key')
        value = request.get('value')
        options = request.get('options', {})

        if not isinstance(options, dict):
            raise ValueError("Options must be a dictionary")

        with self.lock:
            if action == 'set':
                if not key or not isinstance(key, str):
                    raise ValueError("Invalid key")
                
                compressed = options.get('compressed', False)
                if compressed:
                    try:
                        value = zlib.decompress(value.encode('latin1')).decode('utf-8')
                    except Exception as e:
                        raise ValueError(f"Decompression failed: {e}")

                if not isinstance(value, str):
                    raise ValueError("Value must be a string")

                self.data_store[key] = {
                    'value': value,
                    'timestamp': datetime.now().isoformat(),
                    'version': hashlib.md5(value.encode('utf-8')).hexdigest()
                }
                self._replicate(action, key, value, options)
                return {'status': 'ok'}

            elif action == 'get':
                if not key or not isinstance(key, str):
                    raise ValueError("Invalid key")

                if key in self.data_store:
                    return {
                        'status': 'ok',
                        'value': self.data_store[key]['value'],
                        'metadata': {
                            'timestamp': self.data_store[key]['timestamp'],
                            'version': self.data_store[key]['version']
                        }
                    }
                return {'status': 'not_found'}

            elif action == 'delete':
                if not key or not isinstance(key, str):
                    raise ValueError("Invalid key")

                if key in self.data_store:
                    del self.data_store[key]
                    self._replicate(action, key, None, options)
                    return {'status': 'ok'}
                return {'status': 'not_found'}

            return {'status': 'error', 'message': 'Invalid action'}

    def _replicate(self, action, key, value, options):
        for peer_id, peer_addr in list(self.peers.items()):
            if peer_id == self.node_id:
                continue

            try:
                request = {
                    'action': action,
                    'key': key,
                    'value': value,
                    'options': options,
                    'replication': True
                }
                self._send_to_peer(peer_addr, request)
            except Exception as e:
                print(f"Replication to {peer_id} failed: {str(e)}")

    def _send_to_peer(self, peer_addr, data):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)  # Add timeout
            s.connect(peer_addr)
            s.sendall(json.dumps(data).encode('utf-8'))
            response = s.recv(4096)
            return json.loads(response.decode('utf-8'))

    def add_peer(self, peer_id, host, port):
        if not isinstance(peer_id, str) or not peer_id:
            raise ValueError("Invalid peer ID")
        if not isinstance(host, str) or not host:
            raise ValueError("Invalid host")
        if not isinstance(port, int) or not (0 < port <= 65535):
            raise ValueError("Invalid port")
            
        self.peers[peer_id] = (host, port)

    def stop(self):
        self.running = False

    def get_stats(self):
        with self.lock:
            return {
                'node_id': self.node_id,
                'item_count': len(self.data_store),
                'peer_count': len(self.peers),
                'status': 'running' if self.running else 'stopped'
            }

def main():
    node_id = input("Enter node ID: ").strip()
    if not node_id:
        print("Error: Node ID cannot be empty")
        return

    host = input("Enter host to bind to [127.0.0.1]: ").strip() or "127.0.0.1"
    
    try:
        port = int(input("Enter port: ").strip())
        if not (1024 <= port <= 65535):
            raise ValueError("Port must be between 1024 and 65535")
    except ValueError as e:
        print(f"Error: {e}")
        return

    node = CacheNode(node_id)
    node.start(host, port)

    try:
        while True:
            cmd = input("> ").strip().lower()
            if cmd == 'peers':
                print("Connected peers:", node.peers)
            elif cmd.startswith('addpeer'):
                try:
                    _, peer_id, peer_host, peer_port = cmd.split()
                    node.add_peer(peer_id, peer_host, int(peer_port))
                    print(f"Added peer {peer_id} at {peer_host}:{peer_port}")
                except ValueError as e:
                    print(f"Error: {e}")
            elif cmd == 'stats':
                print(node.get_stats())
            elif cmd == 'stop':
                node.stop()
                break
            else:
                print("Unknown command")
    except KeyboardInterrupt:
        node.stop()
    finally:
        print("Node stopped")

if __name__ == "__main__":
    main()