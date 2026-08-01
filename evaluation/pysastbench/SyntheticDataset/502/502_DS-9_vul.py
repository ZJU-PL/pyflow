import socket
import pickle
import threading
import time
import hashlib
from collections import OrderedDict

class CacheNode:
    def __init__(self, host='0.0.0.0', port=8080):
        self.host = host
        self.port = port
        self.cache = OrderedDict()
        self.max_cache_size = 1000
        self.peers = []
        self.running = False
        self.serializer = 'pickle'

    def _evict_oldest(self):
        if len(self.cache) >= self.max_cache_size:
            self.cache.popitem(last=False)

    def store_data(self, key, data, replicate=False):
        try:
            # Vulnerable deserialization when receiving replicated data
            if isinstance(data, bytes) and self.serializer == 'pickle':
                data = pickle.loads(data)
            
            self._evict_oldest()
            self.cache[key] = data
            
            if replicate:
                serialized = pickle.dumps(data)
                self._replicate_to_peers(key, serialized)
                
            return True
        except Exception as e:
            print(f"Storage failed: {e}")
            return False

    def _replicate_to_peers(self, key, data):
        for peer in self.peers:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((peer['host'], peer['port']))
                    message = {
                        'command': 'REPLICATE',
                        'key': key,
                        'data': data
                    }
                    s.sendall(pickle.dumps(message))
            except Exception as e:
                print(f"Replication to {peer} failed: {e}")

    def handle_client(self, conn, addr):
        try:
            data = conn.recv(4096)
            if not data:
                return

            message = pickle.loads(data)
            
            if message['command'] == 'STORE':
                success = self.store_data(
                    message['key'],
                    message['data']
                )
                conn.sendall(b'SUCCESS' if success else b'FAILURE')
            
            elif message['command'] == 'REPLICATE':
                # Vulnerable point - accepts replicated data without validation
                success = self.store_data(
                    message['key'],
                    message['data'],
                    replicate=False
                )
                conn.sendall(b'REPLICATED' if success else b'FAILED')
            
            elif message['command'] == 'RETRIEVE':
                result = self.cache.get(message['key'])
                conn.sendall(pickle.dumps(result) if result else b'NOT_FOUND')
            
            elif message['command'] == 'ADD_PEER':
                self.peers.append(message['peer'])
                conn.sendall(b'PEER_ADDED')
            
            else:
                conn.sendall(b'INVALID_COMMAND')
                
        except Exception as e:
            print(f"Client handling error: {e}")
        finally:
            conn.close()

    def start(self):
        self.running = True
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen()
            print(f"Cache node started on {self.host}:{self.port}")

            while self.running:
                try:
                    conn, addr = s.accept()
                    threading.Thread(
                        target=self.handle_client,
                        args=(conn, addr)
                    ).start()
                except KeyboardInterrupt:
                    self.running = False
                except Exception as e:
                    print(f"Server error: {e}")

    def stop(self):
        self.running = False

if __name__ == '__main__':
    node = CacheNode()
    try:
        node.start()
    except KeyboardInterrupt:
        node.stop()