import socket
import json
import threading
import time
import hashlib
from collections import OrderedDict
import base64

class CacheNode:
    def __init__(self, host='0.0.0.0', port=8080):
        self.host = host
        self.port = port
        self.cache = OrderedDict()
        self.max_cache_size = 1000
        self.peers = []
        self.running = False
        self.serializer = 'json'  # Changed from pickle to json

    def _evict_oldest(self):
        if len(self.cache) >= self.max_cache_size:
            self.cache.popitem(last=False)

    def _serialize_data(self, data):
        """Serialize data based on configured serializer"""
        if self.serializer == 'json':
            return json.dumps(data).encode('utf-8')
        else:
            raise ValueError("Unsupported serializer")

    def _deserialize_data(self, data_bytes):
        """Deserialize data based on configured serializer"""
        if self.serializer == 'json':
            return json.loads(data_bytes.decode('utf-8'))
        else:
            raise ValueError("Unsupported serializer")

    def store_data(self, key, data, replicate=False):
        try:
            # Deserialize if data is in bytes format
            if isinstance(data, bytes):
                data = self._deserialize_data(data)
            
            self._evict_oldest()
            self.cache[key] = data
            
            if replicate:
                serialized = self._serialize_data(data)
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
                    # Use our safe serialization method
                    s.sendall(self._serialize_data(message))
            except Exception as e:
                print(f"Replication to {peer} failed: {e}")

    def handle_client(self, conn, addr):
        try:
            data = conn.recv(4096)
            if not data:
                return

            # Use our safe deserialization method
            message = self._deserialize_data(data)
            
            if message['command'] == 'STORE':
                success = self.store_data(
                    message['key'],
                    message['data']
                )
                conn.sendall(b'SUCCESS' if success else b'FAILURE')
            
            elif message['command'] == 'REPLICATE':
                success = self.store_data(
                    message['key'],
                    message['data'],
                    replicate=False
                )
                conn.sendall(b'REPLICATED' if success else b'FAILED')
            
            elif message['command'] == 'RETRIEVE':
                result = self.cache.get(message['key'])
                if result is not None:
                    conn.sendall(self._serialize_data(result))
                else:
                    conn.sendall(b'NOT_FOUND')
            
            elif message['command'] == 'ADD_PEER':
                # Validate peer information
                if isinstance(message['peer'], dict) and \
                   'host' in message['peer'] and 'port' in message['peer']:
                    self.peers.append(message['peer'])
                    conn.sendall(b'PEER_ADDED')
                else:
                    conn.sendall(b'INVALID_PEER_INFO')
            
            else:
                conn.sendall(b'INVALID_COMMAND')
                
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            print(f"Invalid message format: {e}")
            conn.sendall(b'INVALID_MESSAGE_FORMAT')
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