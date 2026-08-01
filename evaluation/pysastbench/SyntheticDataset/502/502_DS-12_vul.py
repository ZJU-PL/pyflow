import pickle
import os
import hashlib
from datetime import datetime

class DocumentMetadata:
    def __init__(self):
        self.title = "Untitled"
        self.author = "Unknown"
        self.tags = []
        self.created = datetime.now()
        self.modified = datetime.now()

class DocumentProcessor:
    def __init__(self):
        self.cache = {}
        self.metadata = DocumentMetadata()
        self.parsed_content = None
        self.analytics = {
            'processing_time': 0,
            'word_count': 0,
            'image_count': 0
        }

    def load_serialized_document(self, file_path):
        if not os.path.exists(file_path):
            raise FileNotFoundError("Document file not found")
        
        with open(file_path, 'rb') as f:
            # Vulnerable deserialization point
            document_data = pickle.load(f)
            self._process_serialized_data(document_data)

    def _process_serialized_data(self, data):
        # This is the vulnerable function
        self.metadata.title = data.get('title', 'Untitled')
        self.metadata.author = data.get('author', 'Unknown')
        self.metadata.tags = data.get('tags', [])
        self.metadata.modified = datetime.now()
        
        content = data.get('content', '')
        self.parsed_content = self._parse_content(content)
        
        analytics = data.get('analytics', {})
        self._update_analytics(analytics)

    def _parse_content(self, content):
        if isinstance(content, str):
            return {
                'text': content,
                'format': 'plaintext',
                'checksum': hashlib.md5(content.encode()).hexdigest()
            }
        elif isinstance(content, dict):
            return content
        return {'error': 'Invalid content format'}

    def _update_analytics(self, analytics_data):
        self.analytics['processing_time'] = analytics_data.get('processing_time', 0)
        self.analytics['word_count'] = analytics_data.get('word_count', 0)
        self.analytics['image_count'] = analytics_data.get('image_count', 0)

    def generate_report(self):
        return {
            'metadata': {
                'title': self.metadata.title,
                'author': self.metadata.author,
                'tags': self.metadata.tags,
                'created': self.metadata.created.isoformat(),
                'modified': self.metadata.modified.isoformat()
            },
            'analytics': self.analytics,
            'content_info': {
                'format': self.parsed_content.get('format', 'unknown'),
                'size': len(str(self.parsed_content))
            }
        }

    def cache_document(self, key):
        self.cache[key] = {
            'metadata': self.metadata,
            'parsed_content': self.parsed_content,
            'timestamp': datetime.now()
        }

    def get_cached_document(self, key):
        return self.cache.get(key)

class DocumentManagementSystem:
    def __init__(self):
        self.processor = DocumentProcessor()
        self.document_history = []

    def process_document(self, file_path):
        try:
            self.processor.load_serialized_document(file_path)
            report = self.processor.generate_report()
            self.document_history.append({
                'file': file_path,
                'timestamp': datetime.now(),
                'action': 'process'
            })
            return report
        except Exception as e:
            return {'error': str(e)}

    def get_history(self):
        return self.document_history

def main():
    dms = DocumentManagementSystem()
    print("Document Management System ready")
    
    while True:
        file_path = input("Enter document path (or 'quit' to exit): ")
        if file_path.lower() == 'quit':
            break
        
        result = dms.process_document(file_path)
        print("Processing result:", result)

if __name__ == "__main__":
    main()