import json
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
        
        # Check file extension to determine format
        if not file_path.endswith('.json'):
            raise ValueError("Only JSON documents are supported")
        
        with open(file_path, 'r', encoding='utf-8') as f:
            try:
                document_data = json.load(f)
                self._process_document_data(document_data)
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON document: {str(e)}")

    def _process_document_data(self, data):
        # Validate the document structure
        if not isinstance(data, dict):
            raise ValueError("Document data must be a dictionary")
        
        # Process metadata with validation
        self.metadata.title = str(data.get('title', 'Untitled'))
        self.metadata.author = str(data.get('author', 'Unknown'))
        
        tags = data.get('tags', [])
        if isinstance(tags, list):
            self.metadata.tags = [str(tag) for tag in tags]
        else:
            self.metadata.tags = []
        
        self.metadata.modified = datetime.now()
        
        # Process content with validation
        content = data.get('content', '')
        self.parsed_content = self._parse_content(content)
        
        # Process analytics with validation
        analytics = data.get('analytics', {})
        if isinstance(analytics, dict):
            self._update_analytics(analytics)

    def _parse_content(self, content):
        if isinstance(content, str):
            return {
                'text': content,
                'format': 'plaintext',
                'checksum': hashlib.md5(content.encode()).hexdigest()
            }
        elif isinstance(content, dict):
            # Validate dictionary content
            if 'text' in content and isinstance(content['text'], str):
                return {
                    'text': content['text'],
                    'format': content.get('format', 'plaintext'),
                    'checksum': hashlib.md5(content['text'].encode()).hexdigest()
                }
        return {'error': 'Invalid content format'}

    def _update_analytics(self, analytics_data):
        try:
            self.analytics['processing_time'] = float(analytics_data.get('processing_time', 0))
            self.analytics['word_count'] = int(analytics_data.get('word_count', 0))
            self.analytics['image_count'] = int(analytics_data.get('image_count', 0))
        except (ValueError, TypeError):
            # Keep default values if conversion fails
            pass

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
        file_path = input("Enter document path (or 'quit' to exit): ").strip()
        if file_path.lower() == 'quit':
            break
        
        if not file_path:
            print("Error: No file path provided")
            continue
            
        result = dms.process_document(file_path)
        print("Processing result:", result)

if __name__ == "__main__":
    main()