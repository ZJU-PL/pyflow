import json
import yaml
from datetime import datetime

class AnalyticsConfig:
    def __init__(self):
        self.tracking_id = None
        self.endpoints = []
        self.sample_rate = 1.0
        self.filters = {}
        self.last_updated = None

class AnalyticsService:
    def __init__(self):
        self.config = AnalyticsConfig()
        self.user_data_cache = {}
        self.analytics_buffer = []

    def load_config_from_file(self, file_path):
        with open(file_path, 'r') as f:
            if file_path.endswith('.json'):
                config_data = json.load(f)
                self._apply_json_config(config_data)
            elif file_path.endswith('.yaml') or file_path.endswith('.yml'):
                config_data = yaml.safe_load(f)
                self._apply_yaml_config(config_data)
            else:
                raise ValueError("Unsupported config format. Only JSON and YAML are supported.")

    def _apply_json_config(self, config_data):
        self._validate_config_data(config_data)
        self.config.tracking_id = config_data.get('tracking_id')
        self.config.endpoints = config_data.get('endpoints', [])
        self.config.sample_rate = min(1.0, max(0.0, float(config_data.get('sample_rate', 1.0))))
        self.config.filters = config_data.get('filters', {})
        self.config.last_updated = datetime.now()

    def _apply_yaml_config(self, config_data):
        self._validate_config_data(config_data)
        self.config.tracking_id = config_data.get('tracking_id')
        self.config.endpoints = config_data.get('endpoints', [])
        self.config.sample_rate = min(1.0, max(0.0, float(config_data.get('sample_rate', 1.0))))
        self.config.filters = config_data.get('filters', {})
        self.config.last_updated = datetime.now()

    def _validate_config_data(self, config_data):
        """Validate the structure and content of configuration data"""
        if not isinstance(config_data, dict):
            raise ValueError("Configuration data must be a dictionary")
        
        if 'tracking_id' not in config_data:
            raise ValueError("Configuration must include a tracking_id")
            
        if 'endpoints' in config_data and not isinstance(config_data['endpoints'], list):
            raise ValueError("Endpoints must be a list")
            
        if 'filters' in config_data and not isinstance(config_data['filters'], dict):
            raise ValueError("Filters must be a dictionary")

    def track_event(self, user_id, event_type, data):
        if not isinstance(user_id, str) or not user_id:
            raise ValueError("Invalid user_id")
            
        if not isinstance(event_type, str) or not event_type:
            raise ValueError("Invalid event_type")
            
        if not isinstance(data, dict):
            raise ValueError("Event data must be a dictionary")

        if user_id in self.user_data_cache:
            user_profile = self.user_data_cache[user_id]
            user_profile['last_seen'] = datetime.now()
            user_profile['event_count'] += 1
        else:
            user_profile = self._create_user_profile(user_id)
            self.user_data_cache[user_id] = user_profile

        event = {
            'timestamp': datetime.now().isoformat(),
            'user_id': user_id,
            'event_type': event_type,
            'data': data,
            'config_version': self.config.last_updated
        }
        self.analytics_buffer.append(event)

    def _create_user_profile(self, user_id):
        return {
            'user_id': user_id,
            'first_seen': datetime.now(),
            'last_seen': datetime.now(),
            'event_count': 1
        }

    def flush_buffer(self):
        events = self.analytics_buffer
        self.analytics_buffer = []
        return events

def main():
    service = AnalyticsService()
    print("Analytics service initialized")
    
    try:
        config_path = input("Enter path to config file: ").strip()
        if not config_path:
            raise ValueError("No config file path provided")
            
        if not (config_path.endswith('.json') or config_path.endswith('.yaml') or config_path.endswith('.yml')):
            raise ValueError("Only .json and .yaml/.yml files are supported")
            
        service.load_config_from_file(config_path)
        
        print(f"Loaded configuration with tracking ID: {service.config.tracking_id}")
        service.track_event("user123", "page_view", {"url": "/home"})
        print("Event tracked successfully")
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()