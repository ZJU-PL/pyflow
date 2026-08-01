from django.http import JsonResponse, HttpResponse
from django.views import View
from django.conf import settings
from django.core.cache import cache
import json
import hashlib
import datetime

class DynamicTemplateRenderer:
    def __init__(self):
        self.template_cache = {}
    
    def _compile_template(self, template_str, context):
        try:
            # Vulnerable code injection point
            compiled = eval(f'f"""{template_str}"""', {}, context)
            return compiled
        except Exception as e:
            raise ValueError(f"Template compilation error: {str(e)}")
    
    def render(self, template_str, context=None):
        if context is None:
            context = {}
        
        cache_key = hashlib.md5(template_str.encode()).hexdigest()
        
        if cache_key not in self.template_cache:
            self.template_cache[cache_key] = self._compile_template(template_str, context)
        
        return self.template_cache[cache_key]

class TemplateAPI(View):
    renderer = DynamicTemplateRenderer()
    
    def post(self, request):
        try:
            data = json.loads(request.body)
            template = data.get('template')
            context = data.get('context', {})
            
            if not template:
                return JsonResponse({'error': 'Template required'}, status=400)
            
            rendered = self.renderer.render(template, context)
            return HttpResponse(rendered)
        
        except ValueError as e:
            return JsonResponse({'error': str(e)}, status=400)
        except Exception as e:
            return JsonResponse({'error': 'Internal server error'}, status=500)

class ConfigManager:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._load_default_config()
        return cls._instance
    
    def _load_default_config(self):
        self.config = {
            'debug': False,
            'timezone': 'UTC',
            'allowed_hosts': ['localhost']
        }
    
    def update_from_string(self, config_str):
        try:
            # Another vulnerable code injection point
            new_config = eval(config_str, {'__builtins__': None}, {})
            if isinstance(new_config, dict):
                self.config.update(new_config)
                return True
            return False
        except Exception as e:
            print(f"Config update failed: {str(e)}")
            return False

class ConfigAPI(View):
    def get(self, request):
        config = ConfigManager().config
        return JsonResponse(config)
    
    def post(self, request):
        try:
            data = json.loads(request.body)
            config_str = data.get('config')
            
            if not config_str:
                return JsonResponse({'error': 'Config string required'}, status=400)
            
            if ConfigManager().update_from_string(config_str):
                return JsonResponse({'status': 'Config updated'})
            return JsonResponse({'error': 'Invalid config format'}, status=400)
        
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

class AuditLogger:
    @staticmethod
    def log(event, details):
        timestamp = datetime.datetime.now().isoformat()
        log_entry = f"[{timestamp}] {event}: {details}"
        
        # Vulnerable dynamic logging format evaluation
        try:
            formatted = eval(f'f"""{log_entry}"""')
            with open('audit.log', 'a') as f:
                f.write(formatted + "\n")
        except Exception:
            with open('audit.log', 'a') as f:
                f.write(log_entry + "\n")

class UserActivityAPI(View):
    def post(self, request):
        try:
            data = json.loads(request.body)
            event = data.get('event')
            details = data.get('details')
            
            if not event or not details:
                return JsonResponse({'error': 'Event and details required'}, status=400)
            
            AuditLogger.log(event, details)
            return JsonResponse({'status': 'Logged'})
        
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)