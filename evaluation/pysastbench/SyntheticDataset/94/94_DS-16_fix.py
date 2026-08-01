from django.http import JsonResponse, HttpResponse
from django.views import View
from django.conf import settings
from django.core.cache import cache
from django.utils.html import escape
import json
import hashlib
import datetime
from string import Template
import ast

class SafeTemplateRenderer:
    def __init__(self):
        self.template_cache = {}
    
    def _compile_template(self, template_str, context):
        try:
            # Use string.Template for safe substitution
            template = Template(template_str)
            
            # Escape all context values to prevent XSS
            safe_context = {
                key: escape(str(value)) if value is not None else ''
                for key, value in context.items()
            }
            
            return template.safe_substitute(safe_context)
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
    renderer = SafeTemplateRenderer()
    
    def post(self, request):
        try:
            data = json.loads(request.body)
            template = data.get('template')
            context = data.get('context', {})
            
            if not template:
                return JsonResponse({'error': 'Template required'}, status=400)
            
            if not isinstance(context, dict):
                return JsonResponse({'error': 'Context must be a dictionary'}, status=400)
            
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
            # Use ast.literal_eval instead of eval for safe evaluation
            new_config = ast.literal_eval(config_str)
            if isinstance(new_config, dict):
                # Validate config values before updating
                if 'debug' in new_config and isinstance(new_config['debug'], bool):
                    self.config['debug'] = new_config['debug']
                if 'timezone' in new_config and isinstance(new_config['timezone'], str):
                    self.config['timezone'] = new_config['timezone']
                if 'allowed_hosts' in new_config and isinstance(new_config['allowed_hosts'], list):
                    self.config['allowed_hosts'] = [
                        host for host in new_config['allowed_hosts'] 
                        if isinstance(host, str)
                    ]
                return True
            return False
        except (ValueError, SyntaxError) as e:
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
            
            if not config_str or not isinstance(config_str, str):
                return JsonResponse({'error': 'Valid config string required'}, status=400)
            
            if ConfigManager().update_from_string(config_str):
                return JsonResponse({'status': 'Config updated'})
            return JsonResponse({'error': 'Invalid config format'}, status=400)
        
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
        except Exception as e:
            return JsonResponse({'error': 'Internal server error'}, status=500)

class AuditLogger:
    @staticmethod
    def log(event, details):
        timestamp = datetime.datetime.now().isoformat()
        
        # Safe string formatting
        try:
            if not isinstance(event, str):
                event = str(event)
            if not isinstance(details, str):
                details = str(details)
            
            log_entry = f"[{timestamp}] {event}: {details}\n"
            with open('audit.log', 'a') as f:
                f.write(log_entry)
        except Exception as e:
            print(f"Failed to write audit log: {str(e)}")

class UserActivityAPI(View):
    def post(self, request):
        try:
            data = json.loads(request.body)
            event = data.get('event')
            details = data.get('details')
            
            if not event or not details:
                return JsonResponse({'error': 'Event and details required'}, status=400)
            
            if not isinstance(event, str) or not isinstance(details, str):
                return JsonResponse({'error': 'Event and details must be strings'}, status=400)
            
            AuditLogger.log(event, details)
            return JsonResponse({'status': 'Logged'})
        
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
        except Exception as e:
            return JsonResponse({'error': 'Internal server error'}, status=500)