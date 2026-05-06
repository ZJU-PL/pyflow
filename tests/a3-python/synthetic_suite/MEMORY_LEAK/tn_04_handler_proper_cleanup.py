"""
GROUND TRUTH: SAFE (NO MEMORY_LEAK)
REASON: Event handlers are properly unregistered after use
SEMANTIC: Cleanup removes references allowing garbage collection
"""

class ManagedEventEmitter:
    def __init__(self):
        self.handlers = []
    
    def on(self, handler):
        self.handlers.append(handler)
    
    def off(self, handler):
        self.handlers.remove(handler)
    
    def clear(self):
        self.handlers.clear()

def safe_handler_cleanup():
    emitter = ManagedEventEmitter()
    handlers = []
    
    for i in range(1000):
        def handler(event):
            return event
        handlers.append(handler)
        emitter.on(handler)
    
    emitter.clear()

if __name__ == "__main__":
    safe_handler_cleanup()
