"""
GROUND TRUTH: BUG (MEMORY_LEAK)
REASON: Event handlers are registered but never unregistered
SEMANTIC: Handler list grows unbounded as handlers are added but not removed
"""

class EventEmitter:
    def __init__(self):
        self.handlers = []
    
    def on(self, handler):
        self.handlers.append(handler)
    
    def emit(self, data):
        for h in self.handlers:
            h(data)

def create_temp_handler():
    large_data = [0] * 10000
    def handler(event):
        return len(large_data)
    return handler

def leak_handlers():
    emitter = EventEmitter()
    for i in range(10000):
        emitter.on(create_temp_handler())

if __name__ == "__main__":
    leak_handlers()
