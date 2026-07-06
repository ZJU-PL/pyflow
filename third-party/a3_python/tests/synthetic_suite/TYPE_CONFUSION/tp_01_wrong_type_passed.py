"""
TYPE_CONFUSION True Positive #1: Wrong type passed to function expecting different type

Expected: BUG (TYPE_CONFUSION)
Reason: Function expects dict but receives int, causing AttributeError on .get() call
"""

def process_config(config):
    """Expects a dict with 'timeout' key"""
    timeout = config.get('timeout', 30)  # TypeError: 'int' object has no attribute 'get'
    return timeout * 2

def main():
    # Bug: passing int instead of dict
    result = process_config(42)
    print(result)

if __name__ == "__main__":
    main()
