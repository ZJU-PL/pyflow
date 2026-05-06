"""
NULL_PTR True Positive #2: Attribute access on None return value

Ground truth: BUG
Bug type: NULL_PTR
Reason: dict.get() returns None when key missing, accessing .value raises AttributeError

Semantic model: dict.get() can return None, attribute access without check dereferences None.
"""

def main():
    config = {"host": "localhost"}
    # BUG: 'timeout' key doesn't exist, get() returns None
    timeout_obj = config.get("timeout")
    # Accessing attribute on None raises AttributeError
    value = timeout_obj.value
    print(value)

if __name__ == "__main__":
    main()
