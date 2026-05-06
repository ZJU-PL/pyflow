"""
NULL_PTR True Negative #2: Optional with default fallback

Ground truth: SAFE
Bug type: NULL_PTR
Reason: dict.get() with default value ensures never None

Semantic model: get() with default never returns None.
"""

def main():
    config = {"host": "localhost"}
    # SAFE: get() with default value ensures non-None result
    timeout = config.get("timeout", 30)
    # timeout is guaranteed to be non-None (either value or default)
    value = timeout * 2
    print(value)

if __name__ == "__main__":
    main()
