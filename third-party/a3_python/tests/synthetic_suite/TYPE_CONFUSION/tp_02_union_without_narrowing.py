"""
TYPE_CONFUSION True Positive #2: Union type used without narrowing

Expected: BUG (TYPE_CONFUSION)
Reason: Function receives str | int but calls method .append() assuming list type
"""

def append_value(container, value):
    """Expects container to be a list, but type signature allows str | int"""
    # Bug: no isinstance check before calling list-specific method
    container.append(value)  # AttributeError if container is str or int
    return container

def main():
    # Pass a string when function expects list-like behavior
    result = append_value("hello", "x")
    print(result)

if __name__ == "__main__":
    main()
