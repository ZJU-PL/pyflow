"""
TYPE_CONFUSION True Negative #3: Protocol-based duck typing with hasattr

Expected: SAFE
Reason: Uses hasattr to check for required attributes before access
"""

def format_entity(entity):
    """Works with any object that has required attributes"""
    # Check for required attributes before access
    if hasattr(entity, 'name') and hasattr(entity, 'id'):
        return f"{entity.name} (ID: {entity.id})"
    elif hasattr(entity, 'title'):
        return f"Title: {entity.title}"
    else:
        return str(entity)

class User:
    def __init__(self, name, user_id):
        self.name = name
        self.id = user_id

class Document:
    def __init__(self, title):
        self.title = title

def main():
    # Both work safely due to hasattr checks
    user = User("Alice", 123)
    doc = Document("Report")
    
    print(format_entity(user))
    print(format_entity(doc))
    print(format_entity(42))

if __name__ == "__main__":
    main()
