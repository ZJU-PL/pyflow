"""
TYPE_CONFUSION True Positive #3: Dynamic attribute access on wrong class

Expected: BUG (TYPE_CONFUSION)
Reason: Code assumes object has 'name' attribute, but receives object without it
"""

class User:
    def __init__(self, name, email):
        self.name = name
        self.email = email

class Product:
    def __init__(self, sku, price):
        self.sku = sku
        self.price = price

def greet_entity(entity):
    """Assumes entity has 'name' attribute"""
    # Bug: no check for attribute existence
    return f"Hello, {entity.name}!"  # AttributeError if entity is Product

def main():
    # Pass Product where User was expected
    product = Product("ABC123", 29.99)
    greeting = greet_entity(product)
    print(greeting)

if __name__ == "__main__":
    main()
