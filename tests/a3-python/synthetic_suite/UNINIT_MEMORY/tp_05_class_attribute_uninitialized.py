"""
UNINIT_MEMORY True Positive #5: Uninitialized instance attribute access

Bug type: UNINIT_MEMORY
Expected result: BUG
Reason: Instance attribute 'value' is accessed before being initialized.
        __init__ conditionally sets the attribute, and the getter method
        assumes it exists.

Semantic: object attribute access on name not present in __dict__
(AttributeError, which is a form of uninitialized memory for OOP context).
"""

class ConfigHolder:
    def __init__(self, initialize: bool):
        if initialize:
            self.value = 42
        # else: self.value is not set
    
    def get_value(self) -> int:
        # BUG: if initialize=False, self.value doesn't exist
        return self.value  # AttributeError

if __name__ == "__main__":
    # Create instance without initializing value
    config = ConfigHolder(initialize=False)
    # Trigger the bug
    print(config.get_value())
