#!/usr/bin/env python3
"""
Example code demonstrating class pollution vulnerabilities
This file contains patterns that the class pollution checker should detect
"""

import sys
import json


class ExampleClass:
    def __init__(self):
        self.data = {}
        self.safe_attributes = {'id', 'name', 'value', 'status'}  # Safe whitelist
    
    def unsafe_merge(self, user_input):
        """Unsafe merge that could lead to class pollution"""
        # B701: setattr with potentially user-controlled attribute name
        # Note: This would crash at runtime if user_input.get('attr_name') returns '__class__'
        attr_name = user_input.get('attr_name', 'default_attr')
        setattr(self, attr_name, user_input.get('value'))
        
        # B701: setattr with dangerous attribute name
        dangerous_attr = '__class__'
        # This would crash at runtime - just showing the pattern for static analysis
        # setattr(self, dangerous_attr, 'malicious_value')
        
        # B702: unsafe object merge
        self.data.update(user_input)
        
        # B703: direct __dict__ manipulation
        self.__dict__.update(user_input)
    
    def unsafe_string_construction(self, user_input):
        """Examples of unsafe string construction for attribute names"""
        # B701: String concatenation with user input
        prefix = 'user_'
        attr_name = prefix + user_input.get('suffix', 'default')
        setattr(self, attr_name, 'value')
        
        # B701: String formatting with user input
        attr_name_fmt = 'attr_{}'.format(user_input.get('id'))
        setattr(self, attr_name_fmt, 'value')
        
        # B701: f-string with user input
        user_id = user_input.get('id', 'unknown')
        setattr(self, f'user_{user_id}', 'value')


def dangerous_setattr_example(user_input):
    """Example of dangerous setattr usage"""
    obj = ExampleClass()
    
    # B701: setattr with user-controlled attribute name
    attr_name = user_input.get('attribute', 'default_attr')  # User controls this
    setattr(obj, attr_name, 'some_value')
    
    # B701: setattr with dangerous attribute from user input
    dangerous_attr = user_input.get('dangerous_attr', '__dict__')
    # This would crash at runtime - just showing the pattern for static analysis
    # setattr(obj, dangerous_attr, 'malicious_value')
    
    return obj


def unsafe_dict_manipulation(user_input):
    """Example of unsafe dictionary manipulation"""
    obj = ExampleClass()
    
    # B704: direct __dict__ assignment
    # This would be dangerous at runtime - just showing the pattern for static analysis
    # obj.__dict__ = user_input
    
    # B704: dynamic __dict__ key assignment with user input
    key = user_input.get('key', 'default_key')
    obj.__dict__[key] = user_input.get('value')
    
    # B704: dynamic __dict__ key assignment with dangerous key
    dangerous_key = '__class__'
    # This would crash at runtime - just showing the pattern for static analysis
    # obj.__dict__[dangerous_key] = 'malicious_value'
    
    return obj


def namespace_exposure_example(user_input):
    """Example of namespace exposure"""
    # B706: usage of vars() with user input
    current_vars = vars()
    current_vars.update(user_input)
    
    # B706: usage of globals() 
    global_vars = globals()
    global_vars.update(user_input)
    
    # B706: usage of locals()
    local_vars = locals()
    local_vars.update(user_input)
    
    return current_vars


def getattr_misuse_example(user_input):
    """Example of potentially unsafe getattr usage"""
    obj = ExampleClass()
    
    # B705: getattr with user-controlled attribute name
    attr_name = user_input.get('attr')
    value = getattr(obj, attr_name, 'default')
    
    # B705: getattr with dangerous attribute name
    dangerous_attr = '__class__'
    dangerous_value = getattr(obj, dangerous_attr, None)
    
    return value


def request_based_example(request_data):
    """Example using web request data (common attack vector)"""
    obj = ExampleClass()
    
    # B701: Using request parameters for attribute names
    param_name = request_data.get('param')
    setattr(obj, param_name, request_data.get('value'))
    
    # B702: Merging request data directly
    obj.data.update(request_data)
    
    # B703: Direct __dict__ manipulation with request data
    obj.__dict__.update(request_data)
    
    return obj


def json_parsing_example(json_data):
    """Example using parsed JSON data"""
    obj = ExampleClass()
    
    # B701: Using JSON keys as attribute names
    for key, value in json_data.items():
        # Skip dangerous keys to prevent runtime crashes
        if key.startswith('__') and key.endswith('__'):
            continue
        setattr(obj, key, value)
    
    # B704: Direct assignment from JSON
    # This would be dangerous at runtime - just showing the pattern for static analysis
    # obj.__dict__ = json_data
    
    return obj


# Safe examples (should not trigger warnings)
def safe_attribute_access():
    """Safe attribute access patterns"""
    obj = ExampleClass()
    
    # These are safe because attribute names are hardcoded
    setattr(obj, 'safe_attr', 'safe_value')
    setattr(obj, 'id', '123')
    setattr(obj, 'name', 'test')
    obj.__dict__['safe_key'] = 'safe_value'
    
    # Safe getattr usage
    value = getattr(obj, 'data', {})
    safe_value = getattr(obj, 'id', None)
    
    # Safe validation pattern
    user_input = {'attr_name': 'malicious_attr', 'value': 'bad_value'}
    if user_input['attr_name'] in obj.safe_attributes:
        setattr(obj, user_input['attr_name'], user_input['value'])
    
    return obj


def safe_validation_example(user_input):
    """Example with proper validation"""
    obj = ExampleClass()
    
    # Safe: Validation before using attribute name
    attr_name = user_input.get('attr_name')
    if attr_name in obj.safe_attributes:
        setattr(obj, attr_name, user_input.get('value'))
    
    # Safe: Whitelist validation
    allowed_attrs = {'id', 'name', 'status', 'value'}
    for key, value in user_input.items():
        if key in allowed_attrs:
            setattr(obj, key, value)
    
    return obj


def safe_dict_operations():
    """Safe dictionary operations"""
    obj = ExampleClass()
    
    # Safe: Hardcoded dictionary operations
    safe_data = {'id': '123', 'name': 'test', 'status': 'active'}
    obj.data.update(safe_data)
    
    # Safe: Direct assignment with validated data
    obj.__dict__.update({'safe_key': 'safe_value'})
    
    return obj


if __name__ == "__main__":
    # Example usage - using safer values to prevent runtime crashes
    # while still demonstrating the vulnerability patterns for static analysis
    malicious_input = {
        'attr_name': 'user_controlled_attr',  # Would be '__class__' in real attack
        'value': 'malicious_value',
        'attribute': 'dangerous_attribute',   # Would be '__dict__' in real attack
        'key': 'user_key',                    # Would be '__class__' in real attack
        'attr': 'user_attr',                  # Would be '__init__' in real attack
        'dangerous_attr': 'bad_attr',         # Would be '__globals__' in real attack
        'suffix': 'evil_suffix',              # Would be '__bases__' in real attack
        'id': 'malicious_id'
    }
    
    request_data = {
        'param': 'dangerous_param',     # Would be '__class__' in real attack
        'value': 'malicious_value',
        'user_input': 'dangerous_data'
    }
    
    json_data = {
        'dangerous_key': 'malicious_value',  # Would be '__class__' in real attack
        'bad_dict': {'hacked': True},        # Would be '__dict__' in real attack
        'normal_key': 'normal_value'
    }
    
    print("Running class pollution examples...")
    
    # Unsafe examples
    obj1 = ExampleClass()
    obj1.unsafe_merge(malicious_input)
    obj1.unsafe_string_construction(malicious_input)
    
    dangerous_setattr_example(malicious_input)
    unsafe_dict_manipulation(malicious_input)
    namespace_exposure_example(malicious_input)
    getattr_misuse_example(malicious_input)
    request_based_example(request_data)
    json_parsing_example(json_data)
    
    # Safe examples
    safe_attribute_access()
    safe_validation_example(malicious_input)
    safe_dict_operations()
    
    print("Examples completed.")
