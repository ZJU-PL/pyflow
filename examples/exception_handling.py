#!/usr/bin/env python3
"""
Exception Handling Example for PyFlow

This example demonstrates exception handling, error flows, and control flow
that can be analyzed by PyFlow's static analysis tools.

Usage:
    pyflow optimize exception_handling.py --analysis cpa
    pyflow callgraph exception_handling.py
"""

def safe_divide(a, b):
    """Safely divide two numbers with exception handling."""
    try:
        result = a / b
        return result
    except ZeroDivisionError:
        print("Error: Division by zero")
        return None
    except TypeError as e:
        print(f"Error: Invalid types - {e}")
        return None
    except Exception as e:
        print(f"Unexpected error: {e}")
        return None

def process_list_with_errors(data):
    """Process a list with various error conditions."""
    results = []
    
    for i, item in enumerate(data):
        try:
            # Simulate different error conditions
            if item is None:
                raise ValueError("None value encountered")
            elif isinstance(item, str) and not item.isdigit():
                raise TypeError("Non-numeric string")
            else:
                # Convert to int and square it
                value = int(item)
                if value < 0:
                    raise ValueError("Negative value not allowed")
                results.append(value * value)
        except ValueError as e:
            print(f"Value error at index {i}: {e}")
            results.append(0)  # Default value
        except TypeError as e:
            print(f"Type error at index {i}: {e}")
            results.append(-1)  # Error marker
        except Exception as e:
            print(f"Unexpected error at index {i}: {e}")
            results.append(-2)  # Unknown error marker
        finally:
            print(f"Processed item {i}: {item}")
    
    return results

def nested_exception_handling():
    """Demonstrate nested try-except blocks."""
    try:
        outer_value = 10
        try:
            inner_value = outer_value / 0  # This will raise ZeroDivisionError
        except ZeroDivisionError:
            print("Inner: Division by zero caught")
            inner_value = 0
        except Exception as e:
            print(f"Inner: Unexpected error - {e}")
            inner_value = -1
        
        # This might also raise an exception
        result = inner_value * 2
        return result
        
    except Exception as e:
        print(f"Outer: Exception caught - {e}")
        return -1

def file_operations_with_cleanup(filename):
    """Demonstrate file operations with proper cleanup."""
    file_handle = None
    try:
        file_handle = open(filename, 'r')
        content = file_handle.read()
        return content.upper()
    except FileNotFoundError:
        print(f"File {filename} not found")
        return ""
    except PermissionError:
        print(f"Permission denied for {filename}")
        return ""
    except IOError as e:
        print(f"IO error: {e}")
        return ""
    finally:
        if file_handle:
            try:
                file_handle.close()
                print("File closed successfully")
            except Exception as e:
                print(f"Error closing file: {e}")

def custom_exception_example():
    """Demonstrate custom exceptions."""
    class CustomError(Exception):
        def __init__(self, message, error_code):
            super().__init__(message)
            self.error_code = error_code
    
    class ValidationError(CustomError):
        pass
    
    def validate_age(age):
        if not isinstance(age, int):
            raise ValidationError("Age must be an integer", 1001)
        if age < 0:
            raise ValidationError("Age cannot be negative", 1002)
        if age > 150:
            raise ValidationError("Age seems unrealistic", 1003)
        return True
    
    def process_ages(ages):
        results = []
        for age in ages:
            try:
                validate_age(age)
                results.append(f"Valid age: {age}")
            except ValidationError as e:
                results.append(f"Invalid age {age}: {e} (code: {e.error_code})")
            except CustomError as e:
                results.append(f"Custom error for age {age}: {e}")
            except Exception as e:
                results.append(f"Unexpected error for age {age}: {e}")
        
        return results

def exception_propagation():
    """Demonstrate exception propagation through call stack."""
    def level3():
        raise ValueError("Error from level 3")
    
    def level2():
        try:
            level3()
        except ValueError as e:
            print(f"Level 2 caught: {e}")
            raise  # Re-raise the exception
    
    def level1():
        try:
            level2()
        except ValueError as e:
            print(f"Level 1 caught: {e}")
            return "Error handled at level 1"
        return "Success"
    
    return level1()

if __name__ == "__main__":
    # Example usage
    print("=== Safe Division Tests ===")
    print(f"10 / 2 = {safe_divide(10, 2)}")
    print(f"10 / 0 = {safe_divide(10, 0)}")
    print(f"10 / 'a' = {safe_divide(10, 'a')}")
    
    print("\n=== List Processing with Errors ===")
    test_data = [1, 2, None, "abc", "123", -5, 0, 3.14]
    results = process_list_with_errors(test_data)
    print(f"Results: {results}")
    
    print("\n=== Nested Exception Handling ===")
    result = nested_exception_handling()
    print(f"Result: {result}")
    
    print("\n=== File Operations ===")
    content = file_operations_with_cleanup("nonexistent.txt")
    print(f"File content: '{content}'")
    
    print("\n=== Custom Exceptions ===")
    ages = [25, -5, "thirty", 200, 0, 50]
    age_results = custom_exception_example()
    for result in age_results:
        print(result)
    
    print("\n=== Exception Propagation ===")
    prop_result = exception_propagation()
    print(f"Propagation result: {prop_result}")
