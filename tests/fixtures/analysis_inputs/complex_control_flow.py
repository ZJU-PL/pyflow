#!/usr/bin/env python3
"""
Complex Control Flow Example for PyFlow

This example demonstrates complex control flow patterns including:
- Nested conditionals
- Multiple loops (for, while)
- Exception handling with try/except/finally
- Early returns and multiple exit points
- Complex boolean expressions
- Function calls within control structures

Usage:
    pyflow ir tests/fixtures/analysis_inputs/complex_control_flow.py --dump-cfg complex_algorithm
    pyflow callgraph tests/fixtures/analysis_inputs/complex_control_flow.py
"""

import random
from typing import List, Optional, Tuple, Union


def complex_algorithm(data: List[int], threshold: int = 10, max_iterations: int = 100) -> Optional[dict]:
    """
    A complex algorithm with multiple control flow patterns.
    
    This function demonstrates:
    - Early returns
    - Nested conditionals
    - Exception handling
    - Multiple loops
    - Complex boolean logic
    """
    if not data or len(data) == 0:
        return None
    
    if threshold <= 0:
        raise ValueError("Threshold must be positive")
    
    result = {
        'processed': 0,
        'skipped': 0,
        'errors': 0,
        'max_value': None,
        'min_value': None,
        'average': 0.0
    }
    
    total = 0
    iteration_count = 0
    
    # Outer while loop with complex condition
    while iteration_count < max_iterations and result['processed'] < len(data):
        try:
            # Inner for loop with conditional processing
            for i, value in enumerate(data):
                if value is None:
                    result['skipped'] += 1
                    continue
                
                # Nested if-elif-else with multiple conditions
                if value > threshold:
                    if value > 1000:
                        # Complex nested condition
                        if value % 2 == 0 and value > 2000:
                            result['processed'] += 1
                            total += value
                        elif value % 3 == 0:
                            result['processed'] += 1
                            total += value * 0.5
                        else:
                            result['skipped'] += 1
                    else:
                        result['processed'] += 1
                        total += value
                        
                        # Update min/max within nested conditionals
                        if result['max_value'] is None or value > result['max_value']:
                            result['max_value'] = value
                        if result['min_value'] is None or value < result['min_value']:
                            result['min_value'] = value
                            
                elif value < -threshold:
                    # Handle negative values with complex logic
                    if abs(value) > threshold * 2:
                        result['errors'] += 1
                        if result['errors'] > 5:
                            # Early return on too many errors
                            return {'error': 'Too many negative values'}
                    else:
                        result['processed'] += 1
                        total += abs(value)
                        
                else:
                    # Values within threshold range
                    result['processed'] += 1
                    total += value
                
                # Break out of inner loop under certain conditions
                if result['processed'] > 50 and iteration_count > 10:
                    break
                    
        except (TypeError, ValueError) as e:
            result['errors'] += 1
            if result['errors'] > 3:
                # Early return on too many exceptions
                return {'error': f'Too many exceptions: {str(e)}'}
            continue
        except Exception as e:
            # Catch-all exception handler
            result['errors'] += 1
            return {'error': f'Unexpected error: {str(e)}'}
        finally:
            iteration_count += 1
    
    # Calculate final statistics with multiple conditions
    if result['processed'] > 0:
        result['average'] = total / result['processed']
        
        # Final validation and adjustment
        if result['average'] > threshold * 10:
            result['average'] = threshold * 10
        elif result['average'] < -threshold * 10:
            result['average'] = -threshold * 10
            
        # Additional processing based on results
        if result['max_value'] and result['min_value']:
            range_value = result['max_value'] - result['min_value']
            if range_value > threshold * 100:
                result['range_category'] = 'large'
            elif range_value > threshold * 10:
                result['range_category'] = 'medium'
            else:
                result['range_category'] = 'small'
    
    return result


def nested_conditionals(x: int, y: int, z: int) -> str:
    """
    Function with deeply nested conditionals to test CFG complexity.
    """
    if x > 0:
        if y > 0:
            if z > 0:
                if x + y + z > 100:
                    if x * y * z > 1000:
                        return "all_positive_large"
                    else:
                        return "all_positive_medium"
                else:
                    return "all_positive_small"
            else:
                if z > -10:
                    return "z_slightly_negative"
                else:
                    return "z_very_negative"
        else:
            if z > 0:
                if y > -5:
                    return "y_slightly_negative"
                else:
                    return "y_very_negative"
            else:
                return "y_z_negative"
    else:
        if y > 0:
            if z > 0:
                return "x_negative_y_z_positive"
            else:
                return "x_z_negative_y_positive"
        else:
            if z > 0:
                return "x_y_negative_z_positive"
            else:
                return "all_negative"


def loop_with_exceptions(items: List[Union[int, str, None]]) -> dict:
    """
    Function with loops and exception handling.
    """
    result = {'numbers': [], 'strings': [], 'errors': []}
    
    for item in items:
        try:
            if isinstance(item, int):
                if item > 0:
                    result['numbers'].append(item)
                else:
                    result['numbers'].append(abs(item))
            elif isinstance(item, str):
                if len(item) > 0:
                    result['strings'].append(item.upper())
                else:
                    result['strings'].append("EMPTY")
            elif item is None:
                continue
            else:
                raise TypeError(f"Unexpected type: {type(item)}")
                
        except TypeError as e:
            result['errors'].append(str(e))
        except Exception as e:
            result['errors'].append(f"General error: {str(e)}")
    
    return result


def complex_boolean_logic(a: bool, b: bool, c: bool, d: bool) -> str:
    """
    Function with complex boolean expressions.
    """
    if (a and b) or (c and d):
        if a and b and c and d:
            return "all_true"
        elif a and b:
            return "a_b_true"
        elif c and d:
            return "c_d_true"
        else:
            return "mixed_true"
    elif (a or b) and (c or d):
        if not a and not b:
            return "c_or_d_true"
        elif not c and not d:
            return "a_or_b_true"
        else:
            return "partial_true"
    else:
        return "mostly_false"


def multiple_returns_with_loops(data: List[int]) -> Tuple[int, str]:
    """
    Function with multiple return points and loops.
    """
    if not data:
        return 0, "empty"
    
    total = 0
    count = 0
    
    for i, value in enumerate(data):
        if value is None:
            continue
            
        if value < 0:
            return total, "negative_found"
        
        if value > 1000:
            return total, "too_large"
        
        total += value
        count += 1
        
        if count > 50:
            return total, "too_many_items"
    
    if count == 0:
        return 0, "no_valid_items"
    
    average = total / count
    if average > 500:
        return total, "high_average"
    elif average < 10:
        return total, "low_average"
    else:
        return total, "normal"


if __name__ == "__main__":
    # Test the complex algorithm
    test_data = [1, 5, -3, 100, 2000, None, 50, -10, 1500, 75]
    
    try:
        result = complex_algorithm(test_data, threshold=20, max_iterations=50)
        print(f"Complex algorithm result: {result}")
    except Exception as e:
        print(f"Error in complex algorithm: {e}")
    
    # Test nested conditionals
    print(f"Nested conditionals: {nested_conditionals(10, 20, 30)}")
    
    # Test loop with exceptions
    mixed_data = [1, "hello", None, 42, "world", -5, "test"]
    loop_result = loop_with_exceptions(mixed_data)
    print(f"Loop with exceptions: {loop_result}")
    
    # Test complex boolean logic
    print(f"Boolean logic: {complex_boolean_logic(True, False, True, False)}")
    
    # Test multiple returns
    test_numbers = list(range(1, 21)) + [None, 2000, -5]
    total, status = multiple_returns_with_loops(test_numbers)
    print(f"Multiple returns: total={total}, status={status}")
