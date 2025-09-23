def simple_if(x):
    """Simple if statement - basic control flow."""
    if x > 0:
        return x
    else:
        return -x


def nested_if(x, y):
    """Nested if statements - complex control dependencies."""
    if x > 0:
        if y > 0:
            result = x + y
        else:
            result = x - y
    else:
        if y > 0:
            result = -x + y
        else:
            result = -x - y
    return result


def complex_nested_control(x, y, z):
    """Complex nested control flow with multiple levels."""
    if x > 0:
        if y > 0:
            if z > 0:
                result = x + y + z
            else:
                result = x + y - z
        else:
            if z > 0:
                result = x - y + z
            else:
                result = x - y - z
    else:
        if y > 0:
            if z > 0:
                result = -x + y + z
            else:
                result = -x + y - z
        else:
            if z > 0:
                result = -x - y + z
            else:
                result = -x - y - z
    
    # Additional control flow after the nested structure
    if result > 100:
        result = 100
    elif result < -100:
        result = -100
    
    return result


def early_returns(x):
    """Function with multiple early returns."""
    if x < 0:
        return "negative"
    
    if x == 0:
        return "zero"
    
    if x > 100:
        return "large"
    
    if x % 2 == 0:
        return "even"
    else:
        return "odd"


def switch_like_pattern(choice):
    """Switch-like pattern using if-elif-else."""
    if choice == 1:
        return "option 1"
    elif choice == 2:
        return "option 2"
    elif choice == 3:
        return "option 3"
    else:
        return "default"


# Test the functions to ensure they're loaded
if __name__ == "__main__":
    print("Testing functions...")
    print(f"simple_if(5) = {simple_if(5)}")
    print(f"nested_if(3, 4) = {nested_if(3, 4)}")
    print(f"complex_nested_control(1, 2, 3) = {complex_nested_control(1, 2, 3)}")
    print(f"early_returns(42) = {early_returns(42)}")
    print(f"switch_like_pattern(2) = {switch_like_pattern(2)}")
    print("All functions loaded successfully!")
