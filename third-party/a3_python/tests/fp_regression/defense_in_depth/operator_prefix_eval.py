"""
Defense-in-depth pattern: Operator prefix for eval (Qlib pattern).

This pattern prefixes all evaluated expressions with a safe namespace,
preventing access to dangerous builtins and modules.

Expected: NO bugs (or LOW confidence) due to defense-in-depth mitigation
"""


class SafeEvaluator:
    """Evaluator with operator prefix defense-in-depth."""
    
    # Safe operators namespace
    SAFE_OPS = {
        'Abs': abs,
        'Max': max,
        'Min': min,
        'Sum': sum,
        'Len': len,
        'Round': round,
    }
    
    # Restricted builtins (no __import__, eval, exec, etc.)
    SAFE_BUILTINS = {
        'True': True,
        'False': False,
        'None': None,
        'abs': abs,
        'max': max,
        'min': min,
        'sum': sum,
        'len': len,
        'round': round,
        'int': int,
        'float': float,
        'str': str,
        'list': list,
        'dict': dict,
        'set': set,
        'tuple': tuple,
    }
    
    def parse_field(self, expression: str) -> str:
        """Parse and prefix field expression with safe operators.
        
        This is the key defense-in-depth mechanism.
        All field references are prefixed with 'Ops.' to ensure
        they come from our safe namespace.
        """
        # Prefix field references with Ops.
        # e.g., "Abs(close)" -> "Ops.Abs(close)"
        import re
        for op in self.SAFE_OPS:
            expression = re.sub(rf'\b{op}\b', f'Ops.{op}', expression)
        return expression
    
    def filter_globals(self, user_globals: dict) -> dict:
        """Filter globals to only allow safe operations."""
        filtered = {
            '__builtins__': self.SAFE_BUILTINS,
            'Ops': type('Ops', (), self.SAFE_OPS)(),
        }
        # Add user-provided data (not functions)
        for k, v in user_globals.items():
            if not callable(v) and not k.startswith('_'):
                filtered[k] = v
        return filtered
    
    def safe_eval(self, expression: str, context: dict) -> object:
        """Safely evaluate expression with defense-in-depth.
        
        This is SAFE because:
        1. parse_field prefixes all operators with Ops.
        2. filter_globals restricts available builtins
        3. Only whitelisted functions can be called
        """
        # Step 1: Parse and prefix operators
        prefixed = self.parse_field(expression)
        
        # Step 2: Filter globals
        safe_globals = self.filter_globals(context)
        
        # Step 3: Evaluate with restricted environment
        return eval(prefixed, safe_globals, {})


def calculate_indicator(formula: str, data: dict) -> object:
    """Calculate financial indicator from user formula.
    
    Uses defense-in-depth to safely evaluate formulas.
    """
    evaluator = SafeEvaluator()
    return evaluator.safe_eval(formula, data)


if __name__ == "__main__":
    # Simulated user input
    formula = input("Enter formula (e.g., 'Abs(price - mean)'): ")
    data = {'price': 100.5, 'mean': 99.0}
    
    try:
        result = calculate_indicator(formula, data)
        print(f"Result: {result}")
    except Exception as e:
        print(f"Error: {e}")
