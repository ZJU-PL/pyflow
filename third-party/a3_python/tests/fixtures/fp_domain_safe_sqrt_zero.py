"""NON-BUG: math.sqrt with zero argument (valid edge case)."""
import math

x = 0.0
result = math.sqrt(x)  # OK: result = 0.0
