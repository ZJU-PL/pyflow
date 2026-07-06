"""BUG: math.sqrt with negative argument (domain error)."""
import math

x = -1.0
result = math.sqrt(x)  # ValueError: math domain error
