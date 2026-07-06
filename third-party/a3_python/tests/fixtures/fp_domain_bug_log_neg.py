"""BUG: math.log with negative argument (domain error)."""
import math

x = -5.0
result = math.log(x)  # ValueError: math domain error
