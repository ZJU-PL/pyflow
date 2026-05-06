"""BUG: math.log with zero argument (domain error)."""
import math

x = 0.0
result = math.log(x)  # ValueError: math domain error
