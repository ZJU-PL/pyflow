"""BUG: math.asin with argument outside [-1, 1] (domain error)."""
import math

x = 2.0
result = math.asin(x)  # ValueError: math domain error
