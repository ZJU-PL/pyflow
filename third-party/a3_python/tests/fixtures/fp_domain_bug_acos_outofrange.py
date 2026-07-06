"""BUG: math.acos with argument outside [-1, 1] (domain error)."""
import math

x = -1.5
result = math.acos(x)  # ValueError: math domain error
