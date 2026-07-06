"""NON-BUG: math.asin with valid argument in [-1, 1]."""
import math

x = 0.5
result = math.asin(x)  # OK: arcsin(0.5)
