"""NON-BUG: math.sqrt with guard checking for negative."""
import math

x = -4.0
if x >= 0:
    result = math.sqrt(x)
else:
    result = 0.0  # Safe: never calls sqrt with negative
