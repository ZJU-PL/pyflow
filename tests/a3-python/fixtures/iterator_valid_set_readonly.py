# SAFE: set iteration without mutation
s = {1, 2, 3, 4, 5}
result = []
for item in s:
    result.append(item * 2)  # Read-only computation is safe
