# SAFE: dict iteration without mutation
d = {'a': 1, 'b': 2, 'c': 3}
result = []
for key in d:
    result.append(d[key])  # Read-only access is safe
