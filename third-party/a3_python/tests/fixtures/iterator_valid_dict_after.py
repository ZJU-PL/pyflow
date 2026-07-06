# SAFE: dict mutation after iteration completes
d = {'a': 1, 'b': 2, 'c': 3}
for key in d:
    pass  # Iteration completes
d['new_key'] = 99  # Mutation after iteration is safe
