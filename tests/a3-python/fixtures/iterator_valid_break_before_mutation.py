# SAFE: break before mutation
d = {'a': 1, 'b': 2, 'c': 3}
for key in d:
    if key == 'a':
        break  # Exit loop before any mutation
d['new_key'] = 99  # Mutation after loop exit is safe
