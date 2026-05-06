# ITERATOR_INVALID: dict mutation during iteration (BUG)
d = {'a': 1, 'b': 2, 'c': 3}
for key in d:
    if key == 'b':
        d['new_key'] = 99  # Mutate dict during iteration - RuntimeError
