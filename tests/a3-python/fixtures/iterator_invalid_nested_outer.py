# ITERATOR_INVALID: nested iteration with outer mutation (BUG)
d1 = {'a': 1, 'b': 2}
d2 = {'x': 10, 'y': 20}
for k1 in d1:
    for k2 in d2:
        if k1 == 'a' and k2 == 'x':
            d1['new'] = 99  # Mutate outer dict during outer iteration
