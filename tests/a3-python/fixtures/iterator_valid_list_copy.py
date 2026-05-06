# SAFE: list iteration with copy
lst = [1, 2, 3, 4, 5]
for val in lst[:]:  # Iterate over a copy
    if val == 3:
        lst.append(99)  # Mutate original - safe because iterating over copy
