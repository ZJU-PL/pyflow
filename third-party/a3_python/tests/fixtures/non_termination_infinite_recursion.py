# Infinite recursion: no base case
def infinite_recursion(n):
    return infinite_recursion(n + 1)

infinite_recursion(0)
