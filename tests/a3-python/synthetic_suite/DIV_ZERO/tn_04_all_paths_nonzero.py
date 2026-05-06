"""
DIV_ZERO True Negative #4: All paths guarantee non-zero divisor

EXPECTED: SAFE
REASON: Every control flow path ensures divisor is non-zero

The symbolic analyzer must verify that divisor > 0 on all paths.
"""

def all_paths_nonzero(flag):
    if flag:
        divisor = 10
    else:
        divisor = 5
    
    x = 100
    result = x / divisor  # SAFE: divisor is either 10 or 5, never 0
    return result

if __name__ == "__main__":
    print(all_paths_nonzero(True))
    print(all_paths_nonzero(False))
