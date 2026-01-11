
def func_c():
    return 1

def func_b():
    return func_c() + 1

def func_a():
    if True:
        func_b()
    else:
        func_c()

def main():
    func_a()
