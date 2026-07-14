from helpers import helper, sanitize, source
from sinks import sink


def main():
    a = source()
    b = helper(a)
    c = sanitize(b)
    sink(b)
    sink(c)
    return c
