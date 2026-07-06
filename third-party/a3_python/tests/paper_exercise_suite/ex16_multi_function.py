"""
Paper #20 exercise: Multiple standalone functions.

Four independent functions — enough components for
assume-guarantee compositional reasoning.

Target papers: #20
Expected: SAFE
"""


def add(a, b):
    return a + b


def multiply(a, b):
    return a * b


def compute_area(length, width):
    return multiply(length, width)


def compute_perimeter(length, width):
    return add(add(length, width), add(length, width))
