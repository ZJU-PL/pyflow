"""Higher-order calls and reflected operators for the native MIR pipeline.

Run with CPython to check the result, or inspect it using:

    pyflow ir tests/fixtures/analysis_inputs/mir/callbacks.py --dump-mir --dump-output out/
    pyflow callgraph tests/fixtures/analysis_inputs/mir/callbacks.py --algorithm pycg-mir
"""


def leaf():
    return 5


def apply(callback):
    return callback()


class Callback:
    def __add__(self, other):
        return leaf


class PreferredCallback(Callback):
    def __radd__(self, other):
        # A strict subclass's reflected method has priority over Callback.__add__.
        return leaf


left = Callback()
right = PreferredCallback()
result = apply(left + right)
assert result == 5
