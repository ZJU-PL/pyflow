"""Differential regression cases for the reference runtime coverage gaps."""

import textwrap

import pytest

from tests.ir.mir.test_mir_lowering import run_source


@pytest.mark.parametrize(
    "source",
    [
        "result = (str(5), str(-123456), str(0), str(True), str(None))",
        "result = (str(ValueError()), str(ValueError('bad')), str(ValueError(1, 'bad')))",
        "result = ('%s-%d' % ('value', -17), '%d %% %s' % (True, None))",
        "result = ('-'.join(['a', 'b']), ''.join([]), ':'.join(x for x in ['x', 'y']))",
        "result = (len(str(-120)), str(500)[1], list(str(42)))",
        "class X:\n def __str__(self): return 'custom'\nresult = str(X())",
        "class X:\n def __str__(self): return 5\ntry: str(X())\nexcept TypeError: result = True",
        "try: '-'.join(['a', 1])\nexcept TypeError: result = True",
        "try: '%d' % 'x'\nexcept TypeError: result = True",
        "try: '%s' % ()\nexcept TypeError: result = True",
        "try: '%s' % (1, 2)\nexcept TypeError: result = True",
        "try: '%' % ()\nexcept ValueError: result = True",
        "result = (repr('a\\x00b\\n'), repr(\"a'b\"), repr('a\"b'), repr((1,)))",
    ],
)
def test_text_runtime_matches_python(source):
    source = textwrap.dedent(source)
    namespace = {}
    exec(source, namespace)
    actual, _, _ = run_source(source)
    assert actual == namespace["result"]


@pytest.mark.parametrize(
    "source",
    [
        "result = (any([]), all([]), any([0, 2]), all([1, 0]), all([1, 2]))",
        "def g():\n yield 1\n raise ValueError()\nresult = any(g())",
        "def g():\n yield 0\n raise ValueError()\nresult = all(g())",
        "result = (sorted([3, 1, 2, 1]), sorted([]), sorted('cba', reverse=True))",
        "result = sorted([('a', 1), ('b', 2), ('c', 1)], key=lambda x: x[1], reverse=True)",
        "events=[]\ndef key(x):\n events.append(x)\n return -x\nvalues=sorted([1,3,2],key=key)\nresult=(values,events)",
        "result = (list(enumerate(['a', 'b'])), list(enumerate('ab', start=-2)))",
        "result = list(enumerate(iterable=['a', 'b'], start=3))",
        "result = (sorted([3,1,2], reverse=[]), sorted([3,1,2], reverse=[0]))",
        "try: enumerate([1], iterable=[2])\nexcept TypeError: result=True",
        "events=[]\nclass Start:\n def __index__(self):\n  events.append('start')\n  return 2\nclass Items:\n def __iter__(self):\n  events.append('iter')\n  return iter([9])\ne=enumerate(Items(),Start())\nresult=(list(e),events)",
        "events=[]\ndef g():\n events.append(1)\n yield 9\ne=enumerate(g())\nbefore=len(events)\nresult=(before,next(e),events)",
        "result = (list(zip([1,2], [3])), list(zip()), list(zip([1,2])))",
        "result = list(zip([1,2], [3,4], strict=True))",
        "try: list(zip([1], [2,3], strict=True))\nexcept ValueError: result = True",
        "try: list(zip([1,2], [3], strict=True))\nexcept ValueError: result = True",
        "events=[]\ndef g():\n events.append(1)\n yield 9\nz=zip(g(),[2])\nbefore=len(events)\nresult=(before,next(z),events)",
        "try: any(1)\nexcept TypeError: result = True",
        "try: sorted([1], bad=1)\nexcept TypeError: result = True",
    ],
)
def test_iteration_runtime_matches_python(source):
    namespace = {}
    exec(source, namespace)
    actual, _, _ = run_source(source)
    assert actual == namespace["result"]


@pytest.mark.parametrize(
    "source",
    [
        "events=[]\ndef g():\n events.append(1)\n yield 1\nx=g()\nresult=(x.close(), next(x, 9), events)",
        "events=[]\ndef g():\n try: yield 1\n finally: events.append(2)\nx=g()\nnext(x)\nresult=(x.close(),x.close(),next(x,9),events)",
        "def g():\n try: yield 1\n except GeneratorExit: return\nx=g()\nnext(x)\nresult=(x.close(),next(x,9))",
        "def g():\n try: yield 1\n except Exception: yield 2\nx=g()\nnext(x)\nresult=(x.close(),next(x,9))",
        "def g():\n try: yield 1\n finally: raise ValueError()\nx=g()\nnext(x)\ntry: x.close()\nexcept ValueError: result=next(x,9)",
        "def g():\n try: yield 1\n except GeneratorExit: yield 2\nx=g()\nnext(x)\ntry: x.close()\nexcept RuntimeError: result=next(x,9)",
        "events=[]\ndef inner():\n try: yield 1\n finally: events.append(1)\ndef outer():\n try: yield from inner()\n finally: events.append(2)\nx=outer()\nnext(x)\nresult=(x.close(),events,next(x,9))",
        "def g():\n yield from [1,2]\nx=g()\nnext(x)\nresult=(x.close(),next(x,9))",
        "def g():\n try: x.close()\n except ValueError: yield True\nx=g()\nresult=(next(x),x.close())",
        "events=[]\nclass Inner:\n def __iter__(self): return self\n def __next__(self): return 1\n def close(self): raise ValueError()\ndef outer():\n try: yield from Inner()\n finally: events.append(2)\nx=outer()\nnext(x)\ntry: x.close()\nexcept ValueError: result=(events,next(x,9))",
    ],
)
def test_generator_close_matches_python(source):
    namespace = {}
    exec(source, namespace)
    actual, _, _ = run_source(source)
    assert actual == namespace["result"]


def test_generator_close_returns_value_with_python_313_semantics():
    source = "def g():\n try: yield 1\n except GeneratorExit: return 7\nx=g()\nnext(x)\nresult=(x.close(),next(x,9))"
    actual, _, _ = run_source(source)
    assert actual == (7, 9)
