"""Differential tests of lazy MIR suspension against trusted CPython fixtures."""

import ast
import textwrap

import pytest

from pyflow.ir.mir.generators import contains_yield
from tests.ir.mir.test_mir_lowering import run_source

SOURCES = [
    """
    events=[]
    def gen():
        events.append(1)
        yield 3
        events.append(2)
        yield 4
    g=gen()
    before=len(events)
    first=next(g)
    after=len(events)
    second=next(g)
    result=(before,first,after,second,events)
    """,
    """
    def gen():
        yield 1
        yield 2
    result=list(gen())
    """,
    """
    def gen(n):
        for x in range(n):
            yield x+1
    result=list(gen(4))
    """,
    """
    def gen(n):
        x=0
        while x<n:
            yield x
            x+=1
    result=list(gen(4))
    """,
    """
    def gen():
        value=yield 1
        yield value+1
    g=gen()
    result=(next(g),g.send(8),next(g,99))
    """,
    """
    def gen():
        yield 1
    g=gen()
    try:g.send(5)
    except TypeError:invalid=True
    result=(invalid,next(g))
    """,
    """
    def gen():
        yield 1
        return 7
    g=gen()
    first=next(g)
    try:next(g)
    except StopIteration as stop:value=stop.value
    result=(first,value,next(g,99))
    """,
    """
    def gen():
        raise StopIteration()
        yield 1
    g=gen()
    try:next(g)
    except RuntimeError:converted=True
    result=(converted,next(g,9))
    """,
    """
    def inner():
        yield 1
        return 7
    def outer():
        value=yield from inner()
        yield value
    result=list(outer())
    """,
    """
    def inner():
        value=yield 1
        return value+2
    def outer():
        answer=yield from inner()
        yield answer
    g=outer()
    result=(next(g),g.send(5),next(g,99))
    """,
    """
    def gen():
        yield from [2,3]
        yield 4
    result=list(gen())
    """,
    """
    def outer():
        x=4
        def gen():
            yield x
        x=7
        return gen()
    result=list(outer())
    """,
    """
    def gen():
        x=1
        def read():return x
        yield read
        x=9
        yield read
    g=gen()
    read=next(g)
    first=read()
    next(g)
    result=(first,read())
    """,
    """
    def gen():
        x=1
        def change():
            nonlocal x
            x=8
        yield x
        change()
        yield x
    result=list(gen())
    """,
    """
    def gen(start):
        yield start
        start+=1
        yield start
    a=gen(1)
    b=gen(10)
    result=(next(a),next(b),next(a),next(b))
    """,
    """
    x=2
    def gen(a=x,*args,**kwargs):
        yield a
        yield args[0]
        yield kwargs['value']
    x=9
    result=list(gen(1,3,value=5))
    """,
    """
    def outer():
        x=3
        def inner():
            yield x
        yield inner()
        x=6
    g=outer()
    inner=next(g)
    next(g,None)
    result=list(inner)
    """,
    """
    events=[]
    def gen():
        try:
            yield 1
            yield 2
        finally:events.append(9)
    g=gen()
    first=next(g)
    before=len(events)
    second=next(g)
    next(g,None)
    result=(first,before,second,events)
    """,
    """
    def gen():
        try:raise ValueError()
        except ValueError:
            yield 1
            raise
    g=gen()
    first=next(g)
    try:next(g)
    except ValueError:caught=True
    result=(first,caught,next(g,99))
    """,
    """
    events=[]
    def value(x):
        events.append(x)
        return x+1
    g=(value(x) for x in range(4) if x>1)
    before=len(events)
    first=next(g)
    after=len(events)
    result=(before,first,after,list(g),events)
    """,
    """
    result=list(x+y for x in [1,2] for y in [10,20] if y>10)
    """,
    """
    events=[]
    class Source:
        def __iter__(self):
            events.append(1)
            return iter([2,3])
    g=(x for x in Source())
    before=len(events)
    first=next(g)
    result=(before,first,len(events),list(g))
    """,
    """
    g=None
    def gen():
        next(g)
        yield 1
    g=gen()
    try:next(g)
    except ValueError:reentrant=True
    result=(reentrant,next(g,99))
    """,
    """
    make=lambda: (yield 2)
    g=make()
    result=(next(g),next(g,9))
    """,
    """
    def gen():
        def nested(x=(yield 1)):
            return x
        yield nested()
    g=gen()
    result=(next(g),g.send(7))
    """,
    """
    class Iterator:
        def __iter__(self):return self
        def __next__(self):raise StopIteration(9)
    def gen():
        value=yield from Iterator()
        yield value
    result=list(gen())
    """,
    """
    def add(a,b):return a+b
    def gen():
        yield add(2,(yield 3))
    g=gen()
    result=(next(g),g.send(5))
    """,
    """
    def gen():
        try:return 3
        finally:yield 1
    g=gen()
    first=next(g)
    try:next(g)
    except StopIteration as stop:value=stop.value
    result=(first,value)
    """,
    """
    class A:
        @classmethod
        def f(cls):return 3
    class B(A):
        @classmethod
        def gen(cls):
            yield super().f()
            yield __class__ is B
    result=list(B.gen())
    """,
    """
    def gen():
        class C:
            def f(self,x=7):return x
        yield C().f()
        yield C
    g=gen()
    first=next(g)
    cls=next(g)
    result=(first,cls().f())
    """,
    """
    def gen():
        if False:yield 1
        return None
    try:next(gen())
    except StopIteration as stop:result=(stop.value,stop.args)
    """,
]


@pytest.mark.parametrize("source", SOURCES, ids=lambda source: str(SOURCES.index(source)))
def test_generator_matches_cpython(source):
    source = textwrap.dedent(source)
    # The only host execution is these checked-in, trusted test fixtures.
    namespace = {"__name__": "__main__"}
    exec(compile(source, "<generator-oracle>", "exec"), namespace)
    actual, program, _ = run_source(source)
    assert actual == namespace["result"]
    assert any(name.endswith(".$factory") for name in program.cfgs)
    allowed = {"Skip", "Assume", "Alloc", "Bind", "Env", "Delete", "Call"}
    assert {
        type(node.instruction).__name__
        for cfg in program.cfgs.values()
        for node in cfg.nodes.values()
    } <= allowed


def test_yield_detection_respects_function_boundaries_and_default_evaluation():
    regular = ast.parse("def outer():\n def inner():yield 1\n return inner").body[0]
    generator = ast.parse("def outer():\n def inner(x=(yield 1)):return x").body[0]
    assert not contains_yield(regular)
    assert contains_yield(generator)
