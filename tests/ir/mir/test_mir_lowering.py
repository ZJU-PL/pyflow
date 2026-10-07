"""End-to-end semantic checks of Python lowering through the MIR interpreter.

Expected values are independent Python-language examples, not snapshots of the
emitted instructions.  None of the analyzed modules is imported or executed by
the frontend; the only execution here is the explicit MIR reference machine.
"""

import textwrap

import pytest

from pyflow.ir.mir import LoweringError, MIRInterpreter, lower_file, lower_source
from pyflow.ir.mir.interpreter import ListValue, ObjectValue


def run_source(source, *, filename="<string>"):
    program = lower_source(textwrap.dedent(source), filename=filename)
    execution = MIRInterpreter(program, max_steps=500_000).run()
    memory = execution.memory
    builtins = execution.value("$builtins")
    module = execution.value("$return")
    environment = memory[module.fields["$env"]]
    state = memory[builtins.fields["$state"]]
    exception = state.fields["exception"]
    if exception != builtins.fields["None"]:
        cls = memory[memory[exception].fields["__class__"]]
        name = memory[cls.fields["__name__"]]
        if isinstance(name, ObjectValue):
            name = memory[name.fields["$value"]]
        pytest.fail(f"Unexpected modeled Python exception: {name}")

    def decode(address):
        if address == builtins.fields["None"]:
            return None
        value = memory[address]
        if not isinstance(value, ObjectValue):
            return value
        if "$value" not in value.fields:
            return address  # Identity remains available for reference tests.
        payload = memory[value.fields["$value"]]
        if isinstance(payload, ListValue):
            if value.fields["__class__"] == builtins.fields["dict"]:
                return {
                    decode(memory[pair].fields["key"]): decode(memory[pair].fields["value"])
                    for pair in payload.items
                }
            items = [decode(item) for item in payload.items]
            if value.fields["__class__"] == builtins.fields["tuple"]:
                return tuple(items)
            if value.fields["__class__"] == builtins.fields["set"]:
                return set(items)
            return items
        return payload

    return decode(environment.fields["result"]), program, execution


@pytest.mark.parametrize(
    "source,expected",
    [
        ("result = (1 + 2) * 3 - 4", 5),
        ("result = -7 // 3", -3),
        ("result = (-7 % 3, 2 ** 5)", (2, 32)),
        ("result = len('abc')", 3),
        ("result = ('ab' + 'cd')[-1]", "d"),
        ("x=[1,2]; y=x; x.append(3); y[-1]=4; result=x", [1, 2, 4]),
        ("d={'a':1, 2:3}; d['a']=4; result=(d['a'],d[2])", (4, 3)),
        ("a,*b,c=[1,2,3,4]; result=(a,b,c)", (1, [2, 3], 4)),
        ("def f(a,b=3,*,c=4): return a+b+c\nresult=f(2,c=5)", 10),
        ("def f(*args,**kw): return args[1]+kw['x']\nresult=f(1,2,x=3)", 5),
        ("def f(a,/,**kw): return a+kw['a']\nresult=f(1,a=2)", 3),
        ("def f(a,b,*,x): return a+b+x\nresult=f(*[1,2],**{'x':3})", 6),
        ("def f(**kw): return kw['$values']\nresult=f(**{'$values':7})", 7),
        ("def f(n):\n if n<2:return 1\n return n*f(n-1)\nresult=f(5)", 120),
        ("def outer():\n x=1\n def inner(): return x\n x=2\n return inner\nresult=outer()()", 2),
        (
            "def outer():\n"
            " x=1\n"
            " def inner():\n"
            "  nonlocal x\n"
            "  x=3\n"
            " inner()\n"
            " return x\n"
            "result=outer()",
            3,
        ),
        ("x=1\ndef f():\n global x\n x=5\nf()\nresult=x", 5),
        (
            "def deco(f):\n"
            " def wrapped():return f()+1\n"
            " return wrapped\n"
            "@deco\n"
            "def f():return 2\n"
            "result=f()",
            3,
        ),
        ("x=1\ndef f(v=x):return v\nx=2\nresult=f()", 1),
        ("result=0\nfor x in range(5):\n if x==3:break\n result+=x\nelse:result=99", 3),
        ("result=0\nfor x in range(3):\n if x==1:continue\n result+=x\nelse:result+=10", 12),
        ("i=0; result=0\nwhile i<3:\n result+=i\n i+=1\nelse:result+=10", 13),
        ("result=[x+1 for x in range(4) if x>1]", [3, 4]),
        ("result={x:x+1 for x in range(3)}", {0: 1, 1: 2, 2: 3}),
        ("x=10\nresult=[x for x in [1,2]]\nresult=(result,x)", ([1, 2], 10)),
        ("class A:\n def __call__(self,x):return x+1\nresult=A()(3)", 4),
        (
            "class A:\n"
            " def __init__(self,x):self.x=x\n"
            " def get(self):return self.x\n"
            "class B(A):pass\n"
            "result=B(3).get()",
            3,
        ),
        (
            "class A:\n"
            " def __add__(self,o):return 1\n"
            "class B(A):\n"
            " def __radd__(self,o):return 2\n"
            "result=A()+B()",
            2,
        ),
        (
            "class A:\n"
            " def __add__(self,o):return NotImplemented\n"
            "class B:\n"
            " def __radd__(self,o):return 4\n"
            "result=A()+B()",
            4,
        ),
        (
            "class A:\n"
            " def __eq__(self,o):return self.tag\n"
            "class B(A):pass\n"
            "a=A();a.tag=1\n"
            "b=B();b.tag=2\n"
            "result=a==b",
            2,
        ),
        ("class A:\n @property\n def x(self):return 3\nresult=A().x", 3),
        (
            "class A:\n"
            " def __getattribute__(self,n):raise AttributeError()\n"
            " def __getattr__(self,n):return 7\n"
            "result=A().x",
            7,
        ),
        (
            "class A:\n"
            " def f(self):return 2\n"
            "class B(A):\n"
            " def f(self):return super().f()+1\n"
            "result=B().f()",
            3,
        ),
        (
            "class A:\n"
            " @classmethod\n"
            " def f(cls):return 2\n"
            "class B(A):\n"
            " @classmethod\n"
            " def f(cls):return super().f()+1\n"
            "result=B.f()",
            3,
        ),
        ("class A:\n def f(self):return __class__\nresult=A().f() is A", True),
        ("class A:\n def __init_subclass__(cls):cls.x=9\nclass B(A):pass\nresult=B.x", 9),
        ("class D:\n def __set_name__(self,owner,name):owner.x=9\nclass A:d=D()\nresult=A.x", 9),
        ("try:\n raise ValueError()\nexcept ValueError:result=9", 9),
        ("try:\n x=[1];x[5]\nexcept IndexError:result=8", 8),
        ("def f():\n try:return 1\n finally:return 2\nresult=f()", 2),
        ("x=[]\ndef f():\n try:return 1\n finally:x.append(2)\nresult=(f(),x)", (1, [2])),
        ("try:\n try:raise ValueError()\n finally:x=3\nexcept ValueError:result=x", 3),
        (
            "class A:\n def __bool__(self):return 1\ntry:\n if A():pass\nexcept TypeError:result=1",
            1,
        ),
        (
            "class A:\n"
            " def __len__(self):return -1\n"
            "try:\n"
            " if A():pass\n"
            "except ValueError:result=1",
            1,
        ),
        (
            "x=[]\n"
            "class C:\n"
            " def __enter__(self):x.append(1);return 3\n"
            " def __exit__(self,*args):x.append(2)\n"
            "with C() as v:x.append(v)\n"
            "result=x",
            [1, 3, 2],
        ),
        (
            "class C:\n"
            " def __enter__(self):return self\n"
            " def __exit__(self,*args):return True\n"
            "with C():raise ValueError()\n"
            "result=7",
            7,
        ),
        ("class C:\n def __iter__(self):return iter([1,2])\nresult=2 in C()", True),
        (
            "result=0\ntry:\n for x in [1]:break\n result=result*10+1\nfinally:result=result*10+2",
            12,
        ),
        (
            "result=0\n"
            "try:\n"
            " for x in [1,2]:continue\n"
            " result=result*10+1\n"
            "finally:result=result*10+2",
            12,
        ),
        ("try:\n try:pass\n finally:raise\nexcept RuntimeError:result=7", 7),
        (
            "def f():\n"
            " try:raise ValueError()\n"
            " except ValueError as error:return lambda:error\n"
            "g=f()\n"
            "try:g()\n"
            "except NameError:result=8",
            8,
        ),
        (
            "def f():\n"
            " try:\n"
            "  try:return 1\n"
            "  except ValueError:return 2\n"
            "  finally:raise ValueError()\n"
            " except ValueError:return 3\n"
            "result=f()",
            3,
        ),
        (
            "class C:\n"
            " def __enter__(self):return self\n"
            " def __exit__(self,*args):raise ValueError()\n"
            "def f():\n"
            " with C():return 1\n"
            "try:f()\n"
            "except ValueError:result=7",
            7,
        ),
    ],
)
def test_python_lowering_semantics(source, expected):
    actual, _, _ = run_source(source)
    assert actual == expected


@pytest.mark.parametrize(
    "source,fragment",
    [
        ("x=1.5", "float"),
        ("x=b'x'", "bytes"),
        ("x=[1,2][:1]", "slice"),
        ("async def f():pass", "AsyncFunctionDef"),
        ("class C(metaclass=type):pass", "metaclass"),
        ("x=f'{1}'", "JoinedStr"),
        ("import not_a_local_module", "no local source"),
    ],
)
def test_unsupported_features_are_diagnostics(source, fragment):
    with pytest.raises(LoweringError, match=fragment):
        lower_source(source, filename="unsupported.py")


def test_local_package_imports_and_cycles(tmp_path):
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text("seed=4\n", encoding="utf-8")
    (package / "a.py").write_text(
        "from . import seed\nfrom .b import f\nresult=f(seed)\n", encoding="utf-8"
    )
    (package / "b.py").write_text("from . import a\ndef f(x):return x+1\n", encoding="utf-8")
    program = lower_file(package / "a.py", project_root=tmp_path)
    execution = MIRInterpreter(program).run()
    modules = execution.value("$modules")
    module = execution.memory[modules.fields["pkg.a"]]
    environment = execution.memory[module.fields["$env"]]
    result = execution.memory[environment.fields["result"]]
    assert execution.memory[result.fields["$value"]] == 5


def test_source_locations_and_core_instruction_grammar():
    _, program, _ = run_source("def f():return 1\nresult=f()", filename="example.py")
    allowed = {"Skip", "Assume", "Alloc", "Bind", "Env", "Delete", "Call"}
    assert {
        type(node.instruction).__name__
        for cfg in program.cfgs.values()
        for node in cfg.nodes.values()
    } <= allowed
    assert program.cfgs["__main__.f"].filename == "example.py"
    assert any(node.lineno == 2 for node in program.cfgs["__main__"].nodes.values())
