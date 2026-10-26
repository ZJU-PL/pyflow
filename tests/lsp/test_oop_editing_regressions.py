"""Top100 regressions for retained scopes, OOP queries and builtin operators."""

import pytest
from pyflow.lsp.workspace import SourceIndex
from pyflow.lsp.document_analysis import infer_document


def indexed(tmp_path, source):
    path = tmp_path / "app.py"
    return SourceIndex({str(path): source}, (tmp_path,)), path


def errors(source):
    return [
        item
        for item in infer_document("/tmp/oop_probe.py", "oop_probe", source).diagnostics
        if item.code == "annotation-mismatch"
    ]


def test_appended_incomplete_method_line_preserves_self_and_parameters(tmp_path):
    source = "class Text:\n    def __init__(self): self._length = 1\n    def size(self, width):\n        return self._length\n"
    index, path = indexed(tmp_path, source)
    edited = source + "        self."
    current = index.with_source_files({str(path): edited})
    bindings = current.visible_bindings_at(path.as_uri(), 4, len("        self."))
    assert {"self", "width"} <= bindings.keys()
    assert "_length" in {
        item["label"] for item in current.completion_items(path.as_uri(), 4, len("        self."))
    }


def test_new_blank_line_uses_function_scope_even_when_parse_is_valid(tmp_path):
    source = "def compute(value):\n    local = value\n    return local\n    "
    index, path = indexed(tmp_path, source)
    assert {"value", "local"} <= index.visible_bindings_at(path.as_uri(), 3, 4).keys()


def test_retained_module_scope_covers_appended_buffer(tmp_path):
    source = "def top(): pass\n"
    index, path = indexed(tmp_path, source)
    current = index.with_source_files({str(path): source + "\nnew_value = "})
    assert "top" in current.visible_bindings_at(path.as_uri(), 2, len("new_value = "))


def test_retained_function_does_not_cross_next_dedented_definition(tmp_path):
    source = "def first(first_param):\n    return first_param\ndef second(second_param):\n    return second_param\n"
    index, path = indexed(tmp_path, source)
    source = source.replace("    return second_param", "    second_param.")
    current = index.with_source_files({str(path): source})
    bindings = current.visible_bindings_at(path.as_uri(), 3, len("    second_param."))
    assert "second_param" in bindings
    assert "first_param" not in bindings


BASE = """class Base:
    def __init__(self, name: str, enabled=True): pass
    def run(self, count: int = 2) -> int: return count
class Derived(Base):
    def __init__(self, name):
        super().__init__(name=name)
    def run(self, count=2):
        return super().run(count)
"""


def test_super_method_and_super_token_navigate_to_base(tmp_path):
    index, path = indexed(tmp_path, BASE)
    assert index.definitions_at(path.as_uri(), 5, 19)[0].start_line == 1
    assert index.definitions_at(path.as_uri(), 5, 10)[0].start_line == 0
    assert index.definitions_at(path.as_uri(), 7, 25)[0].start_line == 2


def test_super_completion_and_bound_signature_on_new_line(tmp_path):
    index, path = indexed(tmp_path, BASE)
    text = BASE + "        super()."
    current = index.with_source_files({str(path): text})
    assert "run" in {
        item["label"]
        for item in current.completion_items(path.as_uri(), 8, len("        super()."))
    }
    result = index.signature_help(path.as_uri(), 5, len("        super().__init__("))
    assert result["signatures"][0]["label"] == "__init__(name: str, enabled = True)"


def test_explicit_super_resolves_and_shadowed_super_does_not(tmp_path):
    source = BASE.replace("super().run(count)", "super(Derived, self).run(count)")
    index, path = indexed(tmp_path, source)
    column = source.splitlines()[7].index(".run") + 2
    assert index.definitions_at(path.as_uri(), 7, column)[0].start_line == 2
    shadowed = BASE.replace("def run(self, count=2):", "def run(self, count=2, super=None):")
    index, path = indexed(tmp_path, shadowed)
    assert not index.definitions_at(path.as_uri(), 7, 25)


@pytest.mark.parametrize(
    "left,right,annotation",
    [
        ("'x %s'", "(1,)", "str"),
        ("'%(x)s'", "{'x':1}", "str"),
        ("b'x %s'", "(b'a',)", "bytes"),
        ("5", "2", "int"),
    ],
)
def test_modulo_formatting_and_numeric_modulo(left, right, annotation):
    assert not errors(f"def format_value() -> {annotation}:\n    return {left} % {right}\n")
    wrong = "bytes" if annotation == "str" else "str"
    assert errors(f"def format_value() -> {wrong}:\n    return {left} % {right}\n")


@pytest.mark.parametrize("container", ["dict", "set", "frozenset"])
def test_container_union_joins_element_arguments(container):
    first = "dict[str, int]" if container == "dict" else f"{container}[int]"
    second = "dict[str, str]" if container == "dict" else f"{container}[str]"
    result = "dict[str, int | str]" if container == "dict" else f"{container}[int | str]"
    source = f"def merge(a: {first}, b: {second}) -> {result}:\n    return a | b\n"
    assert not errors(source)
    assert errors(source.replace(f"-> {result}", f"-> {first}"))


def test_union_receiver_completions_include_both_branches_without_unsafe_navigation(tmp_path):
    source = "class Cat:\n    def meow(self): pass\n    def common(self): pass\nclass Dog:\n    def bark(self): pass\n    def common(self): pass\ndef handle(animal: Cat | Dog):\n    animal.common()\n"
    index, path = indexed(tmp_path, source)
    current = index.with_source_files({str(path): source + "    animal."})
    assert {"meow", "bark", "common"} <= {
        item["label"] for item in current.completion_items(path.as_uri(), 8, len("    animal."))
    }
    assert not index.definitions_at(path.as_uri(), 7, len("    animal.co"))
    assert not index.rename_ranges_at(path.as_uri(), 7, len("    animal.co"))


@pytest.mark.parametrize(
    "header",
    [
        "from dataclasses import dataclass\n@dataclass",
        "import dataclasses as dc\n@dc.dataclass()",
        "from typing import NamedTuple\n",
    ],
)
def test_generated_constructor_keywords_link_to_field_references_and_rename(tmp_path, header):
    declaration = "class Point(NamedTuple):" if "NamedTuple" in header else "class Point:"
    source = f"{header}\n{declaration}\n    x: int\n    y: int\np = Point(x=1, y=2)\nprint(p.x)\n"
    index, path = indexed(tmp_path, source)
    lines = source.splitlines()
    call = next(i for i, text in enumerate(lines) if text.startswith("p = "))
    field = next(i for i, text in enumerate(lines) if text.strip() == "x: int")
    column = lines[call].index("x=")
    assert index.definitions_at(path.as_uri(), call, column)[0].start_line == field
    ranges = index.rename_ranges_at(path.as_uri(), field, 4)
    assert {item.start_line for item in ranges} == {field, call, call + 1}
    from pyflow.lsp.refactor import validate_rename

    validate_rename(index, index.symbol_at(path.as_uri(), field, 4), ranges, "x_coord")


def test_regular_annotated_class_is_not_assumed_to_accept_field_keywords(tmp_path):
    source = "class Point:\n    x: int\np = Point(x=1)\n"
    index, path = indexed(tmp_path, source)
    assert not index.definitions_at(path.as_uri(), 2, len("p = Point("))


def test_dataclass_init_options_classvars_and_explicit_constructor(tmp_path):
    source = """from dataclasses import dataclass, field
from typing import ClassVar
@dataclass
class Point:
    x: int
    hidden: int = field(init=False)
    tag: ClassVar[str] = 'point'
p = Point(x=1, hidden=2, tag='bad')
"""
    index, path = indexed(tmp_path, source)
    for name in ("hidden", "tag"):
        assert not index.definitions_at(path.as_uri(), 7, source.splitlines()[7].index(name + "="))
    assert (
        index.definitions_at(path.as_uri(), 7, source.splitlines()[7].index("x="))[0].start_line
        == 4
    )
    explicit = """from dataclasses import dataclass
@dataclass
class Point:
    x: int
    def __init__(self, value): self.x=value
p = Point(value=1, x=2)
"""
    index, path = indexed(tmp_path, explicit)
    assert index.definitions_at(path.as_uri(), 5, len("p = Point("))[0].start_line == 4
    assert not index.definitions_at(path.as_uri(), 5, explicit.splitlines()[5].index("x="))
    disabled = source.replace("@dataclass", "@dataclass(init=False)")
    index, path = indexed(tmp_path, disabled)
    assert not index.definitions_at(path.as_uri(), 7, disabled.splitlines()[7].index("x="))


def test_dataclass_inherited_fields_have_keyword_definitions(tmp_path):
    source = "from dataclasses import dataclass\n@dataclass\nclass Base:\n    x: int\n@dataclass\nclass Child(Base):\n    y: int\nc = Child(x=1, y=2)\n"
    index, path = indexed(tmp_path, source)
    assert index.definitions_at(path.as_uri(), 7, len("c = Child("))[0].start_line == 3
    assert (
        index.definitions_at(path.as_uri(), 7, source.splitlines()[7].index("y="))[0].start_line
        == 6
    )


def test_callable_return_variable_hover_displays_signature_and_docstring(tmp_path):
    source = '''def make_adder(x: int):
    def adder(y: int) -> int:
        """Add the captured value."""
        return x+y
    return adder
add5 = make_adder(5)
res = add5(10)
'''
    index, path = indexed(tmp_path, source)
    hover = index.hover_at(path.as_uri(), 6, 8)["contents"]["value"]
    assert "add5: (y: int) -> int" in hover
    assert "Add the captured value." in hover


@pytest.mark.parametrize(
    "callee", ["client.\\\n    connect", "(client\n     .connect)", "client\n    .connect"]
)
def test_signature_help_receiver_can_span_multiple_physical_lines(tmp_path, callee):
    source = (
        "class Client:\n    def connect(self, hostname: str, timeout=3): pass\nclient=Client()\n"
    )
    # Parenthesize the whole expression to permit implicit continuation.
    call = "(" + callee + '(\n    hostname="localhost",\n    timeout=2\n))\n'
    source += call
    index, path = indexed(tmp_path, source)
    row = next(i for i, text in enumerate(source.splitlines()) if "timeout=2" in text)
    result = index.signature_help(path.as_uri(), row, len("    timeout="))
    assert result["signatures"][0]["label"] == "connect(hostname: str, timeout = 3)"
    assert result["activeParameter"] == 1


def test_multiline_signature_help_in_new_appended_incomplete_call(tmp_path):
    source = "def connect(hostname, timeout=3): pass\n"
    index, path = indexed(tmp_path, source)
    edited = source + 'connect(\n    hostname="localhost",\n    '
    current = index.with_source_files({str(path): edited})
    result = current.signature_help(path.as_uri(), 3, 4)
    assert result["signatures"][0]["label"] == "connect(hostname, timeout = 3)"
    assert result["activeParameter"] == 1


def test_completion_on_empty_eof_line_inside_function(tmp_path):
    index, path = indexed(tmp_path, "def handle(argument):\n    local = argument\n")
    assert {"argument", "local"} <= {
        item["label"] for item in index.completion_items(path.as_uri(), 2, 0)
    }


def test_tab_indented_scope_survives_an_appended_member(tmp_path):
    source = "class Text:\n\tdef f(self):\n\t\treturn self\n"
    index, path = indexed(tmp_path, source)
    current = index.with_source_files({str(path): source + "\t\tself."})
    assert "f" in {
        item["label"] for item in current.completion_items(path.as_uri(), 3, len("\t\tself."))
    }


def test_class_scope_continues_on_appended_incomplete_line(tmp_path):
    source = "class Text:\n    value = 1\n"
    index, path = indexed(tmp_path, source)
    current = index.with_source_files({str(path): source + "    unfinished = "})
    assert "value" in current.visible_bindings_at(path.as_uri(), 2, len("    unfinished = "))


def test_formatting_preserves_alternative_left_operand_types():
    source = "def fmt(value: str | bytes, args) -> str | bytes:\n    return value % args\n"
    assert not errors(source)
    assert errors(source.replace("-> str | bytes", "-> str"))


def test_generated_constructor_cache_invalidates_when_decorator_options_change(tmp_path):
    point = str(tmp_path / "point.py")
    consumer = str(tmp_path / "consumer.py")
    sources = {
        point: "from dataclasses import dataclass\n@dataclass\nclass Point:\n    x: int\n",
        consumer: "from point import Point\np=Point(x=1)\n",
    }
    index = SourceIndex(sources, (tmp_path,))
    uri = (tmp_path / "consumer.py").as_uri()
    assert index.definitions_at(uri, 1, len("p=Point("))
    sources[point] = sources[point].replace("@dataclass", "@dataclass(init=False)")
    current = index.with_source_files(sources)
    assert not current.definitions_at(uri, 1, len("p=Point("))


def test_dataclass_field_rename_is_rejected_for_ambiguous_constructor_keywords(tmp_path):
    source = "from dataclasses import dataclass\n@dataclass\nclass A:\n    x: int\n@dataclass\nclass B:\n    x: int\ndef f(flag):\n    cls = A if flag else B\n    return cls(x=1)\n"
    index, path = indexed(tmp_path, source)
    assert not index.rename_ranges_at(path.as_uri(), 3, 4)


def test_imported_unknown_format_string_does_not_return_its_mapping_argument():
    source = 'from external_templates import D\ndef format_value() -> str:\n    return D % {"text": "hello"}\n'
    result = infer_document("/tmp/imported_format.py", "imported_format", source)
    assert not [item for item in result.diagnostics if item.code == "annotation-mismatch"]
    values = [
        value
        for span, value in result.expressions.items()
        if span.lineno == 3 and span.col_offset == 11
    ]
    assert values and values[0].unknown


def test_super_init_keyword_references_are_bound_to_base_parameters(tmp_path):
    index, path = indexed(tmp_path, BASE)
    column = BASE.splitlines()[5].index("name=")
    assert index.definitions_at(path.as_uri(), 5, column)[0].start_line == 1
    assert any(
        item.start_line == 5
        for item in index.rename_ranges_at(path.as_uri(), 1, len("    def __init__(self, "))
    )


def test_generic_type_parameters_remain_visible_on_appended_function_lines(tmp_path):
    import sys

    if sys.version_info < (3, 12):
        pytest.skip("PEP 695 requires Python 3.12")
    source = "def make[T](value: T) -> T:\n    return value\n"
    index, path = indexed(tmp_path, source)
    current = index.with_source_files({str(path): source + "    unfinished = "})
    assert {"T", "value"} <= current.visible_bindings_at(
        path.as_uri(), 2, len("    unfinished = ")
    ).keys()


def test_annotation_wrapped_alternatives_offer_both_member_sets(tmp_path):
    source = "class Cat:\n    def meow(self): pass\nclass Dog:\n    def bark(self): pass\ndef handle(animal: Cat | Dog): pass\n"
    index, path = indexed(tmp_path, source)
    parameter = next(symbol for symbol in index.symbols if symbol.name == "animal")
    annotation = index._resolver.values[parameter.symbol_id][0]
    assert {"meow", "bark"} <= {symbol.name for symbol in index._resolver.members(annotation)}


def test_ambiguous_super_members_do_not_select_arbitrary_base_definitions(tmp_path):
    source = "class Left:\n    def run(self): pass\nclass Right:\n    def run(self): pass\nclass Child(Left, Right):\n    def run(self):\n        return super().run()\n"
    index, path = indexed(tmp_path, source)
    assert not index.definitions_at(path.as_uri(), 6, 24)
    assert not index.rename_ranges_at(path.as_uri(), 1, 9)
