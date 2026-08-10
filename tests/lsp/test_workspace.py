"""Tests for source-accurate LSP workspace indexing."""

from pathlib import Path

from pyflow.lsp.workspace import (
    SourceIndex,
    SymbolKind,
    WorkspaceDocuments,
    lsp_character_to_offset,
    offset_to_lsp_character,
    path_to_uri,
    uri_to_path,
)


def _index(tmp_path: Path) -> tuple[SourceIndex, str]:
    path = tmp_path / "sample.py"
    source = (
        "def target(value):\n"
        "    return value\n\n"
        "def caller():\n"
        "    return target(1)\n"
    )
    path.write_text(source)
    return SourceIndex({str(path): source}, (tmp_path,)), path.as_uri()


def test_file_uri_round_trip_handles_spaces(tmp_path: Path):
    path = tmp_path / "with space.py"
    assert uri_to_path(path_to_uri(path)) == str(path.absolute())


def test_utf16_character_conversion():
    line = "a😀b"
    assert lsp_character_to_offset(line, 3) == 2
    assert offset_to_lsp_character(line, 2) == 3


def test_document_symbols_are_filtered_by_uri(tmp_path: Path):
    index, uri = _index(tmp_path)
    assert [symbol.name for symbol in index.document_symbols(uri)] == [
        "target",
        "caller",
    ]
    assert index.document_symbols("file:///other.py") == []


def test_definition_resolves_identifier_under_cursor(tmp_path: Path):
    index, uri = _index(tmp_path)
    definitions = index.definitions_at(uri, 4, 12)
    assert len(definitions) == 1
    assert definitions[0].start_line == 0
    assert definitions[0].start_character == 4


def test_references_return_real_source_locations(tmp_path: Path):
    index, uri = _index(tmp_path)
    references = index.references_at(uri, 0, 5, include_declaration=True)
    assert {(item.start_line, item.start_character) for item in references} == {
        (0, 4),
        (4, 11),
    }


def test_call_hierarchy_uses_call_site_ranges(tmp_path: Path):
    index, _uri = _index(tmp_path)
    incoming = index.incoming_calls("sample.target")
    assert len(incoming) == 1
    caller, ranges = incoming[0]
    assert caller.qualified_name == "sample.caller"
    assert ranges[0].start_line == 4

    outgoing = index.outgoing_calls("sample.caller")
    assert len(outgoing) == 1
    assert outgoing[0][0].qualified_name == "sample.target"


def test_workspace_documents_track_overlays(tmp_path: Path):
    documents = WorkspaceDocuments()
    path = str(tmp_path / "sample.py")
    documents.open(path, "x = 1\n", 1)
    documents.change(path, [{"text": "x = 2\n"}], 2)
    assert documents.source_overrides()[path] == "x = 2\n"
    documents.close(path)
    assert documents.source_overrides() == {}


def test_workspace_documents_apply_incremental_utf16_changes_and_reject_stale():
    documents = WorkspaceDocuments()
    path = "/tmp/sample.py"
    assert documents.open(path, "value = '😀'\n", 1)
    assert documents.change(
        path,
        [
            {
                "range": {
                    "start": {"line": 0, "character": 0},
                    "end": {"line": 0, "character": 5},
                },
                "text": "result",
            }
        ],
        2,
    )
    assert documents.text(path) == "result = '😀'\n"
    assert not documents.change(path, [{"text": "stale"}], 1)
    assert documents.text(path) == "result = '😀'\n"


def test_symbol_identity_distinguishes_methods_and_local_shadowing(tmp_path: Path):
    path = tmp_path / "symbols.py"
    source = (
        "class A:\n    def foo(self): return 1\n\n"
        "class B:\n    def foo(self): return 2\n\n"
        "def foo(): return 3\n\n"
        "def use():\n    foo = 4\n    return foo\n"
    )
    index = SourceIndex({str(path): source}, (tmp_path,))
    a_foo = index.symbol_by_name("symbols.A.foo")
    b_foo = index.symbol_by_name("symbols.B.foo")
    local_foo = index.definitions_at(path.as_uri(), 9, 4)[0]

    assert a_foo is not None and b_foo is not None
    assert a_foo.symbol_id != b_foo.symbol_id
    assert a_foo.symbol_id.kind is SymbolKind.METHOD
    assert local_foo.start_line == 9
    references = index.references_at(
        path.as_uri(), 10, 11, include_declaration=True
    )
    assert {item.start_line for item in references} == {9, 10}


def test_import_alias_resolves_to_imported_symbol_identity(tmp_path: Path):
    provider = tmp_path / "provider.py"
    consumer = tmp_path / "consumer.py"
    provider_source = "def target():\n    return 1\n"
    consumer_source = "from provider import target as alias\n\ndef use():\n    return alias()\n"
    index = SourceIndex(
        {str(provider): provider_source, str(consumer): consumer_source}, (tmp_path,)
    )

    definition = index.definitions_at(consumer.as_uri(), 3, 11)

    assert len(definition) == 1
    assert definition[0].uri == provider.as_uri()


def test_reassignment_reuses_lexical_binding_and_nested_function_is_not_method(
    tmp_path: Path,
):
    path = tmp_path / "bindings.py"
    source = (
        "class A:\n"
        "    def method(self):\n"
        "        def inner():\n"
        "            return 1\n"
        "        return inner\n\n"
        "def use():\n"
        "    value = 1\n"
        "    value = 2\n"
        "    return value\n"
    )
    index = SourceIndex({str(path): source}, (tmp_path,))

    inner = index.symbol_by_name("bindings.A.method.inner")
    assignment = index.symbol_at(path.as_uri(), 8, 5)
    reference = index.symbol_at(path.as_uri(), 9, 12)

    assert inner is not None
    assert inner.symbol_id.kind is SymbolKind.FUNCTION
    assert assignment is not None and reference is not None
    assert assignment.symbol_id == reference.symbol_id
    assert len([s for s in index.symbols if s.name == "value"]) == 1


def test_ambiguous_symbol_fallback_and_multi_root_module_identity(tmp_path: Path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    first_file = first / "shared.py"
    second_file = second / "shared.py"
    first_file.write_text("def same(): pass\n\ndef use(): return same()\n")
    second_file.write_text("def same(): pass\n")
    index = SourceIndex(
        {
            str(first_file): first_file.read_text(),
            str(second_file): second_file.read_text(),
        },
        (first, second),
    )

    assert {symbol.module for symbol in index.symbols} == {"shared"}
    assert index.symbol_by_name("same") is None
    assert index.incoming_calls("same") == []


def test_method_bare_names_skip_the_enclosing_class_namespace(tmp_path: Path):
    path = tmp_path / "scope.py"
    source = (
        "value = 1\n\n"
        "class A:\n"
        "    value = 2\n\n"
        "    def method(self):\n"
        "        return value\n"
    )
    index = SourceIndex({str(path): source}, (tmp_path,))
    global_value = index.symbol_at(path.as_uri(), 0, 1)
    class_value = index.symbol_at(path.as_uri(), 3, 5)
    reference = next(ref for ref in index.references if ref.location.start_line == 6)

    assert global_value is not None and class_value is not None
    assert reference.symbol_id == global_value.symbol_id
    assert reference.symbol_id != class_value.symbol_id


def test_self_attribute_resolution_remains_separate_from_bare_names(tmp_path: Path):
    path = tmp_path / "attributes.py"
    source = (
        "class A:\n"
        "    value = 2\n\n"
        "    def method(self):\n"
        "        return self.value\n"
    )
    index = SourceIndex({str(path): source}, (tmp_path,))
    class_value = index.symbol_at(path.as_uri(), 1, 5)
    attribute_reference = next(
        ref for ref in index.references if ref.name == "value" and ref.location.start_line == 4
    )

    assert class_value is not None
    assert attribute_reference.symbol_id == class_value.symbol_id


def test_function_bindings_are_predeclared_with_global_and_nonlocal_rules(
    tmp_path: Path,
):
    path = tmp_path / "bindings.py"
    source = (
        "value = 0\n\n"
        "def outer():\n"
        "    value = 1\n"
        "    def inner():\n"
        "        nonlocal value\n"
        "        value = 2\n"
        "        return value\n"
        "    return inner\n\n"
        "def use_before_assignment():\n"
        "    print(value)\n"
        "    value = 3\n"
        "    return value\n\n"
        "def set_global():\n"
        "    global value\n"
        "    value = 4\n"
    )
    index = SourceIndex({str(path): source}, (tmp_path,))
    outer_value = index.symbol_at(path.as_uri(), 3, 5)
    global_value = index.symbol_at(path.as_uri(), 0, 1)
    local_value = index.symbol_at(path.as_uri(), 12, 5)
    inner_references = [
        ref for ref in index.references if ref.location.start_line in {6, 7}
    ]
    before_assignment = next(
        ref
        for ref in index.references
        if ref.location.start_line == 11 and ref.name == "value"
    )
    global_assignment = next(
        ref for ref in index.references if ref.location.start_line == 17
    )

    assert outer_value is not None and global_value is not None and local_value is not None
    assert {ref.symbol_id for ref in inner_references} == {outer_value.symbol_id}
    assert before_assignment.symbol_id == local_value.symbol_id
    assert global_assignment.symbol_id == global_value.symbol_id


def test_function_decorators_and_defaults_resolve_in_enclosing_scope(tmp_path: Path):
    path = tmp_path / "defaults.py"
    source = (
        "decorator = object()\n"
        "default = 1\n\n"
        "@decorator\n"
        "def function(value=default):\n"
        "    return value\n"
    )
    index = SourceIndex({str(path): source}, (tmp_path,))
    decorator = index.symbol_at(path.as_uri(), 0, 1)
    default = index.symbol_at(path.as_uri(), 1, 1)
    decorator_reference = next(
        ref for ref in index.references if ref.location.start_line == 3
    )
    default_reference = next(
        ref for ref in index.references if ref.location.start_line == 4
    )

    assert decorator is not None and default is not None
    assert decorator_reference.symbol_id == decorator.symbol_id
    assert default_reference.symbol_id == default.symbol_id


def test_class_outer_expressions_resolve_before_class_namespace(tmp_path: Path):
    path = tmp_path / "class_scope.py"
    source = (
        "Base = object\n"
        "decorator = lambda value: value\n\n"
        "@decorator\n"
        "class Derived(Base, metaclass=Base):\n"
        "    Base = object\n"
    )
    index = SourceIndex({str(path): source}, (tmp_path,))
    outer_base = index.symbol_at(path.as_uri(), 0, 1)
    class_base = index.symbol_at(path.as_uri(), 5, 5)
    decorator_reference = next(
        ref for ref in index.references if ref.location.start_line == 3
    )
    base_references = [
        ref
        for ref in index.references
        if ref.name == "Base" and ref.location.start_line == 4
    ]

    assert outer_base is not None and class_base is not None
    assert decorator_reference.symbol_id == index.symbol_at(path.as_uri(), 1, 1).symbol_id
    assert {reference.symbol_id for reference in base_references} == {outer_base.symbol_id}
    assert class_base.symbol_id != outer_base.symbol_id


def test_lambda_parameters_use_anonymous_nested_scope(tmp_path: Path):
    path = tmp_path / "lambda_scope.py"
    source = (
        "def function(value):\n"
        "    transform = lambda value: value + 1\n"
        "    return value\n"
    )
    index = SourceIndex({str(path): source}, (tmp_path,))
    outer_parameter = index.symbol_at(path.as_uri(), 0, 13)
    lambda_parameter = index.symbol_at(path.as_uri(), 1, 23)
    lambda_reference = next(
        ref for ref in index.references if ref.name == "value" and ref.location.start_line == 1
    )
    outer_reference = next(
        ref for ref in index.references if ref.name == "value" and ref.location.start_line == 2
    )

    assert outer_parameter is not None and lambda_parameter is not None
    assert lambda_parameter.symbol_id != outer_parameter.symbol_id
    assert "<lambda@" in lambda_parameter.qualified_name
    assert lambda_reference.symbol_id == lambda_parameter.symbol_id
    assert outer_reference.symbol_id == outer_parameter.symbol_id


def test_comprehensions_use_implicit_scopes_without_leaking_targets(tmp_path: Path):
    path = tmp_path / "comprehension_scope.py"
    source = (
        "x = 'outer'\n\n"
        "def function(items):\n"
        "    result = [x for x in items if x]\n"
        "    nested = [(x, y) for x in items for y in x]\n"
        "    return x\n"
    )
    index = SourceIndex({str(path): source}, (tmp_path,))
    outer_x = index.symbol_at(path.as_uri(), 0, 1)
    first_target = index.symbol_at(path.as_uri(), 3, 20)
    nested_x_target = index.symbol_at(path.as_uri(), 4, 26)
    nested_y_target = index.symbol_at(path.as_uri(), 4, 41)
    return_reference = next(
        ref for ref in index.references if ref.name == "x" and ref.location.start_line == 5
    )
    nested_x_references = [
        ref for ref in index.references if ref.name == "x" and ref.location.start_line == 4
    ]

    assert all(
        item is not None
        for item in (outer_x, first_target, nested_x_target, nested_y_target)
    )
    assert "<comprehension@" in first_target.qualified_name
    assert return_reference.symbol_id == outer_x.symbol_id
    assert all(ref.symbol_id == nested_x_target.symbol_id for ref in nested_x_references)
    assert nested_y_target.symbol_id != nested_x_target.symbol_id


def test_module_bindings_are_predeclared_for_forward_references(tmp_path: Path):
    path = tmp_path / "forward.py"
    source = (
        "def first():\n"
        "    return second()\n\n"
        "def set_later():\n"
        "    global later\n"
        "    return later\n\n"
        "def second():\n"
        "    pass\n\n"
        "later = 1\n"
    )
    index = SourceIndex({str(path): source}, (tmp_path,))
    second = index.symbol_by_name("forward.second")
    later = index.symbol_at(path.as_uri(), 10, 1)
    call_reference = next(
        ref for ref in index.references if ref.name == "second" and ref.location.start_line == 1
    )
    global_reference = next(
        ref for ref in index.references if ref.name == "later" and ref.location.start_line == 5
    )

    assert second is not None and later is not None
    assert call_reference.symbol_id == second.symbol_id
    assert global_reference.symbol_id == later.symbol_id


def test_class_body_bindings_are_visible_until_a_lexical_boundary(tmp_path: Path):
    path = tmp_path / "class_body.py"
    source = (
        "def outer():\n"
        "    class C:\n"
        "        x = 1\n"
        "        y = x\n"
        "        method = lambda: x\n"
    )
    index = SourceIndex({str(path): source}, (tmp_path,))
    class_x = index.symbol_at(path.as_uri(), 2, 9)
    body_reference = next(
        ref for ref in index.references if ref.name == "x" and ref.location.start_line == 3
    )
    lambda_reference = next(
        ref for ref in index.references if ref.name == "x" and ref.location.start_line == 4
    )

    assert class_x is not None
    assert body_reference.symbol_id == class_x.symbol_id
    assert lambda_reference.symbol_id is None


def test_global_in_class_body_resolves_module_binding(tmp_path: Path):
    path = tmp_path / "class_global.py"
    source = (
        "x = 0\n\n"
        "def outer():\n"
        "    x = 1\n\n"
        "    class C:\n"
        "        global x\n"
        "        y = x\n"
    )
    index = SourceIndex({str(path): source}, (tmp_path,))
    module_x = index.symbol_at(path.as_uri(), 0, 1)
    reference = next(
        ref for ref in index.references if ref.name == "x" and ref.location.start_line == 7
    )

    assert module_x is not None
    assert reference.symbol_id == module_x.symbol_id


def test_named_expressions_follow_lambda_and_comprehension_scope_rules(tmp_path: Path):
    path = tmp_path / "named_expr.py"
    source = (
        "x = 0\n\n"
        "def lambda_scope():\n"
        "    callback = lambda: (x, (x := 1))\n\n"
        "def comprehension_scope(items):\n"
        "    result = [y := item for item in items]\n"
        "    return y\n"
    )
    index = SourceIndex({str(path): source}, (tmp_path,))
    lambda_x = next(
        symbol
        for symbol in index.symbols
        if symbol.name == "x" and "<lambda@" in symbol.qualified_name
    )
    lambda_reference = next(
        ref for ref in index.references if ref.name == "x" and ref.location.start_line == 3
    )
    comprehension_y = next(
        symbol
        for symbol in index.symbols
        if symbol.name == "y" and symbol.qualified_name == "named_expr.comprehension_scope.y"
    )
    returned_y = next(
        ref for ref in index.references if ref.name == "y" and ref.location.start_line == 7
    )

    assert lambda_reference.symbol_id == lambda_x.symbol_id
    assert returned_y.symbol_id == comprehension_y.symbol_id


def test_exception_and_pattern_captures_create_lexical_bindings(tmp_path: Path):
    path = tmp_path / "captures.py"
    source = (
        "def function(obj):\n"
        "    try:\n"
        "        raise ValueError()\n"
        "    except ValueError as error:\n"
        "        seen = error\n"
        "    match obj:\n"
        "        case {\"item\": item, **rest}:\n"
        "            return item, rest\n"
    )
    index = SourceIndex({str(path): source}, (tmp_path,))
    error = index.symbol_at(path.as_uri(), 3, 25)
    item = index.symbol_at(path.as_uri(), 6, 23)
    rest = index.symbol_at(path.as_uri(), 6, 32)
    references = {
        (reference.name, reference.location.start_line): reference.symbol_id
        for reference in index.references
        if reference.name in {"error", "item", "rest"}
    }

    assert error is not None and item is not None and rest is not None
    assert references[("error", 4)] == error.symbol_id
    assert references[("item", 7)] == item.symbol_id
    assert references[("rest", 7)] == rest.symbol_id


def test_receiver_shortcut_requires_the_actual_method_receiver(tmp_path: Path):
    path = tmp_path / "receiver.py"
    source = (
        "class A:\n"
        "    x = 1\n\n"
        "    def method(self):\n"
        "        def inner(self):\n"
        "            return self.x\n"
        "        def capture():\n"
        "            return self.x\n"
    )
    index = SourceIndex({str(path): source}, (tmp_path,))
    class_x = index.symbol_at(path.as_uri(), 1, 5)
    inner_reference = next(
        ref for ref in index.references if ref.name == "x" and ref.location.start_line == 5
    )
    capture_reference = next(
        ref for ref in index.references if ref.name == "x" and ref.location.start_line == 7
    )

    assert class_x is not None
    assert inner_reference.symbol_id is None
    assert capture_reference.symbol_id == class_x.symbol_id
