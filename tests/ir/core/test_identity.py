import pytest

from pyflow.application.program import Program
from pyflow.ir.core import (
    BlockId,
    ContextSignature,
    EdgeId,
    FactResult,
    AnalysisFacts,
    IRRevision,
    Precision,
    SourceAnchor,
    SymbolKind,
    StaleAnalysisFacts,
    verify_catalog,
)
from pyflow.language.python import ast


def _build_catalog():
    program = Program()
    catalog = program.ir
    code = object()
    procedure = catalog.register_code(
        code,
        module="example",
        qualname="main",
        anchor=SourceAnchor("example.py", 3, 0),
    )
    box = catalog.symbols.intern(
        procedure.root_scope, "box", SymbolKind.LOCAL
    )
    same_box = catalog.symbols.intern(
        procedure.root_scope, "box", SymbolKind.LOCAL
    )
    temp = catalog.symbols.fresh(
        procedure.root_scope, "tmp", SymbolKind.TEMPORARY
    )
    operation = object()
    operation_id = catalog.register_node(procedure.code_id, operation)
    box_0 = catalog.values.define(box.id, operation_id)
    box_1 = catalog.values.define(box.id, operation_id)
    return catalog, procedure, box, same_box, temp, box_0, box_1


def test_symbol_and_value_ids_are_deterministic_and_semantic():
    left = _build_catalog()
    right = _build_catalog()

    assert left[1:] == right[1:]
    assert left[2] is left[3]
    assert left[2].id != left[4].id
    assert left[5].id.version == 0
    assert left[6].id.version == 1
    verify_catalog(left[0])


def test_fact_store_publishes_and_invalidates_complete_snapshots():
    store = Program().ir.facts
    key = ("call", 1)
    revision = store.publish(
        "analysis.call_targets",
        "ipa",
        {key: FactResult.exact({"callee"}, "ipa")},
    )

    result = store.query("analysis.call_targets", key)
    assert result.values == frozenset({"callee"})
    assert result.precision is Precision.EXACT
    assert store.snapshot_revision("analysis.call_targets") == revision

    store.invalidate({"analysis.call_targets"})
    assert store.query("analysis.call_targets", key).precision is Precision.UNKNOWN


def test_fact_store_joins_producers_but_supports_designated_queries():
    store = Program().ir.facts
    store.publish(
        "targets", "ipa", {"call": FactResult.exact({"left"}, "ipa")}
    )
    store.publish(
        "targets", "cpa", {"call": FactResult.exact({"right"}, "cpa")}
    )

    assert store.query("targets", "call").values == frozenset({"left", "right"})
    assert store.query_producer("targets", "ipa", "call").values == frozenset(
        {"left"}
    )


def test_fact_store_distinguishes_empty_conservative_and_missing():
    catalog = Program().ir
    store = catalog.facts
    store.publish(
        "effects",
        "analysis",
        {
            "empty": FactResult.exact((), "analysis"),
            "partial": FactResult.conservative(
                {"unknown-storage"}, "analysis", ("dynamic access",)
            ),
        },
    )

    assert store.query("effects", "empty") == FactResult.exact((), "analysis")
    assert store.query("effects", "partial").precision is Precision.CONSERVATIVE
    assert store.query("effects", "missing").precision is Precision.UNKNOWN


def test_analysis_fact_views_reject_newer_ir_revisions():
    catalog = Program().ir
    view = AnalysisFacts(catalog)

    catalog.commit_revision()

    with pytest.raises(StaleAnalysisFacts):
        view.context_ids(object())


def test_local_repr_is_readable_and_never_exposes_process_addresses():
    local = ast.Local("box")

    assert repr(local) == "Local(%box)"
    assert "/" not in repr(local)


def test_ir_revision_advances_and_retags_only_preserved_facts():
    catalog = Program().ir
    catalog.facts.publish("kept", "test", {"key": FactResult.exact((), "test")})
    catalog.facts.publish("dropped", "test", {"key": FactResult.exact((), "test")})

    revision = catalog.commit_revision(preserved_capabilities={"kept"})

    assert revision == IRRevision(1)
    assert catalog.facts.has("kept")
    assert not catalog.facts.has("dropped")
    assert catalog.facts.snapshot_ir_revision("kept") == revision


def test_cfg_block_and_edge_ids_are_typed_and_stable():
    catalog, procedure, *_rest = _build_catalog()
    first = object()
    second = object()
    first_id = catalog.register_block(procedure.code_id, first)
    second_id = catalog.register_block(procedure.code_id, second)
    edge_id = catalog.register_edge(first_id, "normal", second_id)

    assert first_id == BlockId(procedure.code_id, 0)
    assert second_id == BlockId(procedure.code_id, 1)
    assert edge_id == EdgeId(first_id, "normal", 0)


def test_context_ids_are_derived_from_canonical_signatures():
    catalog, procedure, *_rest = _build_catalog()
    first = object()
    second = object()
    signature = ContextSignature('["context","example"]')

    first_id = catalog.register_context(procedure.code_id, first, signature)
    second_id = catalog.register_context(procedure.code_id, second, signature)

    assert first_id == second_id
    assert catalog.context_id(procedure.code_id, first) == first_id
    assert catalog.context_id(procedure.code_id, second) == second_id
    assert "ctx." in str(first_id)


def test_structurally_equal_references_keep_distinct_node_occurrences():
    catalog = Program().ir
    code = object()
    procedure = catalog.register_code(code, module="example", qualname="cells")
    first = ast.Cell("captured")
    second = ast.Cell("captured")

    first_node = catalog.register_node(procedure.code_id, first)
    second_node = catalog.register_node(procedure.code_id, second)
    symbol = catalog.symbols.intern(
        procedure.root_scope, "captured", SymbolKind.CELL
    )
    catalog.bind_symbol(first, symbol.id)
    catalog.bind_symbol(second, symbol.id)

    assert first == second
    assert first_node != second_node
    assert catalog.node_id(first, code) == first_node
    assert catalog.node_id(second, code) == second_node
    assert catalog.symbol_id(first, code) == catalog.symbol_id(second, code)
