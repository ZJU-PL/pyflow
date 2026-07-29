"""Deterministically index existing Python IR into the shared IR catalog."""

from __future__ import annotations

import os
from collections.abc import Iterable
from typing import TypeVar

from pyflow.language.asttools.origin import SourceOrigin as LegacySourceOrigin
from pyflow.language.python import ast

from .catalog import IRCatalog
from .ids import SourceAnchor, SymbolId
from .source import SourceOrigin, SourceSpan, SyntheticOrigin
from .symbols import SymbolKind


def _iter_children(node: object):
    if isinstance(node, (list, tuple)):
        yield from node
        return
    children = getattr(node, "children", None)
    if children is not None:
        yield from children()


def _flatten(items: Iterable[object]):
    for item in items:
        if isinstance(item, (list, tuple)):
            yield from _flatten(item)
        elif item is not None:
            yield item


T = TypeVar("T")


def _identity_unique(items: Iterable[T]) -> list[T]:
    """Return objects once by identity, independent of structural equality."""
    result: list[T] = []
    seen: set[int] = set()
    for item in items:
        marker = id(item)
        if marker in seen:
            continue
        seen.add(marker)
        result.append(item)
    return result


def _origins(node: object) -> tuple[object, ...]:
    origin = getattr(getattr(node, "annotation", None), "origin", ()) or ()
    if isinstance(origin, (tuple, list)):
        return tuple(origin)
    return (origin,)


def _source_origin(node: object, inherited: object | None = None):
    origins = _origins(node)
    for origin in origins:
        if isinstance(origin, (LegacySourceOrigin, SourceOrigin)):
            return origin
        if all(hasattr(origin, field) for field in ("filename", "lineno", "col")):
            return origin
    for origin in origins:
        if isinstance(origin, str) and origin.startswith("source(") and origin.endswith(")"):
            payload = origin[len("source(") : -1]
            filename, separator, line = payload.rpartition(":")
            if separator and filename:
                try:
                    parsed_line = int(line)
                except ValueError:
                    parsed_line = 0
                return SourceOrigin(SourceSpan(filename, parsed_line, 0))
    if inherited is not None:
        return inherited
    for origin in origins:
        if isinstance(origin, str):
            return SyntheticOrigin(origin)
    return inherited


def _source_anchor(code: ast.Code, fallback_filename: str | None) -> SourceAnchor:
    for origin in _origins(code):
        filename = getattr(origin, "filename", None)
        line = getattr(origin, "lineno", None)
        column = getattr(origin, "col", None)
        if filename:
            return SourceAnchor(str(filename), int(line or 0), int(column or 0))
        if isinstance(origin, str) and origin.startswith("source(") and origin.endswith(")"):
            payload = origin[len("source(") : -1]
            filename, separator, line = payload.rpartition(":")
            if separator and filename:
                try:
                    parsed_line = int(line)
                except ValueError:
                    parsed_line = 0
                return SourceAnchor(filename, parsed_line, 0)
    return SourceAnchor(fallback_filename or "", 0, 0)


def _symbol_kind(name: str) -> SymbolKind:
    if name.startswith(("__pyflow_tmp_", "$tmp_", "%tmp")):
        return SymbolKind.TEMPORARY
    return SymbolKind.LOCAL


def _procedure_metadata(code: ast.Code):
    tags = {str(origin) for origin in _origins(code)}
    construct_kind = next(
        (
            tag.split("(", 1)[0]
            for tag in sorted(tags)
            if tag.startswith("synthetic_module(")
        ),
        None,
    )
    return {
        "is_async": "converted_async_function" in tags,
        "is_generator": any(
            tag in {"converted_generator", "converted_genexpr"} for tag in tags
        ),
        "construct_kind": construct_kind,
    }


def index_code(
    catalog: IRCatalog,
    code: ast.Code,
    *,
    module: str,
    qualname: str | None = None,
    filename: str | None = None,
    seen_codes: set[int] | None = None,
) -> None:
    """Register one code object, all local occurrences, and nested code."""
    if seen_codes is None:
        seen_codes = set()
    code_marker = id(code)
    if code_marker in seen_codes:
        return
    seen_codes.add(code_marker)

    procedure = catalog.register_code(
        code,
        module=module,
        qualname=qualname or code.codeName(),
        anchor=_source_anchor(code, filename),
        **_procedure_metadata(code),
    )
    code.ir_catalog = catalog
    scope = procedure.root_scope

    parameter_ids: dict[str, SymbolId] = {}
    parameters = code.codeparameters
    declared_parameters = [
        parameters.selfparam,
        *parameters.posonlyparams,
        *parameters.params,
        parameters.vparam,
        parameters.kparam,
    ]
    for local in declared_parameters:
        if not isinstance(local, ast.Local) or local.name is None:
            continue
        symbol = catalog.symbols.intern(
            scope,
            local.name,
            SymbolKind.PARAMETER,
            declaration_origin=_source_origin(local),
        )
        parameter_ids[local.name] = symbol.id
        catalog.bind_symbol(local, symbol.id)
        catalog.source_map.set_declaration(symbol.id, symbol.declaration_origin)

    return_ids: dict[str, SymbolId] = {}
    for local in parameters.returnparams:
        if not isinstance(local, ast.Local) or local.name is None:
            continue
        symbol = catalog.symbols.intern(scope, local.name, SymbolKind.RETURN)
        return_ids[local.name] = symbol.id
        catalog.bind_symbol(local, symbol.id)

    def bind_local(local: ast.Local, origin: object | None) -> None:
        if catalog.has_symbol(local, code):
            return
        name = local.name
        if name is None:
            ordinal = len(catalog.symbols)
            symbol = catalog.symbols.fresh(
                scope,
                f"tmp{ordinal}",
                SymbolKind.TEMPORARY,
                declaration_origin=origin,
            )
        elif name in parameter_ids:
            symbol = catalog.symbols[parameter_ids[name]]
        elif name in return_ids:
            symbol = catalog.symbols[return_ids[name]]
        else:
            symbol = catalog.symbols.intern(
                scope,
                name,
                _symbol_kind(name),
                declaration_origin=origin,
            )
        catalog.bind_symbol(local, symbol.id)
        if catalog.source_map.declaration(symbol.id) is None:
            catalog.source_map.set_declaration(symbol.id, origin)

    seen_nodes: set[int] = set()

    def visit(node: object, inherited_origin: object | None = None) -> None:
        if node is None or isinstance(node, ast.leafTypes):
            return
        if isinstance(node, (list, tuple)):
            for item in node:
                visit(item, inherited_origin)
            return
        if not isinstance(node, ast.PythonASTNode):
            return
        node_marker = id(node)
        if node_marker in seen_nodes:
            return
        seen_nodes.add(node_marker)

        origin = _source_origin(node, inherited_origin)
        if isinstance(node, ast.Code) and node is not code:
            nested_name = node.codeName()
            nested_qualname = (
                nested_name
                if "." in nested_name
                else f"{qualname or code.codeName()}.<locals>.{nested_name}"
            )
            index_code(
                catalog,
                node,
                module=module,
                qualname=nested_qualname,
                filename=filename,
                seen_codes=seen_codes,
            )
            return
        catalog.register_node(procedure.code_id, node, origin=origin)
        if isinstance(node, ast.Local):
            bind_local(node, origin)
            return
        if isinstance(node, ast.Cell):
            symbol = catalog.symbols.intern(
                scope,
                node.name,
                SymbolKind.CELL,
                declaration_origin=origin,
            )
            catalog.bind_symbol(node, symbol.id)
            if catalog.source_map.declaration(symbol.id) is None:
                catalog.source_map.set_declaration(symbol.id, origin)
            return
        for child in _flatten(_iter_children(node)):
            visit(child, origin)

    visit(code)


def index_program(
    program,
    *,
    module: str = "__main__",
    filename: str | None = None,
) -> IRCatalog:
    """Index every live procedure in deterministic source/name order."""
    catalog = getattr(program, "ir", None)
    if catalog is None:
        catalog = IRCatalog()
        program.ir = catalog
    seen_codes: set[int] = set()
    candidate_codes = list(getattr(program, "liveCode", ()))
    candidate_codes.extend(
        code
        for entry_point in getattr(program, "entryPoints", ())
        for code in (getattr(entry_point, "code", None),)
        if isinstance(code, ast.Code)
    )
    interface = getattr(program, "interface", None)
    if interface is not None:
        candidate_codes.extend(
            code
            for entry_point in getattr(interface, "entryPoint", ())
            for code in (getattr(entry_point, "code", None),)
            if isinstance(code, ast.Code)
        )
    live_code = sorted(
        _identity_unique(candidate_codes),
        key=lambda code: (
            _source_anchor(code, filename),
            code.codeName(),
        ),
    )
    for code in live_code:
        code_module = module
        anchor = _source_anchor(code, filename)
        if anchor.filename and module == "__main__":
            stem = os.path.splitext(os.path.basename(anchor.filename))[0]
            if stem and stem != "__init__":
                code_module = stem
        index_code(
            catalog,
            code,
            module=code_module,
            qualname=code.codeName(),
            filename=filename,
            seen_codes=seen_codes,
        )
    return catalog


def rebuild_program_ir(
    program,
    *,
    module: str = "__main__",
    filename: str | None = None,
    provenance_seeds=(),
) -> IRCatalog:
    """Replace the catalog after a structural program transformation."""
    previous = getattr(program, "ir", None)
    retained = []
    if previous is not None:
        for node_id, node in previous.nodes():
            retained.append(
                (
                    previous.code(node_id.code),
                    node,
                    previous.source_map.origin(node_id),
                    previous.source_map.provenance(node_id),
                )
            )
    revision = previous.revision.next() if previous is not None else None
    program.ir = IRCatalog(revision) if revision is not None else IRCatalog()
    catalog = index_program(program, module=module, filename=filename)
    from .build_semantics import build_semantics
    from .source import TransformationFrame

    for code, node, origin, provenance in retained:
        if not catalog.has_procedure(code) or not catalog.has_node(node, code):
            continue
        node_id = catalog.node_id(node, code)
        catalog.source_map.set_origin(node_id, origin)
        catalog.source_map.set_provenance(node_id, provenance)

    for seed in provenance_seeds:
        if not catalog.has_procedure(seed.code) or not catalog.has_node(
            seed.node, seed.code
        ):
            continue
        node_id = catalog.node_id(seed.node, seed.code)
        catalog.source_map.set_origin(node_id, seed.origin)
        catalog.source_map.append_provenance(
            node_id,
            TransformationFrame(
                seed.transform,
                inputs=seed.inputs,
                source=seed.origin,
                detail=seed.detail,
            ),
        )
        if isinstance(seed.node, (ast.Local, ast.Cell)) and catalog.has_symbol(
            seed.node, seed.code
        ):
            catalog.source_map.set_declaration(
                catalog.symbol_id(seed.node, seed.code), seed.origin
            )

    build_semantics(catalog)
    return catalog


def ensure_code_indexed(code: ast.Code) -> IRCatalog:
    """Return the mandatory catalog for a standalone code object."""
    catalog = getattr(code, "ir_catalog", None)
    if isinstance(catalog, IRCatalog):
        return catalog
    catalog = IRCatalog()
    index_code(
        catalog,
        code,
        module="__standalone__",
        qualname=code.codeName(),
    )
    from .build_semantics import build_semantics

    build_semantics(catalog)
    return catalog


def ensure_codes_indexed(codes: Iterable[ast.Code]) -> IRCatalog:
    """Return one catalog spanning a related set of procedures.

    Program-extracted procedures already share their program catalog.  Ad-hoc
    CFG clients often construct each ``Code`` independently; those are indexed
    together here so equal-looking IDs from separate catalogs can never collide.
    """
    ordered_codes = tuple(_identity_unique(codes))
    if not ordered_codes:
        return IRCatalog()

    catalogs: set[IRCatalog] = {
        catalog
        for code in ordered_codes
        for catalog in (getattr(code, "ir_catalog", None),)
        if isinstance(catalog, IRCatalog)
    }
    if len(catalogs) == 1:
        catalog = next(iter(catalogs))
        try:
            for code in ordered_codes:
                catalog.procedure(code)
        except KeyError:
            pass
        else:
            # Analyses and normalization passes may have reconstructed AST
            # operations since the catalog was first created.  Refresh node
            # and symbol bindings before returning the shared catalog.
            seen_codes: set[int] = set()
            for code in ordered_codes:
                procedure = catalog.procedure(code)
                index_code(
                    catalog,
                    code,
                    module=procedure.code_id.module,
                    qualname=procedure.code_id.qualname,
                    filename=procedure.code_id.anchor.filename or None,
                    seen_codes=seen_codes,
                )
            from .build_semantics import build_semantics

            build_semantics(catalog)
            return catalog

    catalog = IRCatalog()
    seen_codes = set()
    for code in ordered_codes:
        index_code(
            catalog,
            code,
            module="__standalone__",
            qualname=code.codeName(),
            seen_codes=seen_codes,
        )
    from .build_semantics import build_semantics

    build_semantics(catalog)
    return catalog


def index_cfg(catalog: IRCatalog, cfg) -> None:
    """Index AST operations introduced or cloned by CFG transformations."""
    from pyflow.ir.cfg import graph as cfg_graph

    code = cfg.code
    procedure = catalog.procedure(code)
    scope = procedure.root_scope

    def bind_reference(reference, origin):
        if catalog.has_symbol(reference, code):
            return
        name = getattr(reference, "name", None)
        kind = SymbolKind.CELL if isinstance(reference, ast.Cell) else _symbol_kind(name or "")
        symbol = None
        if name:
            symbol = catalog.symbols.find(
                scope,
                name,
                (
                    SymbolKind.PARAMETER,
                    SymbolKind.LOCAL,
                    SymbolKind.RETURN,
                    SymbolKind.TEMPORARY,
                    SymbolKind.CELL,
                    SymbolKind.EXCEPTION,
                    SymbolKind.PATTERN,
                ),
            )
        if symbol is None:
            if name:
                symbol = catalog.symbols.intern(
                    scope,
                    name,
                    kind,
                    declaration_origin=origin,
                )
            else:
                symbol = catalog.symbols.fresh(
                    scope,
                    f"tmp{len(catalog.symbols)}",
                    SymbolKind.TEMPORARY,
                    declaration_origin=origin,
                )
        catalog.bind_symbol(reference, symbol.id)

    seen_ast: set[int] = set()

    def visit_ast(node, inherited_origin=None):
        if node is None or isinstance(node, ast.leafTypes):
            return
        if isinstance(node, (list, tuple)):
            for item in node:
                visit_ast(item, inherited_origin)
            return
        if not isinstance(node, ast.PythonASTNode) or id(node) in seen_ast:
            return
        seen_ast.add(id(node))
        if isinstance(node, ast.Code) and node is not code:
            return
        origin = _source_origin(node, inherited_origin)
        catalog.register_node(procedure.code_id, node, origin=origin)
        if isinstance(node, (ast.Local, ast.Cell)):
            bind_reference(node, origin)
            return
        for child in _flatten(_iter_children(node)):
            visit_ast(child, origin)

    visited_blocks = set()
    terminals = (
        cfg.entryTerminal,
        cfg.normalTerminal,
        cfg.failTerminal,
        cfg.errorTerminal,
    )
    pending = [cfg.entryTerminal]
    ordered_blocks = []
    while pending:
        block = pending.pop(0)
        if block in visited_blocks:
            continue
        visited_blocks.add(block)
        ordered_blocks.append(block)
        if isinstance(block, cfg_graph.Suite):
            visit_ast(block.ops)
        elif isinstance(block, cfg_graph.Switch):
            visit_ast(block.condition)
        elif isinstance(block, cfg_graph.TypeSwitch):
            visit_ast(block.original)
        elif isinstance(block, cfg_graph.ForIter):
            visit_ast(block.iterator)
            visit_ast(block.index)
        elif isinstance(block, cfg_graph.Merge):
            visit_ast(block.phi)
        pending.extend(
            target for _label, target in sorted(
                block.next.items(), key=lambda item: str(item[0])
            )
        )

    for terminal in terminals:
        if terminal not in visited_blocks:
            ordered_blocks.append(terminal)
    edge_specs = []
    for block in ordered_blocks:
        occurrences: dict[str, int] = {}
        for label, target in sorted(block.next.items(), key=lambda item: str(item[0])):
            label_key = str(label)
            occurrence = occurrences.get(label_key, 0)
            occurrences[label_key] = occurrence + 1
            edge_specs.append((block, label, target, occurrence))
    catalog.synchronize_cfg(
        procedure.code_id,
        tuple(ordered_blocks),
        tuple(edge_specs),
    )

    from .build_semantics import build_semantics

    build_semantics(catalog)
