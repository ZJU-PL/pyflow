"""Stable type-fact bridge and IRCatalog publication for downstream analyses.

This module translates :mod:`pyflow.analysis.typeinfo` results into compact,
immutable :class:`~pyflow.ir.core.PublishedTypeFact` records consumed by
CallGraph, IFDS, and Alias analysis without coupling those engines to
``typeinfo`` internals.
"""

from __future__ import annotations

import ast as py_stdlib_ast
import os
from collections import defaultdict
from pathlib import Path
from typing import Mapping

from pyflow.ir.core import (
    Capabilities,
    FactResult,
    PublishedProcedureTypes,
    PublishedTypeFact,
)
from pyflow.language.modules.project_resolution import (
    ProjectContext,
    default_import_root,
    module_name_for_root,
)
from pyflow.language.python import ast as py_ast

from .core.typesystem import (
    AnyType,
    CallableType,
    Instance,
    LiteralType,
    NeverType,
    NoneType,
    ProperType,
    TupleType,
    TypeType,
    TypeVarType,
    UnionType,
    Unsupported,
)
from .inference.domain import AbstractTypeValue
from .inference.models import FunctionSummary, ModuleInferenceResult, SourceSpan
from .query.service import TypeInfoService


def _collect_proper_type_parts(
    typ: ProperType,
    names: list[str],
    flags: dict[str, bool],
) -> None:
    if isinstance(typ, AnyType) or isinstance(typ, Unsupported):
        flags["gradual"] = True
        return
    if isinstance(typ, NoneType):
        flags["optional"] = True
        return
    if isinstance(typ, NeverType):
        return
    if isinstance(typ, UnionType):
        for item in typ.items:
            _collect_proper_type_parts(item, names, flags)
        return
    if isinstance(typ, LiteralType):
        names.append(typ.base.type.full_name)
        return
    if isinstance(typ, Instance):
        names.append(typ.type.full_name)
        return
    if isinstance(typ, TupleType):
        names.append("builtins.tuple")
        return
    if isinstance(typ, CallableType):
        names.append("collections.abc.Callable")
        return
    if isinstance(typ, TypeType):
        names.append("builtins.type")
        return
    if isinstance(typ, TypeVarType):
        if typ.has_constraints:
            for constraint in typ.constraints:
                _collect_proper_type_parts(constraint, names, flags)
        elif typ.has_bound and typ.bound is not None:
            _collect_proper_type_parts(typ.bound, names, flags)
        else:
            flags["gradual"] = True


def type_fact_from_proper_type(
    typ: ProperType | None,
    *,
    source: str = "typeinfo",
    extra_gradual: bool = False,
) -> PublishedTypeFact | None:
    """Convert a :class:`ProperType` into a canonical :class:`PublishedTypeFact`."""
    if typ is None or isinstance(typ, NeverType):
        return None
    names: list[str] = []
    flags = {"optional": False, "gradual": bool(extra_gradual)}
    _collect_proper_type_parts(typ, names, flags)
    unique_names = tuple(dict.fromkeys(names))
    if not unique_names and not flags["optional"] and not flags["gradual"]:
        return None
    return PublishedTypeFact(
        type_names=unique_names,
        display=str(typ),
        is_optional=flags["optional"],
        is_gradual=flags["gradual"],
        source=source,
    )


def type_fact_from_abstract_value(
    value: AbstractTypeValue | None,
    *,
    source: str = "typeinfo",
) -> PublishedTypeFact | None:
    """Convert an inference :class:`AbstractTypeValue` into a :class:`PublishedTypeFact`."""
    if value is None:
        return None
    runtime_type = value.runtime_type()
    if runtime_type is None:
        return None
    return type_fact_from_proper_type(
        runtime_type,
        source=source,
        extra_gradual=value.has_unknown_alternatives,
    )


class TypeFactBridge:
    """Lazy, cached, failure-isolated bridge from :class:`TypeInfoService` to analyses.

    Constructing the bridge is cheap; the underlying :class:`TypeInfoService`
    is initialized on the first query so analyses pay zero startup cost when
    type-fact fallbacks are never needed.
    """

    def __init__(
        self,
        *,
        service: TypeInfoService | None = None,
        project_context: ProjectContext | None = None,
        project_root: str | Path | None = None,
        source_files: Mapping[str, str] | None = None,
        module_sources: Mapping[str, tuple[str, str | None]] | None = None,
        enable_static_inference: bool = True,
    ) -> None:
        self._service = service
        self._project_context = project_context
        self._project_root = Path(project_root) if project_root is not None else None
        self._source_files = dict(source_files or {})
        self._module_sources = dict(module_sources or {})
        self._enable_static_inference = enable_static_inference
        self._failed_modules: set[str] = set()
        self._annotation_cache: dict[tuple[str, str], PublishedTypeFact | None] = {}
        self._return_cache: dict[tuple[str, str], PublishedTypeFact | None] = {}
        self._member_cache: dict[tuple[str, str], PublishedTypeFact | None] = {}
        self._symbol_cache: dict[tuple[str, str], PublishedTypeFact | None] = {}

    @property
    def service(self) -> TypeInfoService:
        """Lazily initialize and return the backing :class:`TypeInfoService`."""
        if self._service is None:
            context = self._project_context or ProjectContext(
                self._project_root,
                source_files=self._source_files,
            )
            self._service = TypeInfoService(
                context,
                enable_static_inference=self._enable_static_inference,
            )
        return self._service

    def register_module_source(
        self, module_name: str, source: str, path: str | None = None
    ) -> None:
        """Register an in-memory source string for *module_name*."""
        self._module_sources[module_name] = (source, path)
        if path is not None:
            self._source_files[path] = source

    def ensure_module(
        self,
        module_name: str,
        *,
        source: str | None = None,
        path: str | None = None,
    ) -> bool:
        """Collect *module_name* if not yet collected, isolating any failures."""
        if not module_name or module_name in self._failed_modules:
            return False
        service = self.service
        if module_name in service._collected_modules:
            return True
        if source is None and module_name in self._module_sources:
            source, registered_path = self._module_sources[module_name]
            path = path or registered_path
        try:
            service.collect_module(module_name, source=source, path=path)
            return True
        except Exception:
            self._failed_modules.add(module_name)
            return False

    def resolve_type_expression(
        self,
        module_name: str,
        annotation: str,
    ) -> PublishedTypeFact | None:
        """Resolve an annotation expression in *module_name*'s import/alias scope."""
        key = (module_name, annotation)
        if key in self._annotation_cache:
            return self._annotation_cache[key]
        result: PublishedTypeFact | None = None
        if self.ensure_module(module_name):
            try:
                service = self.service
                imports = service._module_imports.get(module_name, {})
                resolved = service._resolve_annotation(
                    annotation,
                    module_name=module_name,
                    imports=imports,
                )
                # Type annotations referencing a local TypeAlias (e.g. ``Handler = A | B``)
                # may resolve to a module fact when ``_resolve_annotation`` sees a bare name.
                if resolved is None and annotation.isidentifier():
                    fact = service.fact_of(module_name, annotation)
                    if fact is not None:
                        resolved = fact.typ
                result = type_fact_from_proper_type(resolved, source="typeinfo.annotation")
            except Exception:
                result = None
        self._annotation_cache[key] = result
        return result

    def symbol_type(self, module_name: str, name: str) -> PublishedTypeFact | None:
        """Return the published type fact for ``module_name.name``."""
        key = (module_name, name)
        if key in self._symbol_cache:
            return self._symbol_cache[key]
        result: PublishedTypeFact | None = None
        if self.ensure_module(module_name):
            try:
                fact = self.service.fact_of(module_name, name)
                if fact is not None:
                    result = type_fact_from_proper_type(fact.typ, source=f"typeinfo.{fact.source}")
            except Exception:
                result = None
        self._symbol_cache[key] = result
        return result

    def return_type(self, module_name: str, callable_name: str) -> PublishedTypeFact | None:
        """Return the inferred or declared return type of ``module_name.callable_name``."""
        key = (module_name, callable_name)
        if key in self._return_cache:
            return self._return_cache[key]
        result: PublishedTypeFact | None = None
        if self.ensure_module(module_name):
            try:
                service = self.service
                local_name = (
                    callable_name[len(module_name) + 1 :]
                    if callable_name.startswith(f"{module_name}.")
                    else callable_name
                )
                sig = service.signature_of(module_name, local_name)
                if sig is not None and sig.returns is not None:
                    result = type_fact_from_proper_type(
                        sig.returns, source=f"typeinfo.{sig.source}"
                    )
                if result is None:
                    mod_res = service.inference_result(module_name)
                    if mod_res is not None:
                        qualified = f"{module_name}.{local_name}"
                        summary = mod_res.functions.get(qualified) or mod_res.functions.get(
                            local_name
                        )
                        if summary is not None:
                            result = type_fact_from_abstract_value(
                                summary.return_value, source="typeinfo.inference"
                            )
                if result is None:
                    fact = service.fact_of(module_name, local_name)
                    if fact is not None and isinstance(fact.typ, CallableType):
                        result = type_fact_from_proper_type(
                            fact.typ.return_type, source=f"typeinfo.{fact.source}"
                        )
            except Exception:
                result = None
        self._return_cache[key] = result
        return result

    def member_type(self, class_qualname: str, attr_name: str) -> PublishedTypeFact | None:
        """Return the inferred or annotated type of attribute ``class_qualname.attr_name``."""
        key = (class_qualname, attr_name)
        if key in self._member_cache:
            return self._member_cache[key]
        result: PublishedTypeFact | None = None
        module_name, sep, _ = class_qualname.rpartition(".")
        if sep and self.ensure_module(module_name):
            try:
                service = self.service
                members = service.members_of(class_qualname)
                member_fact = members.get(attr_name)
                if member_fact is not None and member_fact.typ is not None:
                    if not isinstance(member_fact.typ, CallableType):
                        result = type_fact_from_proper_type(
                            member_fact.typ, source=f"typeinfo.{member_fact.source}"
                        )
                if result is None:
                    descriptor = service.type_system.class_descriptor(class_qualname)
                    if descriptor is not None and attr_name in descriptor.members:
                        member_typ = descriptor.members[attr_name]
                        if not isinstance(member_typ, CallableType):
                            result = type_fact_from_proper_type(
                                member_typ, source="typeinfo.member"
                            )
            except Exception:
                result = None
        self._member_cache[key] = result
        return result


def _procedure_source_file(catalog, code) -> str | None:
    try:
        origin = catalog.source_of(code, code=code)
    except KeyError:
        origin = None
    span = getattr(origin, "span", None)
    filename = getattr(span, "path", None)
    if not filename:
        try:
            filename = catalog.procedure(code).code_id.anchor.filename
        except KeyError:
            filename = None
    return os.path.realpath(filename) if filename else None


def _match_function_summary(
    procedure,
    code,
    module_name: str,
    mod_result: ModuleInferenceResult,
) -> FunctionSummary | None:
    qualname = procedure.code_id.qualname
    clean_parts = [
        part for part in qualname.split(".") if part and part not in {"<module>", "<locals>"}
    ]
    if not clean_parts:
        return None
    candidates = [
        f"{module_name}.{'.'.join(clean_parts)}",
        ".".join(clean_parts),
    ]
    if len(clean_parts) >= 2:
        candidates.append(f"{module_name}.{'.'.join(clean_parts[-2:])}")
    short = code.codeName()
    if short:
        candidates.append(f"{module_name}.{short}")
    for candidate in candidates:
        summary = mod_result.functions.get(candidate)
        if summary is not None:
            return summary
    if short:
        suffix = f".{short}"
        matches = [
            summary
            for name, summary in mod_result.functions.items()
            if name == short or name.endswith(suffix)
        ]
        if len(matches) == 1:
            return matches[0]
    return None


def _node_span_key(catalog, code, node) -> tuple[int, int, int, int] | None:
    try:
        origin = catalog.source_of(node, code=code)
    except KeyError:
        return None
    span = getattr(origin, "span", None)
    start_line = getattr(span, "start_line", None)
    start_col = getattr(span, "start_column", None)
    if start_line is None or start_col is None:
        return None
    end_line = getattr(span, "end_line", None)
    end_col = getattr(span, "end_column", None)
    return (
        int(start_line),
        int(start_col),
        int(end_line) if end_line is not None else -1,
        int(end_col) if end_col is not None else -1,
    )


def _index_call_expressions(
    mod_result: ModuleInferenceResult,
) -> tuple[
    dict[tuple[int, int, int, int], AbstractTypeValue],
    dict[tuple[int, int], list[tuple[SourceSpan, AbstractTypeValue]]],
]:
    exact: dict[tuple[int, int, int, int], AbstractTypeValue] = {}
    by_start: dict[tuple[int, int], list[tuple[SourceSpan, AbstractTypeValue]]] = defaultdict(list)
    for span, value in mod_result.expressions.items():
        if mod_result.expression_kinds.get(span) is not py_stdlib_ast.Call:
            continue
        key = (
            span.lineno,
            span.col_offset,
            span.end_lineno if span.end_lineno is not None else -1,
            span.end_col_offset if span.end_col_offset is not None else -1,
        )
        exact[key] = value
        by_start[(span.lineno, span.col_offset)].append((span, value))
    return exact, by_start


def _fact_result(fact: PublishedTypeFact) -> FactResult:
    if fact.is_gradual:
        return FactResult.conservative((fact,), "typeinfo")
    return FactResult.exact((fact,), "typeinfo")


def publish_typeinfo_facts(
    catalog,
    *,
    project_root: str | Path | None = None,
    source_files: Mapping[str, str] | None = None,
    service: TypeInfoService | None = None,
) -> TypeInfoService | None:
    """Publish :mod:`typeinfo` symbol, procedure, and call-return facts into *catalog*.

    Populates:
    - :attr:`Capabilities.TYPE_SYMBOL_TYPES` (``SymbolId -> PublishedTypeFact``)
    - :attr:`Capabilities.TYPE_CALL_RETURNS` (``NodeId -> PublishedTypeFact``)
    - :attr:`Capabilities.TYPE_PROCEDURE_SUMMARIES` (``CodeId -> PublishedProcedureTypes``)

    Per-module failures are isolated so partial or syntax-broken inputs never
    abort downstream CallGraph, IFDS, or Alias analyses.
    """
    if catalog is None or not hasattr(catalog, "procedures"):
        return service

    file_to_procs: dict[str, list[tuple[object, object]]] = defaultdict(list)
    for procedure in catalog.procedures():
        code = catalog.code(procedure.code_id)
        if code is None:
            continue
        filename = _procedure_source_file(catalog, code)
        if filename is None:
            continue
        file_to_procs[filename].append((procedure, code))

    if not file_to_procs:
        return service

    normalized_sources: dict[str, str] = {}
    for raw_path, text in (source_files or {}).items():
        normalized_sources[os.path.realpath(raw_path)] = text
        normalized_sources[str(raw_path)] = text

    root_path: Path | None = Path(project_root).resolve() if project_root is not None else None
    if root_path is None:
        first_file = Path(next(iter(file_to_procs)))
        root_path = default_import_root(first_file) if first_file.exists() else first_file.parent

    if service is None:
        context = ProjectContext(root_path, source_files=normalized_sources)
        service = TypeInfoService(context, enable_static_inference=True)

    file_to_module: dict[str, str] = {}
    module_results: dict[str, ModuleInferenceResult] = {}
    for filename in file_to_procs:
        path = Path(filename)
        try:
            mod_name = module_name_for_root(path, root_path)
        except ValueError:
            mod_root = default_import_root(path) if path.exists() else path.parent
            try:
                mod_name = module_name_for_root(path, mod_root)
            except ValueError:
                mod_name = path.stem
        file_to_module[filename] = mod_name
        src_text = normalized_sources.get(filename)
        try:
            service.collect_module(mod_name, source=src_text, path=filename)
            mod_res = service.inference_result(mod_name)
            if mod_res is not None:
                module_results[mod_name] = mod_res
        except Exception:
            continue

    if not module_results:
        return service

    procedure_summaries: dict[object, FactResult] = {}
    symbol_types: dict[object, FactResult] = {}
    call_returns: dict[object, FactResult] = {}
    summary_by_code_id: dict[object, tuple[str, FunctionSummary | None, ModuleInferenceResult]] = {}

    for filename, proc_pairs in file_to_procs.items():
        mod_name = file_to_module.get(filename)
        mod_res = module_results.get(mod_name or "")
        if mod_name is None or mod_res is None:
            continue
        for procedure, code in proc_pairs:
            summary = _match_function_summary(procedure, code, mod_name, mod_res)
            summary_by_code_id[procedure.code_id] = (mod_name, summary, mod_res)
            if summary is None:
                continue
            param_facts: list[tuple[str, PublishedTypeFact]] = []
            for param_name, param_val in summary.parameters.items():
                fact = type_fact_from_abstract_value(param_val, source="typeinfo.param")
                if fact is not None:
                    param_facts.append((param_name, fact))
            ret_fact = type_fact_from_abstract_value(summary.return_value, source="typeinfo.return")
            if param_facts or ret_fact is not None:
                published_proc = PublishedProcedureTypes(
                    param_types=tuple(param_facts),
                    return_type=ret_fact,
                )
                procedure_summaries[procedure.code_id] = FactResult.exact(
                    (published_proc,), "typeinfo"
                )

    call_expr_indexes = {
        mod_name: _index_call_expressions(mod_res) for mod_name, mod_res in module_results.items()
    }
    code_by_id = {
        procedure.code_id: catalog.code(procedure.code_id)
        for procedure in catalog.procedures()
        if catalog.code(procedure.code_id) is not None
    }
    call_types = (py_ast.Call, py_ast.DirectCall, py_ast.MethodCall)

    for node_id, node in catalog.nodes():
        code_id = node_id.code
        entry = summary_by_code_id.get(code_id)
        if entry is None:
            continue
        mod_name, summary, mod_res = entry
        code = code_by_id.get(code_id)
        if code is None:
            continue

        if isinstance(node, py_ast.Local) and node.name and catalog.has_symbol(node, code_id):
            symbol_id = catalog.symbol_id(node, code_id)
            if symbol_id not in symbol_types:
                fact: PublishedTypeFact | None = None
                if summary is not None:
                    param_val = summary.parameters.get(node.name)
                    if param_val is not None:
                        fact = type_fact_from_abstract_value(param_val, source="typeinfo.param")
                    if fact is None:
                        sym = mod_res.symbols.get(f"{summary.qualified_name}.{node.name}")
                        if sym is not None:
                            fact = type_fact_from_abstract_value(sym.value, source="typeinfo.local")
                else:
                    sym = mod_res.symbols.get(f"{mod_name}.{node.name}")
                    if sym is not None:
                        fact = type_fact_from_abstract_value(sym.value, source="typeinfo.module")
                    if fact is None:
                        mod_fact = service.fact_of(mod_name, node.name)
                        if mod_fact is not None:
                            fact = type_fact_from_proper_type(
                                mod_fact.typ, source=f"typeinfo.{mod_fact.source}"
                            )
                if fact is None:
                    span_key = _node_span_key(catalog, code, node)
                    if span_key is not None:
                        expr_val = mod_res.expression_value(span_key[0], span_key[1])
                        fact = type_fact_from_abstract_value(expr_val, source="typeinfo.expr")
                if fact is not None:
                    symbol_types[symbol_id] = _fact_result(fact)
        elif isinstance(node, call_types):
            ret_fact: PublishedTypeFact | None = None
            span_key = _node_span_key(catalog, code, node)
            if span_key is not None:
                exact_map, by_start = call_expr_indexes[mod_name]
                expr_val = exact_map.get(span_key)
                if expr_val is None:
                    candidates = by_start.get((span_key[0], span_key[1]), ())
                    if len(candidates) == 1:
                        expr_val = candidates[0][1]
                    elif candidates and span_key[2] >= 0:
                        for cand_span, cand_val in candidates:
                            if (
                                cand_span.end_lineno == span_key[2]
                                and cand_span.end_col_offset == span_key[3]
                            ):
                                expr_val = cand_val
                                break
                ret_fact = type_fact_from_abstract_value(expr_val, source="typeinfo.call")
            if ret_fact is None and isinstance(node, py_ast.DirectCall) and node.code is not None:
                try:
                    target_proc = catalog.procedure(node.code)
                    target_fact = procedure_summaries.get(target_proc.code_id)
                    if target_fact and target_fact.values:
                        ret_fact = next(iter(target_fact.values)).return_type
                except KeyError:
                    ret_fact = None
            if ret_fact is not None:
                call_returns[node_id] = _fact_result(ret_fact)

    catalog.facts.publish_many(
        "typeinfo",
        {
            Capabilities.TYPE_SYMBOL_TYPES: symbol_types,
            Capabilities.TYPE_CALL_RETURNS: call_returns,
            Capabilities.TYPE_PROCEDURE_SUMMARIES: procedure_summaries,
        },
    )
    return service


__all__ = [
    "TypeFactBridge",
    "publish_typeinfo_facts",
    "type_fact_from_abstract_value",
    "type_fact_from_proper_type",
]
