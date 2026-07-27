"""Minimal type-information service.

This module provides a small orchestration layer over the existing typeinfo
facilities.  It resolves public facts to the shared ``typesystem`` model while
preserving raw annotation text for diagnostics and display.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterable, Iterator, cast

from pyflow.analysis.typeinfo.resolution.annotations import (
    BuiltinTypeLookup,
    TypeLookup,
    resolve_annotation,
)
from pyflow.analysis.typeinfo.query.models import (
    ClassTypeInfo,
    FunctionTypeInfo,
    TypeFact,
)
from pyflow.language.modules.type_stubs import (
    StubClassInfo,
    StubDiagnostic,
    StubFunctionInfo,
    StubImportInfo,
    StubResolver,
)
from pyflow.analysis.typeinfo.core.typesystem import (
    ANY,
    NONE_TYPE,
    CallableType,
    Instance,
    ProperType,
    TupleType,
    TypeSystem,
)
from pyflow.analysis.typeinfo.inference.engine import StaticTypeInferenceEngine
from pyflow.analysis.typeinfo.inference.call_models import CallModelProvider
from pyflow.analysis.typeinfo.inference.models import ModuleInferenceResult
from pyflow.language.modules.project_resolution import ProjectContext


class TypeInfoService:
    """Collect and query lightweight type information for Python modules."""

    def __init__(
        self,
        project_context: ProjectContext | None = None,
        *,
        typeshed_roots: list[str | Path] | None = None,
        enable_static_inference: bool = True,
        call_model_providers: Iterable[CallModelProvider] = (),
    ) -> None:
        self.project_context = project_context or ProjectContext(None)
        self.type_system = TypeSystem()
        self.stub_resolver = StubResolver(
            self.project_context,
            typeshed_roots=typeshed_roots,
        )
        self._module_facts: dict[str, dict[str, TypeFact]] = {}
        self._functions: dict[str, dict[str, FunctionTypeInfo]] = {}
        self._classes: dict[str, ClassTypeInfo] = {}
        self._class_aliases: dict[str, str] = {}
        self._module_class_aliases: dict[str, dict[str, str]] = {}
        self._synthetic_types: dict[str, type] = {}
        self._collected_modules: set[str] = set()
        self._collecting_modules: set[str] = set()
        self.enable_static_inference = enable_static_inference
        self.call_model_providers = tuple(call_model_providers)
        self._inference_results: dict[str, ModuleInferenceResult] = {}

    def collect_module(
        self,
        module_name: str,
        *,
        source: str | None = None,
        path: str | None = None,
    ) -> None:
        """Collect source and stub facts for a module."""
        if (
            module_name in self._collected_modules
            or module_name in self._collecting_modules
        ):
            return
        self._collecting_modules.add(module_name)
        if source is None:
            source, path = self._load_module_source(module_name, path)

        try:
            if source is not None:
                self._collect_source_module(module_name, source, path)

            resolved_stub = self.stub_resolver.resolve(
                module_name,
                script_path=path,
            )
            if resolved_stub is not None:
                self._collect_stub_module(
                    module_name,
                    resolved_stub.path,
                    resolved_stub.info.functions,
                    resolved_stub.info.classes,
                    resolved_stub.info.variables,
                    resolved_stub.info.imports,
                )

            self._collected_modules.add(module_name)
        finally:
            self._collecting_modules.discard(module_name)

    def type_of(self, module_name: str, name: str) -> ProperType | None:
        """Return the best known type for ``module.name``."""
        fact = self.fact_of(module_name, name)
        return fact.typ if fact is not None else None

    def fact_of(self, module_name: str, name: str) -> TypeFact | None:
        """Return the best known type fact for ``module.name``."""
        self._ensure_collected(module_name)
        return self._module_facts.get(module_name, {}).get(name)

    def signature_of(
        self,
        module_name: str,
        name: str,
    ) -> FunctionTypeInfo | None:
        """Return function signature information for ``module.name``."""
        self._ensure_collected(module_name)
        return self._functions.get(module_name, {}).get(name)

    def members_of(self, qualified_name: str) -> dict[str, TypeFact]:
        """Return known members for a module or class."""
        if qualified_name in self._classes:
            return dict(self._classes[qualified_name].members)
        self._ensure_collected(qualified_name)
        return dict(self._module_facts.get(qualified_name, {}))

    def diagnostics(self) -> list[StubDiagnostic]:
        """Return stub-resolution diagnostics."""
        return self.stub_resolver.get_diagnostics()

    def inference_result(
        self,
        module_name: str,
    ) -> ModuleInferenceResult | None:
        """Return the standalone static-inference result for a module."""
        self._ensure_collected(module_name)
        return self._inference_results.get(module_name)

    def _ensure_collected(self, module_name: str) -> None:
        if module_name not in self._collected_modules:
            self.collect_module(module_name)

    def _load_module_source(
        self,
        module_name: str,
        path: str | None,
    ) -> tuple[str | None, str | None]:
        if path is None:
            resolution = self.project_context.find_module(module_name)
            if resolution is not None:
                path = resolution.path
        if path is None:
            return None, None
        if path in self.project_context.source_files:
            return self.project_context.source_files[path], path
        try:
            return Path(path).read_text(encoding="utf-8"), path
        except OSError:
            return None, path

    def _collect_source_module(
        self,
        module_name: str,
        source: str,
        path: str | None,
    ) -> None:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return

        facts = self._module_facts.setdefault(module_name, {})
        functions = self._functions.setdefault(module_name, {})
        local_classes: set[str] = set()
        imports = self._collect_import_aliases(module_name, tree, path)
        module_aliases = self._module_class_aliases.setdefault(module_name, {})
        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                qualified_name = f"{module_name}.{node.name}"
                self._class_aliases[node.name] = qualified_name
                module_aliases[node.name] = qualified_name

        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                local_classes.add(node.name)
                class_info = self._class_info_from_source(
                    module_name,
                    node,
                    imports,
                )
                self._classes[class_info.name] = class_info
                facts[node.name] = TypeFact(
                    name=node.name,
                    typ=class_info.typ,
                    raw_annotation=class_info.name,
                    source="annotation",
                    kind="class",
                )
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions[node.name] = self._function_info_from_source(
                    node,
                    module_name=module_name,
                    imports=imports,
                    source="annotation",
                )
                function_info = functions[node.name]
                facts[node.name] = TypeFact(
                    name=node.name,
                    typ=self._callable_type(function_info),
                    raw_annotation=node.name,
                    source="annotation",
                    kind="function",
                )

        for node in tree.body:
            if (
                isinstance(node, ast.AnnAssign)
                and isinstance(node.target, ast.Name)
            ):
                raw_annotation = _annotation_to_str(node.annotation)
                facts[node.target.id] = TypeFact(
                    name=node.target.id,
                    typ=self._resolve_annotation(
                        raw_annotation,
                        module_name=module_name,
                        imports=imports,
                    ),
                    raw_annotation=raw_annotation,
                    source="annotation",
                    kind="variable",
                )
            elif isinstance(node, ast.Assign):
                inferred = self._infer_expr_type(
                    node.value,
                    module_name,
                    local_classes,
                    imports,
                )
                if inferred is None:
                    continue
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        facts[target.id] = TypeFact(
                            name=target.id,
                            typ=inferred,
                            raw_annotation=str(inferred),
                            source="inferred",
                            kind="variable",
                        )

        if self.enable_static_inference:
            self._collect_inferred_source_facts(module_name, source, path)

    def _collect_inferred_source_facts(
        self,
        module_name: str,
        source: str,
        path: str | None,
    ) -> None:
        engine = StaticTypeInferenceEngine(
            self.project_context,
            type_system=self.type_system,
            external_symbol_resolver=self._resolve_inference_external_symbol,
            call_model_providers=self.call_model_providers,
        )
        result = engine.infer_source(module_name, source, filename=path)
        self._inference_results[module_name] = result
        facts = self._module_facts.setdefault(module_name, {})
        prefix = f"{module_name}."
        for qualified_name, symbol in result.symbols.items():
            local_name = qualified_name.removeprefix(prefix)
            if "." in local_name or symbol.typ is None:
                continue
            existing = facts.get(local_name)
            if existing is not None and existing.source in {"annotation", "stub"}:
                continue
            facts[local_name] = TypeFact(
                name=local_name,
                typ=symbol.typ,
                raw_annotation=str(symbol.typ),
                source="static_inference",
                kind=existing.kind if existing is not None else "variable",
            )

        functions = self._functions.setdefault(module_name, {})
        for qualified_name, summary in result.functions.items():
            local_name = qualified_name.removeprefix(prefix)
            if "." in local_name or local_name not in functions:
                continue
            existing_function = functions[local_name]
            params = dict(existing_function.params)
            raw_params = dict(existing_function.raw_params)
            for name, value in summary.parameters.items():
                if name in params and params[name] is None:
                    params[name] = value.public_type()
                    public_type = value.public_type()
                    raw_params[name] = (
                        None if public_type is None else str(public_type)
                    )
            returns = existing_function.returns or summary.return_type
            raw_returns = existing_function.raw_returns
            if raw_returns is None and returns is not None:
                raw_returns = str(returns)
            updated = FunctionTypeInfo(
                name=existing_function.name,
                params=params,
                returns=returns,
                raw_params=raw_params,
                raw_returns=raw_returns,
                source=(
                    existing_function.source
                    if existing_function.source in {"annotation", "stub"}
                    else "static_inference"
                ),
            )
            functions[local_name] = updated
            old_fact = facts.get(local_name)
            facts[local_name] = TypeFact(
                name=local_name,
                typ=self._callable_type(updated),
                raw_annotation=updated.raw_returns,
                source=updated.source,
                kind="function" if old_fact is None else old_fact.kind,
            )

    def _resolve_inference_external_symbol(
        self,
        qualified_name: str,
    ) -> ProperType | None:
        module_name, separator, name = qualified_name.rpartition(".")
        if not separator:
            return None
        if module_name not in self._collected_modules:
            if module_name in self._collecting_modules:
                fact = self._module_facts.get(module_name, {}).get(name)
                return None if fact is None else fact.typ
            if self.project_context.find_module(module_name) is not None:
                self.collect_module(module_name)
        fact = self._module_facts.get(module_name, {}).get(name)
        return None if fact is None else fact.typ

    def _collect_stub_module(
        self,
        module_name: str,
        path: str,
        functions: list[StubFunctionInfo],
        classes: list[StubClassInfo],
        variables: list[tuple[str, str]],
        imports_raw: list[StubImportInfo],
    ) -> None:
        facts = self._module_facts.setdefault(module_name, {})
        module_functions = self._functions.setdefault(module_name, {})
        imports = self._stub_import_aliases(module_name, path, imports_raw)
        module_aliases = self._module_class_aliases.setdefault(module_name, {})

        for cls in classes:
            qualified_name = f"{module_name}.{cls.name}"
            self._class_aliases[cls.name] = qualified_name
            module_aliases[cls.name] = qualified_name

        for function in functions:
            function_info = self._function_info_from_stub(
                function,
                module_name=module_name,
                imports=imports,
            )
            module_functions[function.name] = function_info
            facts[function.name] = TypeFact(
                name=function.name,
                typ=self._callable_type(function_info),
                raw_annotation=function.returns,
                source="stub",
                kind="function",
            )

        for cls in classes:
            class_info = self._class_info_from_stub(module_name, cls, imports)
            self._classes[class_info.name] = class_info
            facts[cls.name] = TypeFact(
                name=cls.name,
                typ=class_info.typ,
                raw_annotation=class_info.name,
                source="stub",
                kind="class",
            )

        for name, annotation in variables:
            facts[name] = TypeFact(
                name=name,
                typ=self._resolve_annotation(
                    annotation,
                    module_name=module_name,
                    imports=imports,
                ),
                raw_annotation=annotation,
                source="stub",
                kind="variable",
            )

    def _collect_import_aliases(
        self,
        module_name: str,
        tree: ast.Module,
        path: str | None,
    ) -> dict[str, str]:
        imports: dict[str, str] = {}
        for node in tree.body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or alias.name.split(".")[0]
                    imports[local] = alias.name if alias.asname else local
            elif isinstance(node, ast.ImportFrom):
                source_module = self.project_context.resolve_import_name(
                    module_name,
                    node.module or "",
                    int(getattr(node, "level", 0) or 0),
                    current_path=path,
                )
                if not source_module:
                    continue
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    local = alias.asname or alias.name
                    imports[local] = f"{source_module}.{alias.name}"
        return imports

    def _stub_import_aliases(
        self,
        module_name: str,
        path: str,
        imports_raw: list[StubImportInfo],
    ) -> dict[str, str]:
        imports: dict[str, str] = {}
        for item in imports_raw:
            if not item.is_from:
                for imported_name, asname in item.names:
                    local = asname or imported_name.split(".")[0]
                    imports[local] = imported_name if asname else local
                continue

            source_module = self.project_context.resolve_import_name(
                module_name,
                item.module or "",
                item.level,
                current_path=path,
            )
            if not source_module:
                continue
            for imported_name, asname in item.names:
                if imported_name == "*":
                    continue
                local = asname or imported_name
                imports[local] = f"{source_module}.{imported_name}"
        return imports

    def _class_info_from_source(
        self,
        module_name: str,
        node: ast.ClassDef,
        imports: dict[str, str],
    ) -> ClassTypeInfo:
        members: dict[str, TypeFact] = {}
        methods: dict[str, FunctionTypeInfo] = {}
        qualified_name = f"{module_name}.{node.name}"
        class_typ = self._synthetic_instance(qualified_name)
        for stmt in node.body:
            if (
                isinstance(stmt, ast.AnnAssign)
                and isinstance(stmt.target, ast.Name)
            ):
                raw_annotation = _annotation_to_str(stmt.annotation)
                members[stmt.target.id] = TypeFact(
                    name=stmt.target.id,
                    typ=self._resolve_annotation(
                        raw_annotation,
                        module_name=module_name,
                        imports=imports,
                    ),
                    raw_annotation=raw_annotation,
                    source="annotation",
                    kind="class_var",
                )
            elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                method_info = self._function_info_from_source(
                    stmt,
                    module_name=module_name,
                    imports=imports,
                    source="annotation",
                )
                methods[stmt.name] = method_info
                members[stmt.name] = TypeFact(
                    name=stmt.name,
                    typ=method_info.returns,
                    raw_annotation=method_info.raw_returns,
                    source="annotation",
                    kind="method",
                )
        raw_bases = tuple(_annotation_to_str(base) for base in node.bases)
        return ClassTypeInfo(
            name=qualified_name,
            typ=class_typ,
            bases=tuple(
                resolved
                for raw_base in raw_bases
                if (
                    resolved := self._resolve_annotation(
                        raw_base,
                        module_name=module_name,
                        imports=imports,
                    )
                )
                is not None
            ),
            raw_bases=raw_bases,
            members=members,
            methods=methods,
            source="annotation",
        )

    def _function_info_from_source(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        module_name: str,
        imports: dict[str, str],
        source: str,
    ) -> FunctionTypeInfo:
        raw_params: dict[str, str | None] = {}
        params: dict[str, ProperType | None] = {}
        for arg in _iter_arguments(node.args):
            raw = (
                _annotation_to_str(arg.annotation)
                if arg.annotation is not None
                else None
            )
            raw_params[arg.arg] = raw
            params[arg.arg] = self._resolve_annotation(
                raw,
                module_name=module_name,
                imports=imports,
            )
        if node.args.vararg is not None:
            raw = (
                _annotation_to_str(node.args.vararg.annotation)
                if node.args.vararg.annotation is not None
                else None
            )
            raw_params[f"*{node.args.vararg.arg}"] = raw
            params[f"*{node.args.vararg.arg}"] = self._resolve_annotation(
                raw,
                module_name=module_name,
                imports=imports,
            )
        if node.args.kwarg is not None:
            raw = (
                _annotation_to_str(node.args.kwarg.annotation)
                if node.args.kwarg.annotation is not None
                else None
            )
            raw_params[f"**{node.args.kwarg.arg}"] = raw
            params[f"**{node.args.kwarg.arg}"] = self._resolve_annotation(
                raw,
                module_name=module_name,
                imports=imports,
            )
        raw_returns = (
            _annotation_to_str(node.returns)
            if node.returns is not None
            else None
        )
        return FunctionTypeInfo(
            name=node.name,
            params=params,
            returns=self._resolve_annotation(
                raw_returns,
                module_name=module_name,
                imports=imports,
            ),
            raw_params=raw_params,
            raw_returns=raw_returns,
            source=source,
        )

    def _function_info_from_stub(
        self,
        function: StubFunctionInfo,
        *,
        module_name: str,
        imports: dict[str, str],
    ) -> FunctionTypeInfo:
        raw_params = {name: annotation for name, annotation in function.params}
        return FunctionTypeInfo(
            name=function.name,
            params={
                name: self._resolve_annotation(
                    annotation,
                    module_name=module_name,
                    imports=imports,
                )
                for name, annotation in raw_params.items()
            },
            returns=self._resolve_annotation(
                function.returns,
                module_name=module_name,
                imports=imports,
            ),
            raw_params=raw_params,
            raw_returns=function.returns,
            source="stub",
        )

    def _class_info_from_stub(
        self,
        module_name: str,
        cls: StubClassInfo,
        imports: dict[str, str],
    ) -> ClassTypeInfo:
        qualified_name = f"{module_name}.{cls.name}"
        members = {
            name: TypeFact(
                name=name,
                typ=self._resolve_annotation(
                    annotation,
                    module_name=module_name,
                    imports=imports,
                ),
                raw_annotation=annotation,
                source="stub",
                kind="class_var",
            )
            for name, annotation in cls.class_vars
        }
        methods = {
            method.name: self._function_info_from_stub(
                method,
                module_name=module_name,
                imports=imports,
            )
            for method in cls.methods
        }
        for method in cls.methods:
            method_info = methods[method.name]
            members[method.name] = TypeFact(
                name=method.name,
                typ=method_info.returns,
                raw_annotation=method_info.raw_returns,
                source="stub",
                kind="method",
            )
        return ClassTypeInfo(
            name=qualified_name,
            typ=self._synthetic_instance(qualified_name),
            bases=tuple(
                resolved
                for raw_base in cls.bases
                if (
                    resolved := self._resolve_annotation(
                        raw_base,
                        module_name=module_name,
                        imports=imports,
                    )
                )
                is not None
            ),
            raw_bases=tuple(cls.bases),
            members=members,
            methods=methods,
            source="stub",
        )

    def _callable_type(self, function_info: FunctionTypeInfo) -> CallableType:
        return_type = (
            function_info.returns if function_info.returns is not None else ANY
        )
        return CallableType(
            tuple(
                typ if typ is not None else ANY
                for typ in function_info.params.values()
            ),
            return_type,
        )

    def _resolve_annotation(
        self,
        annotation: str | None,
        *,
        module_name: str | None = None,
        imports: dict[str, str] | None = None,
    ) -> ProperType | None:
        if annotation is None:
            return None
        lookup = cast(
            TypeLookup,
            lambda name: self._lookup_type(
                name,
                module_name=module_name,
                imports=imports or {},
            ),
        )
        return resolve_annotation(annotation, lookup)

    def _lookup_type(
        self,
        name: str,
        *,
        module_name: str | None = None,
        imports: dict[str, str],
    ) -> ProperType | None:
        imported = self._resolve_imported_type_name(name, imports)
        if imported is not None:
            builtin = BuiltinTypeLookup()(imported)
            if builtin is not None:
                return builtin
            resolved = self._lookup_project_type(
                imported,
                allow_synthetic=True,
            )
            if resolved is not None:
                return resolved

        normalized = name.rsplit(".", 1)[-1]
        if module_name is not None:
            aliases = self._module_class_aliases.get(module_name, {})
            alias = aliases.get(name) or aliases.get(normalized)
            if alias is not None:
                return self._synthetic_instance(alias)
        else:
            alias = self._class_aliases.get(name) or self._class_aliases.get(
                normalized,
            )
            if alias is not None:
                return self._synthetic_instance(alias)
        if module_name is None:
            for class_name, class_info in self._classes.items():
                if (
                    name == class_name
                    or normalized == class_name.rsplit(".", 1)[-1]
                ):
                    return class_info.typ

        builtin = BuiltinTypeLookup()(name)
        if builtin is not None:
            return builtin

        if module_name is not None:
            resolved = self._lookup_project_type(
                f"{module_name}.{name}",
                allow_synthetic=False,
            )
            if resolved is not None:
                return resolved
        return None

    def _resolve_imported_type_name(
        self,
        name: str,
        imports: dict[str, str],
    ) -> str | None:
        imported = imports.get(name)
        if imported is not None:
            return imported

        prefix, separator, rest = name.partition(".")
        if not separator:
            return None
        imported_prefix = imports.get(prefix)
        if imported_prefix is None:
            return None
        return f"{imported_prefix}.{rest}"

    def _lookup_project_type(
        self,
        qualified_name: str,
        *,
        allow_synthetic: bool,
    ) -> ProperType | None:
        class_info = self._classes.get(qualified_name)
        if class_info is not None:
            return class_info.typ

        module_name, separator, attr = qualified_name.rpartition(".")
        if not separator:
            return None

        if module_name not in self._collected_modules:
            if self.project_context.find_module(module_name) is not None:
                self.collect_module(module_name)

        class_info = self._classes.get(qualified_name)
        if class_info is not None:
            return class_info.typ

        fact = self._module_facts.get(module_name, {}).get(attr)
        if fact is not None:
            return fact.typ

        if (
            allow_synthetic
            and self.project_context.find_module(module_name) is not None
        ):
            return self._synthetic_instance(qualified_name)
        return None

    def _synthetic_instance(self, full_name: str) -> Instance:
        raw_type = self._synthetic_types.get(full_name)
        if raw_type is None:
            module_name, _, class_name = full_name.rpartition(".")
            raw_type = type(class_name, (), {"__module__": module_name})
            self._synthetic_types[full_name] = raw_type
        return Instance(self.type_system.to_class_descriptor(raw_type))

    def _infer_expr_type(
        self,
        node: ast.expr,
        module_name: str,
        local_classes: set[str],
        imports: dict[str, str],
    ) -> ProperType | None:
        if isinstance(node, ast.Constant):
            if node.value is None:
                return NONE_TYPE
            return Instance(self.type_system.to_class_descriptor(type(node.value)))
        if isinstance(node, ast.List):
            return Instance(self.type_system.to_class_descriptor(list))
        if isinstance(node, ast.Dict):
            return Instance(self.type_system.to_class_descriptor(dict))
        if isinstance(node, ast.Tuple):
            return TupleType(())
        if isinstance(node, ast.Set):
            return Instance(self.type_system.to_class_descriptor(set))
        if isinstance(node, ast.Name):
            if node.id in local_classes:
                return self._synthetic_instance(f"{module_name}.{node.id}")
            imported = self._resolve_imported_type_name(node.id, imports)
            if imported is not None:
                return self._synthetic_instance(imported)
        if isinstance(node, ast.Call):
            callee = _expr_name(node.func)
            if callee is None:
                return None
            if callee in local_classes:
                return self._synthetic_instance(f"{module_name}.{callee}")
            imported = imports.get(callee)
            if imported is None:
                imported = self._resolve_imported_type_name(callee, imports)
            if imported is not None:
                return self._synthetic_instance(imported)
        return None


def _iter_arguments(args: ast.arguments) -> Iterator[ast.arg]:
    yield from args.posonlyargs
    yield from args.args
    yield from args.kwonlyargs


def _annotation_to_str(node: ast.expr) -> str:
    return ast.unparse(node)


def _expr_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _expr_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None
