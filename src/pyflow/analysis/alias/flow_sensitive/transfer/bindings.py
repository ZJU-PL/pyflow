"""Lexical and runtime binding resolution for heap transfer."""

from __future__ import annotations

from pyflow.language.python.ir_metadata import assigned_locals
from pyflow.language.python import ast as py_ast

from ..domain.abstraction import LocalValue
from ..model import HeapLocation, UpdatePolicy


class _BindingTransferMixin:
    def _outer_local_locations(
        self,
        local: py_ast.Local,
    ) -> tuple[HeapLocation, ...]:
        local_name = getattr(local, "name", None)
        locations: list[HeapLocation] = []
        keys = set(self.heap.storage_overrides) | set(self.heap.allocation_sites)
        for key in keys:
            if not isinstance(local_name, str) or self.heap._local_names.get(
                key
            ) != local_name:
                continue
            storage = self.heap.storage_overrides.get(key)
            if storage is None:
                site = self.heap.allocation_sites.get(key)
                storage = (
                    self.heap.site_storage.get(site, ()) if site is not None else ()
                )
            locations.extend(self.heap.location_for_raw(raw) for raw in storage)
        return tuple(dict.fromkeys(locations))

    def _declared_location(
        self,
        procedure: object,
        local: py_ast.Local,
    ) -> HeapLocation | None:
        name = getattr(local, "name", None)
        if not name:
            return None
        procedure_id = self._procedure_identity(procedure)
        if name in self._global_declarations.get(procedure_id, set()):
            return self.effect_builder.global_location(procedure, name)
        if name in self._nonlocal_declarations.get(procedure_id, set()):
            owner = self._nonlocal_owners.get((procedure_id, name))
            if owner is None:
                owner = self._register_nonlocal_binding(procedure, name)
            return self._lexical_cell_location(owner, name)
        if name in self._captured_names_by_scope.get(procedure_id, set()):
            return self._lexical_cell_location(procedure, name)
        return None

    def _register_nonlocal_binding(self, procedure: object, name: str) -> object:
        owner = self._nearest_lexical_binding(procedure, name)
        procedure_id = self._procedure_identity(procedure)
        owner_id = self._procedure_identity(owner)
        self._nonlocal_owners[(procedure_id, name)] = owner
        self._captured_names_by_scope.setdefault(owner_id, set()).add(name)
        cell = self._lexical_cell_location(owner, name)
        existing = self._scope_name_locations(owner, name)
        if existing:
            current = self.state.read(cell, fallback=())
            self.state.write(
                cell,
                tuple(dict.fromkeys((*current, *existing))),
                UpdatePolicy.STRONG,
            )
        return owner

    def _nearest_lexical_binding(self, procedure: object, name: str) -> object:
        parent = self._lexical_parents.get(procedure)
        fallback = parent if parent is not None else procedure
        while parent is not None:
            if self._scope_defines_name(parent, name):
                return parent
            parent = self._lexical_parents.get(parent)
        return fallback

    def _scope_defines_name(self, procedure: object, name: str) -> bool:
        parameters = getattr(procedure, "codeparameters", None)
        if parameters is not None:
            for formal in self._callee_formals(procedure):
                if getattr(formal, "name", None) == name:
                    return True
        if (self._procedure_identity(procedure), name) in self._definition_locals:
            return True
        if self._scope_name_locations(procedure, name):
            return True
        body = getattr(procedure, "ast", None)
        for operation in self.iter_operations(body):
            if isinstance(operation, (py_ast.FunctionDef, py_ast.ClassDef)):
                if operation.name == name:
                    return True
                continue
            if any(
                getattr(local, "name", None) == name
                for local in assigned_locals(operation)
            ):
                return True
        return False

    def _scope_name_locations(
        self,
        procedure: object,
        name: str,
    ) -> tuple[HeapLocation, ...]:
        locations: list[HeapLocation] = []
        keys = set(self.heap.storage_overrides) | set(self.heap.allocation_sites)
        for key in keys:
            if key[0] != self.heap._procedure_key(
                procedure
            ) or self.heap._local_names.get(key) != name:
                continue
            storage = self.heap.storage_overrides.get(key)
            if storage is None:
                site = self.heap.allocation_sites.get(key)
                storage = (
                    self.heap.site_storage.get(site, ()) if site is not None else ()
                )
            locations.extend(self.heap.location_for_raw(raw) for raw in storage)
        return tuple(dict.fromkeys(locations))

    def _lexical_cell_location(
        self,
        owner: object,
        name: str,
    ) -> HeapLocation:
        key = (self._procedure_identity(owner), name)
        cell = self._lexical_cells.get(key)
        if cell is None:
            cell = py_ast.Cell(name)
            self._lexical_cells[key] = cell
        return self.effect_builder.cell_location(cell, owner)

    def _bind_runtime_local(
        self,
        procedure: object,
        local: py_ast.Local,
        locations: tuple[HeapLocation, ...],
        *,
        include_provider_storage: bool = False,
        may_non_reference: bool = False,
    ) -> None:
        declared = self._declared_location(procedure, local)
        if declared is not None:
            self.state.write(declared, locations, UpdatePolicy.STRONG)
            return
        if not locations:
            self.heap.clear_local_binding(procedure, local)
            return
        self.heap.bind_local_to_locations(
            procedure,
            local,
            locations,
            include_provider_storage=include_provider_storage,
        )
        if may_non_reference:
            self.heap._set_local_value(
                procedure,
                local,
                LocalValue(
                    refs=frozenset(locations),
                    may_non_reference=True,
                ),
            )

    def _clear_runtime_local(
        self,
        procedure: object,
        local: py_ast.Local,
        *,
        unbound: bool = False,
    ) -> None:
        declared = self._declared_location(procedure, local)
        if declared is not None:
            if unbound:
                self.state.delete(declared)
            else:
                self.state.write(
                    declared,
                    (),
                    UpdatePolicy.STRONG,
                    has_non_reference=True,
                )
            return
        self.heap.clear_local_binding(procedure, local, unbound=unbound)

    @classmethod
    def iter_code_objects(cls, root: object):
        """Yield code objects reachable from *root* without recursing into bodies."""
        seen: set[object] = set()

        def visit(value: object):
            if value is None or isinstance(value, py_ast.leafTypes):
                return
            if isinstance(value, py_ast.Code):
                if value not in seen:
                    seen.add(value)
                    yield value
                return
            if isinstance(value, (list, tuple, set, frozenset)):
                for item in value:
                    yield from visit(item)
                return
            for attr in ("liveCode", "entryPoints", "codes", "procedures", "functions"):
                child = getattr(value, attr, None)
                if child is not None:
                    yield from visit(child)
            code = getattr(value, "code", None)
            if code is not value:
                yield from visit(code)

        yield from visit(root)

    @classmethod
    def iter_operations(cls, node: object):
        """Yield operation nodes inside a code body."""
        if node is None or isinstance(node, py_ast.leafTypes):
            return
        if isinstance(node, py_ast.Code):
            return
        if isinstance(node, py_ast.Suite):
            for block in node.blocks:
                yield from cls.iter_operations(block)
            return
        if isinstance(node, py_ast.PythonASTNode):
            yield node
            if hasattr(node, "visitChildren"):
                children: list[object] = []
                node.visitChildren(children.append)
                for child in children:
                    yield from cls.iter_operations(child)
