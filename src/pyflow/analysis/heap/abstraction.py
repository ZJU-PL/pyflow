"""Heap abstraction engine — canonicalization, alias tracking, and update policies.

:class:`HeapAbstraction` is the main workhorse: it canonicalizes raw
annotation-provided storage identities into :class:`HeapLocation` roots,
tracks alias equivalence classes via union-find, gates strong/weak
updates via reference counting, and tracks escape status.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .points_to_graph import PointsToGraph

from .model import (
    AllocationSensitivity,
    ContainerSensitivity,
    FieldSensitivity,
    HeapEscapeState,
    HeapLocation,
    HeapObject,
    HeapObjectFreshness,
    HeapObjectKind,
    HeapPolicy,
    HeapSelector,
    HeapWrite,
    RawStorageProvider,
    UpdatePolicy,
)


class HeapAbstraction:
    """Location-based heap abstraction shared by concrete IFDS clients.

    Locals initially map to annotation-provided raw storage identities, which
    are canonicalized into ``HeapLocation`` roots before they enter IFDS facts.
    Direct local aliases share the same raw-storage tuple and allocation-site
    id; strong local updates break that sharing and allocate a fresh site.
    Attribute and subscript accesses extend canonical roots with structural
    selectors.
    """

    def __init__(
        self,
        raw_storage_provider: RawStorageProvider,
        *,
        policy: HeapPolicy | None = None,
        storage_overrides: dict[tuple[int, int], tuple[object, ...]] | None = None,
        allocation_sites: dict[tuple[int, int], int] | None = None,
        site_storage: dict[int, tuple[object, ...]] | None = None,
        next_site: int = 0,
    ) -> None:
        self.policy = policy or HeapPolicy()
        self._raw_storage_provider = raw_storage_provider
        self.storage_overrides = (
            storage_overrides if storage_overrides is not None else {}
        )
        self.allocation_sites = allocation_sites if allocation_sites is not None else {}
        self.site_storage = site_storage if site_storage is not None else {}
        self._raw_locations: dict[int, HeapLocation] = {}
        self._objects: dict[tuple[object, ...], HeapObject] = {}
        self._object_labels: dict[HeapObject, str] = {}
        self._escaped_objects: set[HeapObject] = set()
        self._equiv_parent: dict[int, int] = {}
        self._equiv_members: dict[int, set[int]] = {}
        self._site_ref_counts: dict[int, int] = {}
        self.next_site = next_site

    def locations_for_local(
        self,
        procedure: object,
        local: object,
    ) -> tuple[HeapLocation, ...]:
        """Return canonical locations currently bound to a local."""
        return tuple(
            self.location_for_raw(raw)
            for raw in self._raw_storage_for_local(procedure, local)
        )

    def location_for_raw(self, raw: object) -> HeapLocation:
        """Canonicalize raw annotation/storage identity into a heap location."""
        if isinstance(raw, HeapLocation):
            return raw
        if isinstance(raw, HeapObject):
            return HeapLocation(raw)

        raw_identity = self._canonical_raw(raw)
        key = id(raw_identity)
        location = self._raw_locations.get(key)
        if location is None:
            location = HeapLocation(self._object_for_raw(raw_identity))
            self._raw_locations[key] = location
        return location

    def write_for_location(
        self,
        location: HeapLocation,
        *,
        policy: UpdatePolicy | None = None,
    ) -> HeapWrite:
        """Return a semantic write descriptor for a canonical location."""
        return HeapWrite(
            location=location,
            policy=policy or self.update_policy_for_location(location),
        )

    def update_policy_for_location(self, location: HeapLocation) -> UpdatePolicy:
        """Default IFDS update policy gated by equivalence-class reference counts.

        Root locations (locals, globals, cells) can be strongly updated when
        the equivalence class they belong to has a single reference (ref count
        ≤ 1).  Nested field/element locations default to weak updates because
        Python aliasing can make another access path observe the old value,
        unless the root is fresh and has exactly one reference.

        Immutable types skip the reference-count check entirely for root
        locations: reassignment always produces a fresh bind, so strong
        updates are always safe.
        """
        if location.root in self._escaped_objects:
            return UpdatePolicy.WEAK
        if self._is_immutable_type(location.root):
            return UpdatePolicy.STRONG if not location.is_nested() else UpdatePolicy.WEAK
        if not location.root.is_singleton():
            return UpdatePolicy.WEAK
        if not location.is_precise():
            return UpdatePolicy.WEAK
        site = self._root_allocation_site(location.root)
        ref_count = self._equiv_class_ref_count(site) if site is not None else 0
        if not location.is_nested():
            return UpdatePolicy.STRONG if ref_count <= 1 else UpdatePolicy.WEAK
        if self.policy.allow_strong_nested_fresh and ref_count <= 1:
            return UpdatePolicy.STRONG
        return UpdatePolicy.WEAK

    def _is_immutable_type(self, root: HeapObject) -> bool:
        if root.type_hint is not None and root.type_hint in self.policy.immutable_type_hints:
            return True
        return False

    def _root_allocation_site(self, root: HeapObject) -> int | None:
        """Get the allocation-site id for a HeapObject root, if one exists."""
        alloc_site = root.allocation_site
        if alloc_site is None:
            return None
        if isinstance(alloc_site, tuple):
            site_key = alloc_site
        else:
            site_key = id(alloc_site)
        for site, storage in self.site_storage.items():
            candidate = self._objects.get(
                (
                    root.kind.value,
                    root.key,
                    root.label,
                    root.type_hint,
                    site_key,
                    root.context,
                    root.freshness.value,
                    root.escape.value,
                )
            )
            if candidate is root:
                return site
        return None

    # ── alias equivalence-class tracking ────────────────────────────────

    def _find(self, site: int) -> int:
        """Union-find: find canonical root of an allocation site."""
        parent = self._equiv_parent.get(site)
        if parent is None:
            self._equiv_parent[site] = site
            self._equiv_members.setdefault(site, set()).add(site)
            return site
        if parent != site:
            root = self._find(parent)
            if root != parent:
                self._equiv_parent[site] = root
        return self._equiv_parent[site]

    def _unify(self, site_a: int, site_b: int) -> int:
        """Union-find: merge two equivalence classes. Returns the new canonical root."""
        if site_a == site_b:
            return site_a
        root_a = self._find(site_a)
        root_b = self._find(site_b)
        if root_a == root_b:
            return root_a
        members_a = self._equiv_members.get(root_a, {root_a})
        members_b = self._equiv_members.get(root_b, {root_b})
        refs_a = self._site_ref_counts.get(root_a, 0)
        refs_b = self._site_ref_counts.get(root_b, 0)
        if len(members_a) >= len(members_b):
            self._equiv_parent[root_b] = root_a
            merged = members_a | members_b
            self._equiv_members[root_a] = merged
            self._equiv_members.pop(root_b, None)
            self._site_ref_counts[root_a] = refs_a + refs_b
            self._site_ref_counts.pop(root_b, None)
            return root_a
        self._equiv_parent[root_a] = root_b
        merged = members_b | members_a
        self._equiv_members[root_b] = merged
        self._equiv_members.pop(root_a, None)
        self._site_ref_counts[root_b] = refs_b + refs_a
        self._site_ref_counts.pop(root_a, None)
        return root_b

    def _is_site_in_equiv_class(self, site: int, canonical_root: int) -> bool:
        return self._find(site) == self._find(canonical_root)

    def _equiv_class_sites(self, root_site: int) -> frozenset[int]:
        canonical = self._find(root_site)
        return frozenset(self._equiv_members.get(canonical, {canonical}))

    def _equiv_class_ref_count(self, root_site: int) -> int:
        canonical = self._find(root_site)
        return self._site_ref_counts.get(canonical, 0)

    def _incr_site_ref(self, site: int) -> None:
        canonical = self._find(site)
        self._site_ref_counts[canonical] = self._site_ref_counts.get(canonical, 0) + 1

    def _decr_site_ref(self, site: int) -> None:
        canonical = self._find(site)
        current = self._site_ref_counts.get(canonical, 0)
        if current > 0:
            self._site_ref_counts[canonical] = current - 1

    def aliased_locations(self, location: HeapLocation) -> frozenset[HeapLocation]:
        site = self._root_allocation_site(location.root)
        if site is None or location.is_nested():
            return frozenset({location})
        equiv_sites = self._equiv_class_sites(site)
        result: set[HeapLocation] = {location}
        for member_site in equiv_sites:
            if member_site == site:
                continue
            member_storage = self.site_storage.get(member_site)
            if member_storage is None:
                continue
            for raw in member_storage:
                member_loc = self.location_for_raw(raw)
                result.add(member_loc)
        return frozenset(result)

    def dynamic_attribute_location(self, base: object, attribute: str) -> HeapLocation:
        return self._append_selector(
            self.location_for_raw(base),
            self._field_selector(attribute),
        )

    def dynamic_subscript_location(self, base: object, subscript: str) -> HeapLocation:
        return self._append_selector(
            self.location_for_raw(base),
            self._subscript_selector(subscript),
        )

    def extend_location(
        self,
        base: object,
        selectors: tuple[HeapSelector, ...],
    ) -> HeapLocation:
        location = self.location_for_raw(base)
        for selector in selectors:
            location = self._append_selector(location, selector)
        return location

    def dynamic_attribute_locations(
        self,
        bases: tuple[object, ...],
        attributes: tuple[str, ...],
    ) -> tuple[HeapLocation, ...]:
        locations: list[HeapLocation] = []
        seen: set[HeapLocation] = set()
        for base in bases:
            for attribute in attributes:
                location = self.dynamic_attribute_location(base, attribute)
                if location in seen:
                    continue
                seen.add(location)
                locations.append(location)
        return tuple(locations)

    def dynamic_subscript_locations(
        self,
        bases: tuple[object, ...],
        subscripts: tuple[str, ...],
    ) -> tuple[HeapLocation, ...]:
        locations: list[HeapLocation] = []
        seen: set[HeapLocation] = set()
        for base in bases:
            for subscript in subscripts:
                location = self.dynamic_subscript_location(base, subscript)
                if location in seen:
                    continue
                seen.add(location)
                locations.append(location)
        return tuple(locations)

    def alias_locals(self, procedure: object, target: object, source: object) -> None:
        """Make *target* share source storage identity when both are named locals."""
        if not self._is_named_local(target) or not self._is_named_local(source):
            return
        source_storage = self._raw_storage_for_local(procedure, source)
        if not source_storage:
            return
        target_key = self._local_key(procedure, target)
        source_key = self._local_key(procedure, source)
        self.storage_overrides[target_key] = source_storage
        target_name = getattr(target, "name", None)
        if isinstance(target_name, str):
            for raw in source_storage:
                location = self.location_for_raw(raw)
                if location.root not in self._object_labels:
                    self._object_labels[location.root] = target_name
        source_site = self.allocation_sites.get(source_key)
        target_site = self.allocation_sites.get(target_key)
        if source_site is not None:
            self.allocation_sites[target_key] = source_site
            if target_site is not None and target_site != source_site:
                self._decr_site_ref(target_site)
                self._unify(source_site, target_site)
            else:
                self._incr_site_ref(source_site)

    def unalias_local(self, procedure: object, local: object) -> None:
        """Break a local alias and allocate a fresh site for the local."""
        if not self._is_named_local(local):
            return
        key = self._local_key(procedure, local)
        old_site = self.allocation_sites.get(key)
        if old_site is not None:
            self._decr_site_ref(old_site)
        self.storage_overrides.pop(key, None)
        raw = self._raw_storage_provider(procedure, local)
        self._assign_site(key, raw)

    def _sync_name_bindings(
        self,
        procedure: object,
        name: str,
        storage: tuple[object, ...],
        except_key: tuple[int, int],
    ) -> None:
        """Update all storage_overrides entries for the same variable name to
        point to the current *storage*, keeping the local alias class consistent
        across distinct ``Local`` node identities that share a variable name."""
        proc_id = id(procedure)
        for (p_id, l_id), old_storage in list(self.storage_overrides.items()):
            if p_id != proc_id or (p_id, l_id) == except_key:
                continue
            if not old_storage:
                continue
            root = old_storage[0]
            if self._name_matches_object(root, name):
                self.storage_overrides[(p_id, l_id)] = storage
                old_site = self.allocation_sites.get((p_id, l_id))
                if old_site is not None:
                    self._decr_site_ref(old_site)
                self.allocation_sites.pop((p_id, l_id), None)

    def bind_local_to_object(
        self,
        procedure: object,
        local: object,
        obj: HeapObject,
        *,
        include_raw_fallback: bool = False,
    ) -> None:
        """Bind a local directly to an abstract object root."""
        if not self._is_named_local(local):
            return
        key = self._local_key(procedure, local)
        old_site = self.allocation_sites.get(key)
        if old_site is not None:
            self._decr_site_ref(old_site)
        storage = (obj,)
        if include_raw_fallback:
            storage = (*storage, *self._raw_storage_provider(procedure, local))
        self.storage_overrides[key] = storage
        name = getattr(local, "name", None)
        if isinstance(name, str) and obj not in self._object_labels:
            self._object_labels[obj] = name
        self._assign_site(key, storage)
        if isinstance(name, str):
            self._sync_name_bindings(procedure, name, storage, except_key=key)

    def bind_local_to_locations(
        self,
        procedure: object,
        local: object,
        locations: tuple[object, ...],
        *,
        include_raw_fallback: bool = False,
    ) -> None:
        """Bind a local to existing abstract locations."""
        if not self._is_named_local(local):
            return
        storage = tuple(
            dict.fromkeys(self.location_for_raw(location) for location in locations)
        )
        if include_raw_fallback:
            storage = (*storage, *self._raw_storage_provider(procedure, local))
        if not storage:
            return
        key = self._local_key(procedure, local)
        self.storage_overrides[key] = storage
        name = getattr(local, "name", None)
        if isinstance(name, str):
            for raw in storage:
                location = self.location_for_raw(raw)
                if location.root not in self._object_labels:
                    self._object_labels[location.root] = name
        self._assign_site(key, storage)
        if isinstance(name, str):
            self._sync_name_bindings(procedure, name, storage, except_key=key)

    def bind_parameter(
        self,
        procedure: object,
        formal: object,
        index: int,
        actual_locations: tuple[object, ...],
        *,
        include_raw_fallback: bool = True,
    ) -> None:
        """Bind a callee formal to actual heap roots or to a parameter root."""
        if actual_locations:
            self.bind_local_to_locations(
                procedure,
                formal,
                actual_locations,
                include_raw_fallback=include_raw_fallback,
            )
            return
        label = getattr(formal, "name", None)
        self.bind_local_to_object(
            procedure,
            formal,
            self.parameter_object(procedure, index, label=label),
            include_raw_fallback=include_raw_fallback,
        )

    def bind_allocation_targets(
        self,
        procedure: object,
        targets: tuple[object, ...],
        site: object,
        *,
        label: str | None = None,
        type_hint: str | None = None,
        context: tuple[object, ...] = (),
        include_raw_fallback: bool = False,
    ) -> None:
        """Bind assignment targets to a fixed allocation-site object."""
        obj = self.allocation_object(
            procedure,
            site,
            label=label,
            type_hint=type_hint,
            context=context,
        )
        for target in targets:
            self.bind_local_to_object(
                procedure,
                target,
                obj,
                include_raw_fallback=include_raw_fallback,
            )

    def bind_fresh_return_targets(
        self,
        procedure: object,
        targets: tuple[object, ...],
        site: object,
        *,
        label: str | None = None,
        type_hint: str | None = None,
        context: tuple[object, ...] = (),
    ) -> None:
        """Bind call-result targets to a fresh allocation-like return object."""
        obj = self.allocation_object(
            procedure,
            site,
            label=label,
            type_hint=type_hint,
            context=context,
        )
        for target in targets:
            self.bind_local_to_object(
                procedure,
                target,
                obj,
                include_raw_fallback=True,
            )
            name = getattr(target, "name", None)
            if isinstance(name, str):
                self._object_labels[obj] = name

    def bind_call_result_targets(
        self,
        procedure: object,
        targets: tuple[object, ...],
        site: object,
        *,
        label: str | None = None,
        type_hint: str | None = None,
        context: tuple[object, ...] = (),
    ) -> None:
        """Bind assignment targets to a fixed call-result object."""
        for index, target in enumerate(targets):
            target_site = (site, index) if len(targets) > 1 else site
            target_label = label if len(targets) == 1 else f"{label or 'call'}[{index}]"
            obj = self.call_result_object(
                procedure,
                target_site,
                label=target_label,
                type_hint=type_hint,
                context=context,
            )
            self.bind_local_to_object(
                procedure,
                target,
                obj,
                include_raw_fallback=True,
            )

    def bind_summary_targets(
        self,
        procedure: object,
        targets: tuple[object, ...],
        key: object,
        *,
        label: str | None = None,
        type_hint: str | None = None,
    ) -> None:
        """Bind assignment targets to a summary object."""
        obj = self.summary_object(key, label=label, type_hint=type_hint)
        for target in targets:
            self.bind_local_to_object(
                procedure,
                target,
                obj,
                include_raw_fallback=True,
            )

    def update_assignment_aliases(
        self,
        procedure: object,
        targets: tuple[object, ...],
        expr: object,
    ) -> None:
        """Apply direct local assignment alias policy for ``targets = expr``."""
        for target in targets:
            self.unalias_local(procedure, target)
        if not self._is_named_local(expr):
            return
        for target in targets:
            self.alias_locals(procedure, target, expr)

    def local_object(
        self,
        procedure: object,
        local: object,
        *,
        label: str | None = None,
    ) -> HeapObject:
        name = label or getattr(local, "name", None) or self._describe_raw_storage(local)
        key = ("local", id(procedure), name)
        return self._object(
            HeapObjectKind.LOCAL,
            key,
            str(name),
            freshness=HeapObjectFreshness.FRESH,
            escape=HeapEscapeState.LOCAL,
        )

    def parameter_object(
        self,
        procedure: object,
        index: int,
        *,
        label: str | None = None,
        type_hint: str | None = None,
    ) -> HeapObject:
        key = ("parameter", id(procedure), index)
        return self._object(
            HeapObjectKind.PARAMETER,
            key,
            label or f"param[{index}]",
            type_hint=type_hint,
            freshness=HeapObjectFreshness.UNKNOWN,
            escape=HeapEscapeState.UNKNOWN,
        )

    def return_object(
        self,
        procedure: object,
        index: int,
        *,
        label: str | None = None,
        type_hint: str | None = None,
    ) -> HeapObject:
        key = ("return", id(procedure), index)
        return self._object(
            HeapObjectKind.RETURN,
            key,
            label or f"return[{index}]",
            type_hint=type_hint,
            freshness=HeapObjectFreshness.UNKNOWN,
            escape=HeapEscapeState.UNKNOWN,
        )

    def allocation_object(
        self,
        procedure: object,
        site: object,
        *,
        label: str | None = None,
        type_hint: str | None = None,
        context: tuple[object, ...] = (),
    ) -> HeapObject:
        key = self._site_key("allocation", procedure, site, context)
        freshness = (
            HeapObjectFreshness.FRESH
            if self.policy.recency
            else HeapObjectFreshness.SUMMARY
        )
        return self._object(
            HeapObjectKind.ALLOCATION,
            key,
            label or self._site_label("alloc", site),
            type_hint=type_hint,
            allocation_site=key,
            context=self._context_key(context),
            freshness=freshness,
            escape=HeapEscapeState.LOCAL,
        )

    def call_result_object(
        self,
        procedure: object,
        site: object,
        *,
        label: str | None = None,
        type_hint: str | None = None,
        context: tuple[object, ...] = (),
    ) -> HeapObject:
        key = self._site_key("call_result", procedure, site, context)
        return self._object(
            HeapObjectKind.CALL_RESULT,
            key,
            label or self._site_label("call", site),
            type_hint=type_hint,
            allocation_site=key,
            context=self._context_key(context),
            freshness=HeapObjectFreshness.UNKNOWN,
            escape=HeapEscapeState.UNKNOWN,
        )

    def external_object(
        self,
        key: object,
        *,
        label: str | None = None,
        type_hint: str | None = None,
    ) -> HeapObject:
        return self._object(
            HeapObjectKind.EXTERNAL,
            ("external", key),
            label or f"external:{key!r}",
            type_hint=type_hint,
            freshness=HeapObjectFreshness.UNKNOWN,
            escape=HeapEscapeState.EXTERNAL,
        )

    def global_object(
        self,
        name: object,
        *,
        module: object | None = None,
        label: str | None = None,
        type_hint: str | None = None,
    ) -> HeapObject:
        display = label or str(name)
        key = ("global", module, name)
        return self._object(
            HeapObjectKind.GLOBAL,
            key,
            display,
            type_hint=type_hint,
            freshness=HeapObjectFreshness.FRESH,
            escape=HeapEscapeState.EXTERNAL,
        )

    def cell_object(
        self,
        name: object,
        *,
        label: str | None = None,
        type_hint: str | None = None,
    ) -> HeapObject:
        display = label or str(name)
        return self._object(
            HeapObjectKind.CELL,
            ("cell", name),
            display,
            type_hint=type_hint,
            freshness=HeapObjectFreshness.FRESH,
            escape=HeapEscapeState.UNKNOWN,
        )

    def module_object(
        self,
        name: object,
        *,
        label: str | None = None,
        type_hint: str | None = None,
    ) -> HeapObject:
        display = label or str(name)
        return self._object(
            HeapObjectKind.GLOBAL,
            ("module", name),
            display,
            type_hint=type_hint or "module",
            freshness=HeapObjectFreshness.FRESH,
            escape=HeapEscapeState.EXTERNAL,
        )

    def summary_object(
        self,
        key: object,
        *,
        label: str | None = None,
        type_hint: str | None = None,
    ) -> HeapObject:
        return self._object(
            HeapObjectKind.SUMMARY,
            ("summary", key),
            label or f"summary:{key!r}",
            type_hint=type_hint,
            freshness=HeapObjectFreshness.SUMMARY,
            escape=HeapEscapeState.ESCAPED,
        )

    def display_label_for_location(self, location: HeapLocation) -> str:
        label = self._object_labels.get(location.root, location.root.label)
        for selector in location.selectors:
            if selector.kind == "field":
                label = f"{label}.{selector.value}"
            elif selector.kind == "element":
                label = f"{label}{selector.value}"
            elif selector.kind == "key":
                label = f"{label}[{selector.value!r}]"
            elif selector.kind == "index":
                label = f"{label}[{selector.value}]"
            elif selector.kind == "slice":
                label = f"{label}[slice]"
            elif selector.kind == "element_type":
                label = f"{label}[{selector.value}]"
            elif selector.kind == "summary":
                label = f"{label}.*"
        return label

    def mark_escaped(self, location: object) -> None:
        """Mark a location's root as escaped under the fixed escape policy."""
        if not self.policy.track_escapes:
            return
        heap_location = self.location_for_raw(location)
        self._escaped_objects.add(heap_location.root)

    def mark_all_escaped(self, locations: tuple[object, ...]) -> None:
        for location in locations:
            self.mark_escaped(location)

    @staticmethod
    def access_path_prefix_matches(stored: object, query: object) -> bool:
        """Return whether *stored* implies *query* by location/access-path prefix."""
        if stored == query:
            return True
        stored_location = getattr(stored, "location", None)
        query_location = getattr(query, "location", None)
        if stored_location is None or query_location is None:
            return False
        if isinstance(stored_location, HeapLocation) and isinstance(
            query_location,
            HeapLocation,
        ):
            if not stored_location.is_prefix_of(query_location):
                return False
        elif stored_location != query_location:
            return False
        stored_path = getattr(stored, "access_path", ())
        query_path = getattr(query, "access_path", ())
        if stored_path == query_path:
            return True
        return (
            len(stored_path) <= len(query_path)
            and query_path[: len(stored_path)] == stored_path
        )

    def to_points_to_graph(self) -> "PointsToGraph":
        """Export heap state as a reusable :class:`PointsToGraph`.

        Extracts a read-only snapshot mapping every canonical root
        :class:`HeapLocation` to a :class:`PointsToEntry` with alias,
        escape, reference-count, and update-policy metadata.  The
        resulting graph is consumed by optimization passes and the
        semantic query API.
        """
        from .points_to_graph import PointsToEntry, PointsToGraph

        entries: dict[HeapLocation, PointsToEntry] = {}
        for obj_key, obj in self._objects.items():
            location = HeapLocation(obj)
            if location in entries:
                continue
            site = self._root_allocation_site(obj)
            entries[location] = PointsToEntry(
                location=location,
                label=self.display_label_for_location(location),
                aliases=self.aliased_locations(location),
                ref_count=self._equiv_class_ref_count(site) if site is not None else 0,
                is_escaped=obj in self._escaped_objects,
                is_singleton=obj.is_singleton()
                and obj not in self._escaped_objects,
                update_policy=self.update_policy_for_location(location),
            )
        return PointsToGraph(entries=entries)

    def to_dict(self) -> dict:
        """Serialize the full heap state for inspection and debugging.

        Returns a dictionary with policy, allocation sites, equivalence
        classes, ref counts, and canonicalized object/location caches.
        The ``raw_storage_provider`` callable is not serializable and is
        omitted; reconstruction requires a new provider.
        """
        return {
            "policy": self.policy.to_dict(),
            "next_site": self.next_site,
            "storage_overrides": {
                str(k): [self._describe_raw_storage(r) for r in v]
                for k, v in self.storage_overrides.items()
            },
            "allocation_sites": {str(k): v for k, v in self.allocation_sites.items()},
            "site_count": len(self.site_storage),
            "escaped_objects": sorted(
                self.display_label_for_location(HeapLocation(obj))
                for obj in sorted(self._escaped_objects, key=lambda o: o.label)
            ),
            "equivalence_classes": len(self._equiv_parent),
            "total_ref_counts": sum(self._site_ref_counts.values()),
            "cached_objects": len(self._objects),
            "cached_locations": len(self._raw_locations),
        }

    @staticmethod
    def _local_key(procedure: object, local: object) -> tuple[int, int]:
        return id(procedure), id(local)

    @staticmethod
    def _is_named_local(value: object) -> bool:
        return isinstance(getattr(value, "name", None), str)

    def _object(
        self,
        kind: HeapObjectKind,
        key: object,
        label: str,
        *,
        type_hint: str | None = None,
        allocation_site: object | None = None,
        context: tuple[object, ...] = (),
        freshness: HeapObjectFreshness = HeapObjectFreshness.FRESH,
        escape: HeapEscapeState = HeapEscapeState.LOCAL,
    ) -> HeapObject:
        object_key = (
            kind.value,
            key,
            label,
            type_hint,
            allocation_site,
            context,
            freshness.value,
            escape.value,
        )
        obj = self._objects.get(object_key)
        if obj is None:
            obj = HeapObject(
                kind,
                key,
                label,
                type_hint=type_hint,
                allocation_site=allocation_site,
                context=context,
                freshness=freshness,
                escape=escape,
            )
            self._objects[object_key] = obj
        return obj

    def _object_for_raw(self, raw: object) -> HeapObject:
        if isinstance(raw, HeapObject):
            return raw
        slot_name = getattr(raw, "slotName", None)
        if slot_name is not None:
            if hasattr(slot_name, "isLocal") and slot_name.isLocal():
                local = getattr(slot_name, "local", None)
                name = getattr(local, "name", None)
                label = str(name) if name is not None else str(slot_name)
                return self._object(
                    HeapObjectKind.LOCAL,
                    ("slot-local", id(slot_name), label),
                    label,
                    freshness=HeapObjectFreshness.FRESH,
                    escape=HeapEscapeState.LOCAL,
                )
            if hasattr(slot_name, "isExisting") and slot_name.isExisting():
                obj = getattr(slot_name, "object", None)
                label = self._object_label(obj) or str(slot_name)
                return self._object(
                    HeapObjectKind.GLOBAL,
                    ("slot-existing", id(obj), id(slot_name)),
                    label,
                    freshness=HeapObjectFreshness.FRESH,
                    escape=HeapEscapeState.EXTERNAL,
                )
        label = self._describe_raw_storage(raw)
        return self._object(
            HeapObjectKind.STORAGE,
            ("raw", id(raw)),
            label,
            freshness=HeapObjectFreshness.FRESH,
            escape=HeapEscapeState.LOCAL,
        )

    def _site_key(
        self,
        kind: str,
        procedure: object,
        site: object,
        context: tuple[object, ...],
    ) -> tuple[object, ...]:
        if self.policy.allocation_sensitivity is AllocationSensitivity.NONE:
            return (kind,)
        if isinstance(site, tuple) and site and site[0] == "call_return":
            return (kind, *site)
        if self.policy.allocation_sensitivity is AllocationSensitivity.SITE:
            return kind, id(site)
        if self.policy.allocation_sensitivity is AllocationSensitivity.PROCEDURE:
            return kind, id(procedure), id(site)
        return kind, id(procedure), id(site), self._context_key(context)

    def _context_key(self, context: tuple[object, ...]) -> tuple[object, ...]:
        depth = self.policy.context_sensitivity_depth
        if depth <= 0:
            return ()
        return tuple(context[-depth:])

    @staticmethod
    def _site_label(prefix: str, site: object) -> str:
        line = getattr(site, "line", None)
        column = getattr(site, "column", None)
        if line is not None and column is not None:
            return f"{prefix}@{line}:{column}"
        if line is not None:
            return f"{prefix}@{line}"
        return f"{prefix}@{type(site).__name__}:{id(site):x}"

    @staticmethod
    def _object_label(obj: object) -> str | None:
        pyobj = getattr(obj, "pyobj", None)
        if isinstance(pyobj, str):
            return pyobj
        if pyobj is not None:
            return repr(pyobj)
        name = getattr(obj, "name", None)
        if isinstance(name, str):
            return name
        return None

    @staticmethod
    def _canonical_raw(raw: object) -> object:
        get_forward = getattr(raw, "getForward", None)
        if callable(get_forward):
            return get_forward()
        return raw

    @staticmethod
    def _describe_raw_storage(raw: object) -> str:
        label = getattr(raw, "label", None)
        if isinstance(label, str):
            return label
        slot_name = getattr(raw, "slotName", None)
        if slot_name is not None:
            return str(slot_name)
        return repr(raw)

    def _field_selector(self, attribute: str) -> HeapSelector:
        if self.policy.field_sensitivity is FieldSensitivity.NONE:
            return HeapSelector.unknown_field()
        if attribute == "*":
            return HeapSelector.unknown_field()
        return HeapSelector.field(attribute)

    def _subscript_selector(self, subscript: str) -> HeapSelector:
        if subscript == "[slice]":
            return HeapSelector.slice()
        if subscript == "[*]":
            return HeapSelector.unknown_element()
        policy = self.policy.container_sensitivity
        if policy in {ContainerSensitivity.NONE, ContainerSensitivity.WILDCARD}:
            return HeapSelector.unknown_element()
        literal = self._subscript_literal(subscript)
        if policy is ContainerSensitivity.LITERAL_KEYS:
            if literal is not None:
                index = self._literal_index(literal)
                if index is not None:
                    return HeapSelector.index(index)
                return HeapSelector.key(literal)
            return HeapSelector.unknown_element()
        if policy is ContainerSensitivity.BOUNDED_INDICES:
            if literal is not None:
                index = self._literal_index(literal)
                if index is not None and 0 <= index <= self.policy.max_index:
                    return HeapSelector.index(index)
                return HeapSelector.key(literal)
            return HeapSelector.unknown_element()
        return HeapSelector.unknown_element()

    @staticmethod
    def _subscript_literal(subscript: str) -> str | None:
        if len(subscript) < 3 or not subscript.startswith("[") or not subscript.endswith("]"):
            return None
        inner = subscript[1:-1]
        if not inner or inner == "*":
            return None
        if (
            len(inner) >= 2
            and inner[0] == inner[-1]
            and inner[0] in {"'", '"'}
        ):
            return inner[1:-1]
        return inner

    @staticmethod
    def _literal_index(literal: str) -> int | None:
        try:
            return int(literal)
        except ValueError:
            return None

    def _append_selector(
        self,
        location: HeapLocation,
        selector: HeapSelector,
    ) -> HeapLocation:
        if (
            self.policy.field_sensitivity is FieldSensitivity.BOUNDED_PATH
            and self.policy.max_selector_depth is not None
            and len(location.selectors) >= self.policy.max_selector_depth
        ):
            selector = HeapSelector.summary()
        return HeapLocation(location.root, (*location.selectors, selector))

    def _raw_storage_for_local(
        self,
        procedure: object,
        local: object,
    ) -> tuple[object, ...]:
        key = self._local_key(procedure, local)
        override = self.storage_overrides.get(key)
        if override is not None:
            return override
        site = self.allocation_sites.get(key)
        if site is not None:
            return self.site_storage[site]
        # Fallback: name-based lookup for the same variable. The IR may
        # produce distinct Local nodes (different id()) for the same name
        # (e.g. CodeParameters vs Assign.expr vs Call args). Try to find
        # canonical storage before creating a new empty site.
        canon = self._canonical_storage_for_name(procedure, local)
        if canon is not None:
            return canon
        raw = self._raw_storage_provider(procedure, local)
        self._assign_site(key, raw)
        return raw

    def _name_matches_object(self, obj: object, name: str) -> bool:
        """Check if *obj* has the given *name*, checking both ``.label`` and
        the ``_object_labels`` override map (set by :meth:`alias_locals`)."""
        if getattr(obj, "label", None) == name:
            return True
        return self._object_labels.get(obj) == name

    def _canonical_storage_for_name(
        self,
        procedure: object,
        local: object,
    ) -> tuple[object, ...] | None:
        """Look up storage by variable name across the same procedure.

        Returns the canonical storage for the variable named by *local*
        if found in either ``storage_overrides`` or ``allocation_sites``
        under any ``Local`` id for this procedure.

        Search in reverse insertion order so that the most recent
        assignment to the variable takes precedence over earlier ones.
        """
        name = getattr(local, "name", None)
        if not name:
            return None
        proc_id = id(procedure)
        # Search storage_overrides in reverse: most recent binding wins.
        for (p_id, _l_id), storage in reversed(list(self.storage_overrides.items())):
            if p_id != proc_id or not storage:
                continue
            root = storage[0]
            if self._name_matches_object(root, name):
                return storage
        # Search allocation_sites in reverse for the same reason.
        for (p_id, _l_id), site in reversed(list(self.allocation_sites.items())):
            if p_id != proc_id:
                continue
            stored = self.site_storage.get(site, ())
            if not stored:
                continue
            root = stored[0]
            if self._name_matches_object(root, name):
                return tuple(stored)
        return None

    def _assign_site(self, key: tuple[int, int], storage: tuple[object, ...]) -> None:
        site = self.next_site
        self.next_site += 1
        self.allocation_sites[key] = site
        self.site_storage[site] = storage
        self._incr_site_ref(site)
