"""Heap abstraction engine — canonicalization, alias tracking, and update policies.

:class:`HeapAbstraction` is the main workhorse: it canonicalizes raw
annotation-provided storage identities into :class:`HeapLocation` roots,
tracks alias equivalence classes via union-find, gates strong/weak
updates via reference counting, and tracks escape status.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from pyflow.ir.core.storage import (
    AttributeStorage,
    CellStorage,
    GlobalStorage,
    LocalStorage,
    StorageLocation,
    SubscriptStorage,
    SummaryStorage,
    UnknownStorage,
)

if TYPE_CHECKING:
    from .points_to import PointsToGraph

from ..model import (
    AllocationSensitivity,
    ContainerSensitivity,
    FieldSensitivity,
    HeapEscapeState,
    HeapLocation,
    HeapObject,
    HeapObjectCardinality,
    HeapObjectFreshness,
    HeapObjectIdentity,
    HeapObjectKind,
    HeapPolicy,
    HeapSelector,
    HeapWrite,
    RawStorageProvider,
    UpdatePolicy,
)


@dataclass
class HeapEnvironment:
    """Flow-sensitive snapshot of mutable heap binding metadata.

    Canonical object caches are deliberately not included: they are stable
    identities shared by every path.  Bindings, escape state, alias metadata,
    and reference counts do vary by path and therefore must be restored and
    joined with the value-level :class:`HeapState`.
    """

    storage_overrides: dict[tuple[int, int], tuple[object, ...]]
    allocation_sites: dict[tuple[int, int], int]
    site_storage: dict[int, tuple[object, ...]]
    object_labels: dict[HeapObject, str]
    local_names: dict[tuple[int, int], str]
    escaped_objects: set[HeapObject]
    equiv_parent: dict[int, int]
    equiv_members: dict[int, set[int]]
    site_ref_counts: dict[int, int]


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
        self._raw_locations: dict[object, HeapLocation] = {}
        self._root_site_index: dict[HeapObject, int] | None = None
        self._objects: dict[tuple[object, ...], HeapObject] = {}
        self._object_labels: dict[HeapObject, str] = {}
        self._local_names: dict[tuple[int, int], str] = {}
        self._escaped_objects: set[HeapObject] = set()
        self._equiv_parent: dict[int, int] = {}
        self._equiv_members: dict[int, set[int]] = {}
        self._site_ref_counts: dict[int, int] = {}
        self._opaque_sites: list[object] = []
        self._opaque_raw_objects: list[object] = []
        self.next_site = next_site

    def locations_for_local(
        self,
        procedure: object,
        local: object,
    ) -> tuple[HeapLocation, ...]:
        """Return canonical locations currently bound to a local."""
        locations = tuple(
            self.location_for_raw(raw)
            for raw in self._raw_storage_for_local(procedure, local)
        )
        name = getattr(local, "name", None)
        if isinstance(name, str):
            for location in locations:
                self._object_labels.setdefault(location.root, name)
        return locations

    def location_for_raw(self, raw: object) -> HeapLocation:
        """Canonicalize raw annotation/storage identity into a heap location."""
        if isinstance(raw, HeapLocation):
            return raw
        if isinstance(raw, HeapObject):
            return HeapLocation(raw)

        if isinstance(raw, AttributeStorage):
            return self.dynamic_attribute_location(raw.base, str(raw.field))
        if isinstance(raw, SubscriptStorage):
            return self.dynamic_subscript_location(
                raw.base, self._storage_subscript(raw.key)
            )
        if isinstance(raw, SummaryStorage):
            return self._append_selector(
                self.location_for_raw(raw.base), HeapSelector.summary()
            )

        raw_identity = self._canonical_raw(raw)
        key = self._raw_location_key(raw_identity)
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
        ≤ 1).  A precise nested field/element of a singleton abstract object
        can be strongly updated regardless of how many access paths reach that
        object: the concrete write overwrites the same field for all aliases.
        Operation-level transfer separately downgrades writes through multiple
        possible receiver roots.

        Immutable types skip the reference-count check entirely for root
        locations: reassignment always produces a fresh bind, so strong
        updates are always safe.
        """
        if self._is_immutable_type(location.root):
            return (
                UpdatePolicy.STRONG if not location.is_nested() else UpdatePolicy.WEAK
            )
        if not location.root.is_singleton():
            return UpdatePolicy.WEAK
        if not location.is_precise():
            return UpdatePolicy.WEAK
        if location.is_nested() and self.policy.allow_strong_nested_fresh:
            return UpdatePolicy.STRONG
        if location.is_nested():
            return UpdatePolicy.WEAK
        ref_count = self.reference_count_for_root(location.root)
        return UpdatePolicy.STRONG if ref_count <= 1 else UpdatePolicy.WEAK

    def snapshot_environment(self) -> HeapEnvironment:
        """Capture all path-dependent binding and escape metadata."""
        return HeapEnvironment(
            storage_overrides=dict(self.storage_overrides),
            allocation_sites=dict(self.allocation_sites),
            site_storage=dict(self.site_storage),
            object_labels=dict(self._object_labels),
            local_names=dict(self._local_names),
            escaped_objects=set(self._escaped_objects),
            equiv_parent=dict(self._equiv_parent),
            equiv_members={
                root: set(members) for root, members in self._equiv_members.items()
            },
            site_ref_counts=dict(self._site_ref_counts),
        )

    def restore_environment(self, environment: HeapEnvironment) -> None:
        """Restore a previously captured flow-sensitive environment."""
        self.storage_overrides = dict(environment.storage_overrides)
        self.allocation_sites = dict(environment.allocation_sites)
        self.site_storage = dict(environment.site_storage)
        self._root_site_index = None
        self._object_labels = dict(environment.object_labels)
        self._local_names = dict(environment.local_names)
        self._escaped_objects = set(environment.escaped_objects)
        self._equiv_parent = dict(environment.equiv_parent)
        self._equiv_members = {
            root: set(members) for root, members in environment.equiv_members.items()
        }
        self._site_ref_counts = dict(environment.site_ref_counts)

    def join_environments(
        self,
        environments: tuple[HeapEnvironment, ...],
    ) -> HeapEnvironment:
        """Join path environments by unioning each local's possible storage.

        Allocation-site equivalence is a must-alias relation, so branch-local
        unifications are not unioned.  Joined bindings instead retain every
        possible root and receive an independent site whenever the incoming
        bindings differ.  Reference counts are subsequently derived from live
        bindings rather than historical union-find membership.
        """
        if not environments:
            return self.snapshot_environment()

        local_names: dict[tuple[int, int], str] = {}
        object_labels: dict[HeapObject, str] = {}
        escaped_objects: set[HeapObject] = set()
        keys: set[tuple[int, int]] = set()
        for environment in environments:
            local_names.update(environment.local_names)
            object_labels.update(environment.object_labels)
            escaped_objects.update(environment.escaped_objects)
            keys.update(environment.storage_overrides)
            keys.update(environment.allocation_sites)

        storage_overrides: dict[tuple[int, int], tuple[object, ...]] = {}
        allocation_sites: dict[tuple[int, int], int] = {}
        site_storage: dict[int, tuple[object, ...]] = {}
        site_ref_counts: dict[int, int] = {}

        for key in sorted(keys, key=self._binding_sort_key):
            incoming = tuple(
                self._environment_storage(environment, key)
                for environment in environments
            )
            joined = self._join_storage(incoming)
            if not joined:
                continue

            storage_overrides[key] = joined
            sites = tuple(
                environment.allocation_sites.get(key) for environment in environments
            )
            concrete_sites = tuple(site for site in sites if site is not None)
            same_storage = all(
                self._canonicalize_storage(storage) == joined
                for storage in incoming
                if storage
            )
            if (
                concrete_sites
                and len(concrete_sites) == len(environments)
                and same_storage
            ):
                site = concrete_sites[0]
            else:
                site = self.next_site
                self.next_site += 1
            allocation_sites[key] = site
            site_storage[site] = joined
            site_ref_counts[site] = site_ref_counts.get(site, 0) + 1

        equiv_parent = {site: site for site in site_storage}
        equiv_members = {site: {site} for site in site_storage}
        return HeapEnvironment(
            storage_overrides=storage_overrides,
            allocation_sites=allocation_sites,
            site_storage=site_storage,
            object_labels=object_labels,
            local_names=local_names,
            escaped_objects=escaped_objects,
            equiv_parent=equiv_parent,
            equiv_members=equiv_members,
            site_ref_counts=site_ref_counts,
        )

    @staticmethod
    def _environment_storage(
        environment: HeapEnvironment,
        key: tuple[int, int],
    ) -> tuple[object, ...]:
        override = environment.storage_overrides.get(key)
        if override is not None:
            return override
        site = environment.allocation_sites.get(key)
        if site is None:
            return ()
        return environment.site_storage.get(site, ())

    def _canonicalize_storage(
        self,
        storage: tuple[object, ...],
    ) -> tuple[HeapLocation, ...]:
        return tuple(dict.fromkeys(self.location_for_raw(raw) for raw in storage))

    def _join_storage(
        self,
        storages: tuple[tuple[object, ...], ...],
    ) -> tuple[HeapLocation, ...]:
        return tuple(
            dict.fromkeys(
                location
                for storage in storages
                for location in self._canonicalize_storage(storage)
            )
        )

    def reference_count_for_root(self, root: HeapObject) -> int:
        """Count live logical local bindings that may reference *root*."""
        logical_bindings: set[tuple[object, ...]] = set()
        keys = set(self.storage_overrides) | set(self.allocation_sites)
        for key in keys:
            storage = self.storage_overrides.get(key)
            if storage is None:
                site = self.allocation_sites.get(key)
                storage = self.site_storage.get(site, ()) if site is not None else ()
            if not any(self.location_for_raw(raw).root == root for raw in storage):
                continue
            name = self._local_names.get(key)
            logical_bindings.add((key[0], name) if name is not None else key)
        return len(logical_bindings)

    def _is_immutable_type(self, root: HeapObject) -> bool:
        if (
            root.type_hint is not None
            and root.type_hint in self.policy.immutable_type_hints
        ):
            return True
        return False

    def _root_allocation_site(self, root: HeapObject) -> int | None:
        """Get the allocation-site id for a HeapObject root, if one exists."""
        if self._root_site_index is None:
            index: dict[HeapObject, int] = {}
            for site, storage in self.site_storage.items():
                for raw in storage:
                    index.setdefault(self.location_for_raw(raw).root, site)
            self._root_site_index = index
        return self._root_site_index.get(root)

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
        target_name = getattr(target, "name", None)
        source_name = getattr(source, "name", None)
        if isinstance(target_name, str):
            self._local_names[target_key] = target_name
        if isinstance(source_name, str):
            self._local_names[source_key] = source_name
        self.storage_overrides[target_key] = source_storage
        if isinstance(target_name, str):
            for raw in source_storage:
                location = self.location_for_raw(raw)
                # Prefer the most recently introduced source-level binding for
                # diagnostics.  Identity remains the shared SymbolId-backed
                # root; this label is presentation metadata only.
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
        name = getattr(local, "name", None)
        if isinstance(name, str):
            self._local_names[key] = name
        old_site = self.allocation_sites.get(key)
        if old_site is not None:
            self._decr_site_ref(old_site)
        self.storage_overrides.pop(key, None)
        raw = self._raw_storage_provider(procedure, local)
        self._assign_site(key, raw)

    def clear_local_binding(self, procedure: object, local: object) -> None:
        """Record that *local* currently contains no heap-relevant value."""
        if not self._is_named_local(local):
            return
        key = self._local_key(procedure, local)
        name = getattr(local, "name", None)
        if isinstance(name, str):
            self._local_names[key] = name
        old_site = self.allocation_sites.pop(key, None)
        if old_site is not None:
            self._decr_site_ref(old_site)
        self.storage_overrides[key] = ()
        if isinstance(name, str):
            proc_id = self._procedure_key(procedure)
            for other_key in list(self.storage_overrides):
                if (
                    other_key != key
                    and other_key[0] == proc_id
                    and self._local_names.get(other_key) == name
                ):
                    self.storage_overrides[other_key] = ()
                    other_site = self.allocation_sites.pop(other_key, None)
                    if other_site is not None:
                        self._decr_site_ref(other_site)

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
        proc_id = self._procedure_key(procedure)
        for (p_id, l_id), old_storage in list(self.storage_overrides.items()):
            if p_id != proc_id or (p_id, l_id) == except_key:
                continue
            if self._local_names.get((p_id, l_id)) != name:
                continue
            if not old_storage:
                continue
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
        include_provider_storage: bool = False,
    ) -> None:
        """Bind a local directly to an abstract object root."""
        if not self._is_named_local(local):
            return
        key = self._local_key(procedure, local)
        name = getattr(local, "name", None)
        if isinstance(name, str):
            self._local_names[key] = name
        old_site = self.allocation_sites.get(key)
        if old_site is not None:
            self._decr_site_ref(old_site)
        storage = (obj,)
        if include_provider_storage:
            storage = (*storage, *self._raw_storage_provider(procedure, local))
        self.storage_overrides[key] = storage
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
        include_provider_storage: bool = False,
    ) -> None:
        """Bind a local to existing abstract locations."""
        if not self._is_named_local(local):
            return
        storage = tuple(
            dict.fromkeys(self.location_for_raw(location) for location in locations)
        )
        if include_provider_storage:
            storage = (*storage, *self._raw_storage_provider(procedure, local))
        if not storage:
            return
        key = self._local_key(procedure, local)
        name = getattr(local, "name", None)
        if isinstance(name, str):
            self._local_names[key] = name
        self.storage_overrides[key] = storage
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
        include_provider_storage: bool = True,
    ) -> None:
        """Bind a callee formal to actual heap roots or to a parameter root."""
        if actual_locations:
            self.bind_local_to_locations(
                procedure,
                formal,
                actual_locations,
                include_provider_storage=include_provider_storage,
            )
            return
        label = getattr(formal, "name", None)
        self.bind_local_to_object(
            procedure,
            formal,
            self.parameter_object(procedure, index, label=label),
            include_provider_storage=include_provider_storage,
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
        include_provider_storage: bool = False,
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
                include_provider_storage=include_provider_storage,
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
        name = (
            label or getattr(local, "name", None) or self._describe_raw_storage(local)
        )
        key = ("local", self._procedure_key(procedure), self._local_key(procedure, local))
        return self._object(
            HeapObjectKind.LOCAL,
            key,
            str(name),
            freshness=HeapObjectFreshness.FRESH,
            cardinality=HeapObjectCardinality.ONE,
            identity=HeapObjectIdentity.SYMBOLIC,
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
        key = ("parameter", self._procedure_key(procedure), index)
        return self._object(
            HeapObjectKind.PARAMETER,
            key,
            label or f"param[{index}]",
            type_hint=type_hint,
            freshness=HeapObjectFreshness.UNKNOWN,
            cardinality=HeapObjectCardinality.UNKNOWN,
            identity=HeapObjectIdentity.SYMBOLIC,
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
        key = ("return", self._procedure_key(procedure), index)
        return self._object(
            HeapObjectKind.RETURN,
            key,
            label or f"return[{index}]",
            type_hint=type_hint,
            freshness=HeapObjectFreshness.UNKNOWN,
            cardinality=HeapObjectCardinality.UNKNOWN,
            identity=HeapObjectIdentity.SYMBOLIC,
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
        cardinality = (
            HeapObjectCardinality.ONE
            if self.policy.allocation_sensitivity is not AllocationSensitivity.NONE
            and self.policy.recency
            else HeapObjectCardinality.MANY
        )
        return self._object(
            HeapObjectKind.ALLOCATION,
            key,
            label or self._site_label("alloc", site),
            type_hint=type_hint,
            allocation_site=key,
            context=self._context_key(context),
            freshness=freshness,
            cardinality=cardinality,
            identity=(
                HeapObjectIdentity.SINGLETON
                if cardinality is HeapObjectCardinality.ONE
                else HeapObjectIdentity.SUMMARY
            ),
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
            cardinality=HeapObjectCardinality.UNKNOWN,
            identity=HeapObjectIdentity.SYMBOLIC,
            escape=HeapEscapeState.UNKNOWN,
        )

    def external_object(
        self,
        key: object,
        *,
        label: str | None = None,
        type_hint: str | None = None,
        stable_identity: bool = False,
    ) -> HeapObject:
        return self._object(
            HeapObjectKind.EXTERNAL,
            ("external", key),
            label or f"external:{key!r}",
            type_hint=type_hint,
            freshness=HeapObjectFreshness.UNKNOWN,
            cardinality=HeapObjectCardinality.UNKNOWN,
            identity=(
                HeapObjectIdentity.SYMBOLIC
                if stable_identity
                else HeapObjectIdentity.SUMMARY
            ),
            escape=HeapEscapeState.EXTERNAL,
        )

    def unknown_object(
        self,
        key: object,
        *,
        label: str | None = None,
        type_hint: str | None = None,
        identity: HeapObjectIdentity = HeapObjectIdentity.SUMMARY,
    ) -> HeapObject:
        """Return an explicit top-like reference root with stable provenance."""
        return self._object(
            HeapObjectKind.UNKNOWN,
            ("unknown", key),
            label or f"unknown:{key!r}",
            type_hint=type_hint,
            freshness=HeapObjectFreshness.UNKNOWN,
            cardinality=HeapObjectCardinality.UNKNOWN,
            identity=identity,
            escape=HeapEscapeState.UNKNOWN,
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
            cardinality=HeapObjectCardinality.ONE,
            identity=HeapObjectIdentity.SYMBOLIC,
            escape=HeapEscapeState.EXTERNAL,
        )

    def cell_object(
        self,
        name: object,
        *,
        label: str | None = None,
        type_hint: str | None = None,
    ) -> HeapObject:
        cell_name = getattr(name, "name", name)
        display = label or str(cell_name)
        has_identity = hasattr(name, "name")
        key = (
            (
                "cell-object",
                self._raw_location_key(name),
                cell_name,
            )
            if has_identity
            else ("cell-name", cell_name)
        )
        return self._object(
            HeapObjectKind.CELL,
            key,
            display,
            type_hint=type_hint,
            freshness=(
                HeapObjectFreshness.FRESH
                if has_identity
                else HeapObjectFreshness.SUMMARY
            ),
            cardinality=(
                HeapObjectCardinality.ONE
                if has_identity
                else HeapObjectCardinality.UNKNOWN
            ),
            identity=(
                HeapObjectIdentity.SYMBOLIC
                if has_identity
                else HeapObjectIdentity.SUMMARY
            ),
            escape=(HeapEscapeState.LOCAL if has_identity else HeapEscapeState.UNKNOWN),
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
            cardinality=HeapObjectCardinality.ONE,
            identity=HeapObjectIdentity.SYMBOLIC,
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
            cardinality=HeapObjectCardinality.MANY,
            identity=HeapObjectIdentity.SUMMARY,
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

    def to_points_to_graph(
        self,
        *,
        state: object | None = None,
        program_point_states: dict[object, tuple[object, object]] | None = None,
        program_point_outcomes: dict[object, dict[str, object]] | None = None,
        precision_degradations: dict[object, frozenset[str]] | None = None,
        operation_identities: dict[object, object] | None = None,
    ) -> "PointsToGraph":
        """Export heap state as a reusable :class:`PointsToGraph`.

        Extracts a read-only snapshot mapping every canonical root
        :class:`HeapLocation` to a :class:`PointsToEntry` with alias,
        escape, reference-count, and update-policy metadata.  The
        resulting graph is consumed by optimization passes and the
        semantic query API.
        """
        from .points_to import HeapValueSnapshot, PointsToEntry, PointsToGraph

        entries: dict[HeapLocation, PointsToEntry] = {}
        # Alias/reference-count queries may lazily intern summary objects.
        # Iterate over the entry snapshot so that does not invalidate export.
        for obj_key, obj in tuple(self._objects.items()):
            location = HeapLocation(obj)
            if location in entries:
                continue
            ref_count = self.reference_count_for_root(obj)
            escaped = obj in self._escaped_objects or obj.escape in {
                HeapEscapeState.ESCAPED,
                HeapEscapeState.EXTERNAL,
                HeapEscapeState.UNKNOWN,
            }
            entries[location] = PointsToEntry(
                location=location,
                label=self.display_label_for_location(location),
                aliases=self.aliased_locations(location),
                ref_count=ref_count,
                is_escaped=escaped,
                is_singleton=obj.is_singleton(),
                update_policy=self.update_policy_for_location(location),
                cardinality=obj.cardinality,
                identity=obj.identity,
            )
        values = getattr(state, "values", {}) if state is not None else {}
        contaminants = getattr(state, "contaminants", {}) if state is not None else {}
        point_values: dict[object, tuple[dict, dict]] = {}
        point_contaminants: dict[object, tuple[dict, dict]] = {}
        point_absent: dict[object, tuple[frozenset, frozenset]] = {}
        point_scalar_present: dict[object, tuple[frozenset, frozenset]] = {}
        point_complete_roots: dict[object, tuple[frozenset, frozenset]] = {}
        point_locals: dict[object, tuple[dict, dict]] = {}
        point_outcomes: dict[object, dict[str, HeapValueSnapshot]] = {}

        def heap_state(flow):
            return getattr(flow, "heap_state", flow)

        def local_values(flow) -> dict[tuple[object, str], frozenset[HeapLocation]]:
            environment = getattr(flow, "environment", None)
            if environment is None:
                return {}
            keys = set(environment.storage_overrides) | set(
                environment.allocation_sites
            )
            result: dict[tuple[object, str], set[HeapLocation]] = {}
            for key in keys:
                name = environment.local_names.get(key)
                if not name:
                    continue
                storage = self._environment_storage(environment, key)
                result.setdefault((key[0], name), set()).update(
                    self.location_for_raw(raw) for raw in storage
                )
            return {key: frozenset(locations) for key, locations in result.items()}

        def payloads(mapping) -> dict[object, frozenset[HeapLocation]]:
            return {
                self._procedure_key(procedure): frozenset(locations)
                for procedure, locations in mapping.items()
            }

        def return_payloads(mapping) -> dict[object, tuple[frozenset[HeapLocation], ...]]:
            return {
                self._procedure_key(procedure): tuple(frozenset(slot) for slot in slots)
                for procedure, slots in mapping.items()
            }

        for key, pair in (program_point_states or {}).items():
            before, after = pair
            before_heap = heap_state(before)
            after_heap = heap_state(after)
            point_values[key] = (
                {
                    location: frozenset(stored)
                    for location, stored in getattr(before_heap, "values", {}).items()
                },
                {
                    location: frozenset(stored)
                    for location, stored in getattr(after_heap, "values", {}).items()
                },
            )
            point_contaminants[key] = (
                {
                    location: frozenset(stored)
                    for location, stored in getattr(
                        before_heap, "contaminants", {}
                    ).items()
                },
                {
                    location: frozenset(stored)
                    for location, stored in getattr(
                        after_heap, "contaminants", {}
                    ).items()
                },
            )
            point_absent[key] = (
                frozenset(getattr(before_heap, "absent", ())),
                frozenset(getattr(after_heap, "absent", ())),
            )
            point_scalar_present[key] = (
                frozenset(getattr(before_heap, "scalar_present", ())),
                frozenset(getattr(after_heap, "scalar_present", ())),
            )
            point_complete_roots[key] = (
                frozenset(getattr(before_heap, "complete_roots", ())),
                frozenset(getattr(after_heap, "complete_roots", ())),
            )
            point_locals[key] = (local_values(before), local_values(after))
        for key, outcomes in (program_point_outcomes or {}).items():
            point_outcomes[key] = {
                label: HeapValueSnapshot(
                    values={
                        location: frozenset(stored)
                        for location, stored in getattr(
                            heap_state(outcome), "values", {}
                        ).items()
                    },
                    contaminants={
                        location: frozenset(stored)
                        for location, stored in getattr(
                            heap_state(outcome),
                            "contaminants",
                            {},
                        ).items()
                    },
                    absent=frozenset(getattr(heap_state(outcome), "absent", ())),
                    complete_roots=frozenset(
                        getattr(heap_state(outcome), "complete_roots", ())
                    ),
                    scalar_present=frozenset(
                        getattr(heap_state(outcome), "scalar_present", ())
                    ),
                    locals=local_values(outcome),
                    returns=return_payloads(
                        getattr(heap_state(outcome), "return_slots", {})
                    ),
                    yields=payloads(getattr(heap_state(outcome), "yields", {})),
                    raised=payloads(getattr(heap_state(outcome), "raised", {})),
                )
                for label, outcome in outcomes.items()
            }
        return PointsToGraph(
            entries=entries,
            allow_strong_nested_fresh=self.policy.allow_strong_nested_fresh,
            heap_values={
                location: frozenset(stored) for location, stored in values.items()
            },
            heap_contaminants={
                location: frozenset(stored) for location, stored in contaminants.items()
            },
            program_point_values=point_values,
            program_point_contaminants=point_contaminants,
            heap_absent=frozenset(getattr(state, "absent", ())),
            heap_scalar_present=frozenset(getattr(state, "scalar_present", ())),
            complete_roots=frozenset(getattr(state, "complete_roots", ())),
            program_point_absent=point_absent,
            program_point_scalar_present=point_scalar_present,
            program_point_complete_roots=point_complete_roots,
            program_point_outcomes=point_outcomes,
            program_point_locals=point_locals,
            precision_degradations=dict(precision_degradations or {}),
            operation_identities=dict(operation_identities or {}),
        )

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
    def _procedure_key(procedure: object) -> object:
        catalog = getattr(procedure, "ir_catalog", None)
        if catalog is not None:
            return catalog.procedure(procedure).code_id
        return procedure

    @staticmethod
    def _binding_sort_key(key: tuple[object, object]) -> tuple[object, ...]:
        def component(value: object) -> tuple[str, str, str]:
            name = getattr(value, "name", None)
            if name is None:
                code_name = getattr(value, "codeName", None)
                name = code_name() if callable(code_name) else str(value)
            return type(value).__module__, type(value).__qualname__, str(name)

        return component(key[0]), component(key[1])

    @staticmethod
    def _local_key(procedure: object, local: object) -> tuple[object, object]:
        catalog = getattr(procedure, "ir_catalog", None)
        if catalog is not None and catalog.has_symbol(local, procedure):
            return catalog.procedure(procedure).code_id, catalog.symbol_id(local, procedure)
        return procedure, local

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
        cardinality: HeapObjectCardinality = HeapObjectCardinality.UNKNOWN,
        identity: HeapObjectIdentity = HeapObjectIdentity.SUMMARY,
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
            cardinality.value,
            identity.value,
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
                cardinality=cardinality,
                identity=identity,
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
                    ("slot-local", self._raw_location_key(slot_name), label),
                    label,
                    freshness=HeapObjectFreshness.FRESH,
                    cardinality=HeapObjectCardinality.ONE,
                    identity=HeapObjectIdentity.SYMBOLIC,
                    escape=HeapEscapeState.LOCAL,
                )
            if hasattr(slot_name, "isExisting") and slot_name.isExisting():
                obj = getattr(slot_name, "object", None)
                label = self._object_label(obj) or str(slot_name)
                return self._object(
                    HeapObjectKind.GLOBAL,
                    (
                        "slot-existing",
                        self._raw_location_key(obj),
                        self._raw_location_key(slot_name),
                    ),
                    label,
                    freshness=HeapObjectFreshness.FRESH,
                    cardinality=HeapObjectCardinality.ONE,
                    identity=HeapObjectIdentity.SYMBOLIC,
                    escape=HeapEscapeState.EXTERNAL,
                )
        label = self._describe_raw_storage(raw)
        kind = HeapObjectKind.STORAGE
        freshness = HeapObjectFreshness.FRESH
        cardinality = HeapObjectCardinality.ONE
        escape = HeapEscapeState.LOCAL
        if isinstance(raw, LocalStorage):
            kind = HeapObjectKind.LOCAL
            label = str(raw.symbol)
            # A symbolic local may contain an arbitrary runtime object.  Only
            # allocation/call-result bindings establish singleton cardinality.
            freshness = HeapObjectFreshness.UNKNOWN
            cardinality = HeapObjectCardinality.UNKNOWN
        elif isinstance(raw, CellStorage):
            label = str(raw.symbol)
        elif isinstance(raw, GlobalStorage):
            kind = HeapObjectKind.GLOBAL
            label = f"{raw.module}.{raw.name}" if raw.module else raw.name
            escape = HeapEscapeState.EXTERNAL
        elif isinstance(raw, UnknownStorage):
            kind = HeapObjectKind.UNKNOWN
            label = raw.kind
            escape = HeapEscapeState.UNKNOWN
        raw_key = (
            ("storage", raw)
            if isinstance(raw, StorageLocation)
            else ("raw", self._raw_location_key(raw))
        )
        return self._object(
            kind,
            raw_key,
            label,
            freshness=freshness,
            cardinality=cardinality,
            identity=HeapObjectIdentity.SYMBOLIC,
            escape=escape,
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
            # In bounded programs the same syntactic site may execute through
            # multiple distinct call activations.  Retaining the activation
            # token prevents a multi-object site from being misclassified as
            # a singleton and used for unsound strong updates.
            return (
                (kind, self._site_identity(site, procedure), tuple(context))
                if context
                else (kind, self._site_identity(site, procedure))
            )
        if self.policy.allocation_sensitivity is AllocationSensitivity.PROCEDURE:
            return (
                kind,
                self._site_identity(procedure),
                self._site_identity(site, procedure),
            )
        return (
            kind,
            self._site_identity(procedure),
            self._site_identity(site, procedure),
            self._context_key(context),
        )

    def _site_identity(
        self, node: object, procedure: object | None = None
    ) -> object:
        if isinstance(node, tuple):
            return tuple(
                self._site_identity(item, procedure) for item in node
            )
        if isinstance(node, (str, bytes, int, float, bool, type(None))):
            return node
        catalog = getattr(node, "ir_catalog", None)
        if catalog is not None and catalog.has_procedure(node):
            return catalog.procedure(node).code_id
        catalog = getattr(procedure, "ir_catalog", None)
        if catalog is not None and catalog.has_node(node, procedure):
            return catalog.node_id(node, procedure)
        line = getattr(node, "line", None)
        column = getattr(node, "column", None)
        name = getattr(node, "name", None)
        if name is not None or line is not None or column is not None:
            return (
                type(node).__module__,
                type(node).__qualname__,
                name,
                line,
                column,
            )
        for ordinal, candidate in enumerate(self._opaque_sites):
            if candidate is node:
                return ("opaque-site", ordinal, type(node).__qualname__)
        ordinal = len(self._opaque_sites)
        self._opaque_sites.append(node)
        return ("opaque-site", ordinal, type(node).__qualname__)

    def _context_key(self, context: tuple[object, ...]) -> tuple[object, ...]:
        depth = self.policy.context_sensitivity_depth
        if depth <= 0:
            return ()
        return tuple(context[-depth:])

    def _site_label(self, prefix: str, site: object) -> str:
        line = getattr(site, "line", None)
        column = getattr(site, "column", None)
        if line is not None and column is not None:
            return f"{prefix}@{line}:{column}"
        if line is not None:
            return f"{prefix}@{line}"
        identity = self._site_identity(site)
        return f"{prefix}@{identity}"

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

    def _raw_location_key(self, raw: object) -> object:
        """Use value identity for typed storage and object identity otherwise."""
        if isinstance(raw, StorageLocation):
            return ("storage", raw)
        missing = object()
        pyobj = getattr(raw, "pyobj", missing)
        if pyobj is not missing and isinstance(
            pyobj, (str, bytes, int, float, bool, type(None))
        ):
            return ("literal", type(pyobj).__name__, pyobj)
        slot_name = getattr(raw, "slotName", None)
        if slot_name is not None:
            return (
                "slot",
                type(slot_name).__module__,
                type(slot_name).__qualname__,
                str(slot_name),
            )
        label = getattr(raw, "label", None)
        if isinstance(label, str):
            return ("labeled", type(raw).__module__, type(raw).__qualname__, label)
        for ordinal, candidate in enumerate(self._opaque_raw_objects):
            if candidate is raw:
                return ("opaque-storage", ordinal, type(raw).__qualname__)
        ordinal = len(self._opaque_raw_objects)
        self._opaque_raw_objects.append(raw)
        return ("opaque-storage", ordinal, type(raw).__qualname__)

    @staticmethod
    def _storage_subscript(key: object) -> str:
        if key == "*":
            return "[*]"
        if isinstance(key, str) and key.startswith("[") and key.endswith("]"):
            return key
        return f"[{key!r}]"

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
        if (
            len(subscript) < 3
            or not subscript.startswith("[")
            or not subscript.endswith("]")
        ):
            return None
        inner = subscript[1:-1]
        if not inner or inner == "*":
            return None
        if len(inner) >= 2 and inner[0] == inner[-1] and inner[0] in {"'", '"'}:
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
        name = getattr(local, "name", None)
        if isinstance(name, str):
            self._local_names[key] = name
        override = self.storage_overrides.get(key)
        if override is not None:
            return override
        site = self.allocation_sites.get(key)
        if site is not None:
            return self.site_storage[site]
        # Unindexed standalone IR may contain distinct Local objects for the
        # same source binding. Coalesce those occurrences by scope/name before
        # creating a new site; indexed IR reaches this through SymbolId keys.
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
        proc_id = self._procedure_key(procedure)
        # Prefer explicit key->name metadata. This distinguishes separate
        # locals that alias a value from distinct IR nodes for the same local.
        for key, storage in reversed(list(self.storage_overrides.items())):
            p_id, _l_id = key
            if p_id == proc_id and storage and self._local_names.get(key) == name:
                return storage
        for key, site in reversed(list(self.allocation_sites.items())):
            p_id, _l_id = key
            if p_id != proc_id or self._local_names.get(key) != name:
                continue
            stored = self.site_storage.get(site, ())
            if stored:
                return tuple(stored)
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
        if self._root_site_index is not None:
            for raw in storage:
                self._root_site_index.setdefault(
                    self.location_for_raw(raw).root,
                    site,
                )
        self._incr_site_ref(site)
