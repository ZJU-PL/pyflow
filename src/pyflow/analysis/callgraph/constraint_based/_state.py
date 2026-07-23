"""Abstract-state lookup and updates for names, objects, and containers."""

from __future__ import annotations

import ast
import warnings
from typing import Dict, Iterable, List, Mapping, Optional, Set, Tuple

from .model import (
    AbstractValue,
    CLASS_KIND,
    CONTAINER_KIND,
    FUNC_KIND,
    INSTANCE_KIND,
    MODULE_KIND,
    STRING_KIND,
    ScopeInfo,
    UNKNOWN_VALUE,
    instance_class_name,
    make_bound_class_method,
    make_bound_method,
    make_class,
    make_container,
    make_func,
    parse_instance_name,
)


class _StateAnalysisMixin:
    """Read and update abstract bindings, fields, containers, and MRO state."""

    def _assign_reflective_attribute(
        self,
        target_values: Set[AbstractValue],
        attr_names: Set[str],
        assigned_values: Set[AbstractValue],
    ) -> None:
        if not attr_names or not assigned_values:
            return

        for target_value in target_values:
            if target_value.kind == INSTANCE_KIND:
                for attr_name in attr_names:
                    current = self.instance_fields[target_value.name][attr_name]
                    before = len(current)
                    current.update(assigned_values)
                    if (
                        len(current) != before
                        and self._active_changed_instance_fields is not None
                    ):
                        self._active_changed_instance_fields.add(
                            (target_value.name, attr_name)
                        )
            elif target_value.kind == CLASS_KIND:
                for attr_name in attr_names:
                    current = self.class_fields[target_value.name][attr_name]
                    before = len(current)
                    current.update(assigned_values)
                    if (
                        len(current) != before
                        and self._active_changed_class_fields is not None
                    ):
                        self._active_changed_class_fields.add(
                            (target_value.name, attr_name)
                        )

    def _note_container_state_changed(
        self,
        container_name: str,
        key_name: str = "*",
    ) -> None:
        if self._active_changed_container_state is not None:
            self._active_changed_container_state.add((container_name, key_name))

    def _register_container_read(
        self,
        container_name: str,
        key_names: Set[str] | None = None,
    ) -> None:
        if key_names:
            for key_name in key_names:
                self._register_container_dependency(container_name, key_name)
            return
        self._register_container_dependency(container_name, "*")

    def _mark_container_key_maybe_missing(
        self,
        target_values: Iterable[AbstractValue],
        key_names: Set[str],
    ) -> None:
        normalized_keys = set(key_names) if key_names else {"*"}
        changed = False
        for target_value in target_values:
            if target_value.kind != CONTAINER_KIND:
                continue
            missing_keys = self.container_maybe_missing_keys[target_value.name]
            before = len(missing_keys)
            missing_keys.update(normalized_keys)
            changed = changed or len(missing_keys) != before
        if changed:
            for target_value in target_values:
                if target_value.kind != CONTAINER_KIND:
                    continue
                for key_name in normalized_keys:
                    self._note_container_state_changed(target_value.name, key_name)

    def _clear_container_key_maybe_missing(
        self,
        target_values: Iterable[AbstractValue],
        key_names: Set[str],
    ) -> None:
        if not key_names:
            return
        changed = False
        for target_value in target_values:
            if target_value.kind != CONTAINER_KIND:
                continue
            missing_keys = self.container_maybe_missing_keys.get(target_value.name)
            if not missing_keys:
                continue
            for key_name in key_names:
                if key_name in missing_keys:
                    missing_keys.discard(key_name)
                    changed = True
            if "*" in missing_keys:
                missing_keys.discard("*")
                changed = True
        if changed:
            for target_value in target_values:
                if target_value.kind != CONTAINER_KIND:
                    continue
                for key_name in key_names:
                    self._note_container_state_changed(target_value.name, key_name)
                self._note_container_state_changed(target_value.name, "*")

    def _container_key_maybe_missing(
        self,
        container_name: str,
        key_names: Set[str],
    ) -> bool:
        missing_keys = self.container_maybe_missing_keys.get(container_name, set())
        if not key_names:
            return bool(missing_keys)
        return "*" in missing_keys or any(
            key_name in missing_keys for key_name in key_names
        )

    def _mark_attribute_maybe_missing(
        self,
        target_values: Iterable[AbstractValue],
        attr_names: Set[str],
    ) -> None:
        for target_value in target_values:
            if target_value.kind == INSTANCE_KIND:
                missing_fields = self.instance_maybe_missing_fields[target_value.name]
                for attr_name in attr_names:
                    if attr_name in missing_fields:
                        continue
                    missing_fields.add(attr_name)
                    if self._active_changed_instance_fields is not None:
                        self._active_changed_instance_fields.add(
                            (target_value.name, attr_name)
                        )
            elif target_value.kind == CLASS_KIND:
                missing_fields = self.class_maybe_missing_fields[target_value.name]
                for attr_name in attr_names:
                    if attr_name in missing_fields:
                        continue
                    missing_fields.add(attr_name)
                    if self._active_changed_class_fields is not None:
                        self._active_changed_class_fields.add(
                            (target_value.name, attr_name)
                        )

    def _clear_attribute_maybe_missing(
        self,
        target_values: Iterable[AbstractValue],
        attr_names: Set[str],
    ) -> None:
        for target_value in target_values:
            if target_value.kind == INSTANCE_KIND:
                missing_fields = self.instance_maybe_missing_fields.get(
                    target_value.name
                )
                if not missing_fields:
                    continue
                for attr_name in attr_names:
                    missing_fields.discard(attr_name)
            elif target_value.kind == CLASS_KIND:
                missing_fields = self.class_maybe_missing_fields.get(target_value.name)
                if not missing_fields:
                    continue
                for attr_name in attr_names:
                    missing_fields.discard(attr_name)

    def _attribute_maybe_missing(
        self,
        target_values: Iterable[AbstractValue],
        attr_name: str,
    ) -> bool:
        for target_value in target_values:
            if target_value.kind == INSTANCE_KIND:
                instance_name = target_value.name
                if attr_name in self.instance_maybe_missing_fields.get(
                    instance_name, set()
                ):
                    return True
                for klass in self._class_lookup_order(
                    instance_class_name(target_value)
                ):
                    if attr_name in self.instance_maybe_missing_fields.get(
                        klass, set()
                    ):
                        return True
                    if attr_name in self.class_maybe_missing_fields.get(klass, set()):
                        return True
            elif target_value.kind == CLASS_KIND:
                for klass in self._class_lookup_order(target_value.name):
                    if attr_name in self.class_maybe_missing_fields.get(klass, set()):
                        return True
        return False

    def _assign_target(
        self,
        scope: ScopeInfo,
        target: ast.AST,
        values: Set[AbstractValue],
        env: Dict[str, Set[AbstractValue]],
        weak: bool = False,
        global_writes: Optional[Dict[str, Set[AbstractValue]]] = None,
        nonlocal_writes: Optional[Dict[str, Set[AbstractValue]]] = None,
        changed_instance_fields: Optional[Set[Tuple[str, str]]] = None,
        changed_class_fields: Optional[Set[Tuple[str, str]]] = None,
    ) -> bool:
        """
        Assign abstract values into a target (name, destructuring, attr, subscript).

        Returns `True` when heap-like field/container state changed.
        """
        if not values:
            values = {UNKNOWN_VALUE}

        if isinstance(target, ast.Name):
            if target.id in scope.global_names:
                self._merge_value_set(
                    env.setdefault(target.id, set()),
                    set(values),
                    preserve_callables=True,
                )
                if global_writes is not None:
                    self._merge_value_set(
                        global_writes.setdefault(target.id, set()),
                        set(values),
                        preserve_callables=True,
                    )
                return False
            if target.id in scope.nonlocal_names:
                self._merge_value_set(
                    env.setdefault(target.id, set()),
                    set(values),
                    preserve_callables=True,
                )
                if nonlocal_writes is not None:
                    self._merge_value_set(
                        nonlocal_writes.setdefault(target.id, set()),
                        set(values),
                        preserve_callables=True,
                    )
                self._propagate_nonlocal_write(target.id, set(values))
                return False
            self._merge_value_set(
                env.setdefault(target.id, set()),
                set(values),
                preserve_callables=True,
            )
            return False

        if isinstance(target, (ast.Tuple, ast.List)):
            starred_indices = [
                index
                for index, elt in enumerate(target.elts)
                if isinstance(elt, ast.Starred)
            ]
            indexed_values: Dict[int, Set[AbstractValue]] = {}
            for value in values:
                if value.kind != CONTAINER_KIND:
                    continue
                self._register_container_read(value.name)
                key_map = self.container_key_values.get(value.name, {})
                for key_name, key_values in key_map.items():
                    if not key_name.startswith("#"):
                        continue
                    try:
                        key_index = int(key_name[1:])
                    except ValueError:
                        continue
                    self._merge_value_set(
                        indexed_values.setdefault(key_index, set()),
                        set(key_values),
                        preserve_callables=True,
                    )

            if len(starred_indices) <= 1 and indexed_values:
                changed = False
                max_index = max(indexed_values)
                sequence_len = max_index + 1
                star_index = starred_indices[0] if starred_indices else None
                prefix_len = star_index if star_index is not None else len(target.elts)
                suffix_len = (
                    len(target.elts) - star_index - 1 if star_index is not None else 0
                )
                for elt_index, elt in enumerate(target.elts):
                    if isinstance(elt, ast.Starred):
                        start = prefix_len
                        end = max(start, sequence_len - suffix_len)
                        star_container_name = (
                            f"unpack:{scope.name}@{getattr(elt, 'lineno', -1)}:"
                            f"{getattr(elt, 'col_offset', -1)}:{start}:{end}"
                        )
                        star_container = make_container(star_container_name)
                        for src_index in range(start, end):
                            src_values = indexed_values.get(src_index, set())
                            if not src_values:
                                continue
                            self._merge_value_set(
                                self.container_elements[star_container.name],
                                set(src_values),
                                preserve_callables=True,
                            )
                            self._merge_value_set(
                                self.container_key_values[star_container.name][
                                    f"#{src_index - start}"
                                ],
                                set(src_values),
                                preserve_callables=True,
                            )
                        assign_values = (
                            {star_container}
                            if self.container_elements.get(star_container.name)
                            else {UNKNOWN_VALUE}
                        )
                        changed = (
                            self._assign_target(
                                scope,
                                elt.value,
                                assign_values,
                                env,
                                weak=weak,
                                global_writes=global_writes,
                                nonlocal_writes=nonlocal_writes,
                                changed_instance_fields=changed_instance_fields,
                                changed_class_fields=changed_class_fields,
                            )
                            or changed
                        )
                        continue

                    if star_index is None or elt_index < star_index:
                        src_index = elt_index
                    else:
                        src_index = sequence_len - (len(target.elts) - elt_index)
                    assign_values = indexed_values.get(src_index, set()) or {
                        UNKNOWN_VALUE
                    }
                    changed = (
                        self._assign_target(
                            scope,
                            elt,
                            assign_values,
                            env,
                            weak=weak,
                            global_writes=global_writes,
                            nonlocal_writes=nonlocal_writes,
                            changed_instance_fields=changed_instance_fields,
                            changed_class_fields=changed_class_fields,
                        )
                        or changed
                    )
                return changed

            changed = False
            item_values = self._iterable_members(values) or {UNKNOWN_VALUE}
            for elt in target.elts:
                changed = (
                    self._assign_target(
                        scope,
                        elt,
                        item_values,
                        env,
                        weak=weak,
                        global_writes=global_writes,
                        nonlocal_writes=nonlocal_writes,
                        changed_instance_fields=changed_instance_fields,
                        changed_class_fields=changed_class_fields,
                    )
                    or changed
                )
            return changed

        if isinstance(target, ast.Attribute):
            if isinstance(target.value, ast.Name):
                base_name = target.value.id
                if scope.method_self_param and base_name == scope.method_self_param:
                    receiver_instances = {
                        value.name
                        for value in env.get(base_name, set())
                        if value.kind == INSTANCE_KIND
                    }
                    if receiver_instances:
                        changed = False
                        for receiver_instance in receiver_instances:
                            current = self.instance_fields[receiver_instance][
                                target.attr
                            ]
                            did_change = self._merge_value_set(
                                current, set(values), preserve_callables=True
                            )
                            changed = changed or did_change
                            if did_change and changed_instance_fields is not None:
                                changed_instance_fields.add(
                                    (receiver_instance, target.attr)
                                )
                        return changed
                    owner = self._owner_class_for_scope(scope.name)
                    if owner:
                        current = self.instance_fields[owner][target.attr]
                        changed = self._merge_value_set(
                            current, set(values), preserve_callables=True
                        )
                        if changed and changed_instance_fields is not None:
                            changed_instance_fields.add((owner, target.attr))
                        return changed
                if scope.method_cls_param and base_name == scope.method_cls_param:
                    receiver_classes = {
                        value.name
                        for value in env.get(base_name, set())
                        if value.kind == CLASS_KIND
                    }
                    if receiver_classes:
                        changed = False
                        for receiver_class in receiver_classes:
                            current = self.class_fields[receiver_class][target.attr]
                            did_change = self._merge_value_set(
                                current, set(values), preserve_callables=True
                            )
                            changed = changed or did_change
                            if did_change and changed_class_fields is not None:
                                changed_class_fields.add((receiver_class, target.attr))
                        return changed
                    owner = self._owner_class_for_scope(scope.name)
                    if owner:
                        current = self.class_fields[owner][target.attr]
                        changed = self._merge_value_set(
                            current, set(values), preserve_callables=True
                        )
                        if changed and changed_class_fields is not None:
                            changed_class_fields.add((owner, target.attr))
                        return changed
                base_values = env.get(base_name, set())
                class_values = {v.name for v in base_values if v.kind == CLASS_KIND}
                instance_values = {
                    v.name for v in base_values if v.kind == INSTANCE_KIND
                }
                changed = False
                for class_name in class_values:
                    current = self.class_fields[class_name][target.attr]
                    did_change = self._merge_value_set(
                        current, set(values), preserve_callables=True
                    )
                    changed = changed or did_change
                    if did_change and changed_class_fields is not None:
                        changed_class_fields.add((class_name, target.attr))
                for instance_or_class_name in instance_values:
                    current = self.instance_fields[instance_or_class_name][target.attr]
                    did_change = self._merge_value_set(
                        current, set(values), preserve_callables=True
                    )
                    changed = changed or did_change
                    if did_change and changed_instance_fields is not None:
                        changed_instance_fields.add(
                            (instance_or_class_name, target.attr)
                        )
                return changed
            return False

        if isinstance(target, ast.Subscript):
            base_values: Set[AbstractValue] = set()
            if isinstance(target.value, ast.Name):
                base_values = set(env.get(target.value.id, set()))
            elif isinstance(target.value, ast.Subscript) and isinstance(
                target.value.value, ast.Name
            ):
                parent_values = set(env.get(target.value.value.id, set()))
                parent_keys = self._subscript_keys(target.value)
                for parent_value in parent_values:
                    if parent_value.kind != CONTAINER_KIND:
                        continue
                    self._register_container_read(parent_value.name, parent_keys)
                    parent_key_map = self.container_key_values.get(
                        parent_value.name, {}
                    )
                    nested_values: Set[AbstractValue] = set()
                    if parent_keys:
                        for key_name in parent_keys:
                            nested_values.update(parent_key_map.get(key_name, set()))
                    else:
                        self._register_container_read(parent_value.name)
                        nested_values.update(
                            self.container_elements.get(parent_value.name, set())
                        )
                    base_values.update(
                        value for value in nested_values if value.kind == CONTAINER_KIND
                    )
            key_names = self._subscript_keys(target)
            changed = False
            for base_value in base_values:
                if base_value.kind != CONTAINER_KIND:
                    continue
                current = self.container_elements[base_value.name]
                container_elements_changed = self._merge_value_set(
                    current, set(values), preserve_callables=True
                )
                changed = container_elements_changed or changed
                if container_elements_changed:
                    self._note_container_state_changed(base_value.name, "*")
                for key_name in key_names:
                    keyed_current = self.container_key_values[base_value.name][key_name]
                    if weak:
                        key_changed = self._merge_value_set(
                            keyed_current, set(values), preserve_callables=True
                        )
                        changed = key_changed or changed
                        if key_changed:
                            self._note_container_state_changed(
                                base_value.name, key_name
                            )
                    else:
                        replacement = self._cap_values(
                            set(values), preserve_callables=True
                        )
                        if keyed_current != replacement:
                            self.container_key_values[base_value.name][
                                key_name
                            ] = replacement
                            changed = True
                            self._note_container_state_changed(
                                base_value.name, key_name
                            )
            if key_names:
                self._clear_container_key_maybe_missing(base_values, key_names)
            return changed

        return False

    def _class_lookup_order(self, class_name: str) -> List[str]:
        """
        Return class lookup order.

        Uses C3 MRO when available; falls back to conservative BFS order for
        classes with invalid/inconsistent MRO.
        """
        if class_name in self._invalid_mro_classes:
            queue = [class_name]
            seen: Set[str] = set()
            order: List[str] = []
            while queue:
                current = queue.pop(0)
                if current in seen:
                    continue
                seen.add(current)
                order.append(current)
                class_info = self.classes.get(current)
                if class_info:
                    queue.extend(class_info.bases)
            return order
        return self._mro(class_name)

    def _lookup_name(
        self,
        module_name: str,
        name: str,
        env: Mapping[str, Set[AbstractValue]],
    ) -> Set[AbstractValue]:
        """Resolve symbol from environment or builtin callable namespace."""
        self._register_module_dependency(module_name)
        if name in env:
            return set(env[name])
        if name in self._builtin_callable_names:
            return {make_func(f"<builtin>.{name}")}
        return set()

    def _descriptor_bind_values(
        self,
        values: Iterable[AbstractValue],
        owner_class: Optional[str],
        instance_class: Optional[str],
    ) -> Set[AbstractValue]:
        """Apply descriptor `__get__`-style binding to attribute values."""
        out: Set[AbstractValue] = set()
        for value in values:
            if value.kind == FUNC_KIND:
                if instance_class is not None:
                    out.add(make_bound_method(value.name, instance_class))
                else:
                    out.add(value)
                continue

            if value.kind == INSTANCE_KIND:
                descriptor_class, _descriptor_alloc = parse_instance_name(value.name)
                descriptor_mro = self._mro(descriptor_class)
                for descriptor_class in descriptor_mro:
                    descriptor_info = self.classes.get(descriptor_class)
                    if not descriptor_info:
                        continue
                    get_method = descriptor_info.methods.get("__get__")
                    if not get_method:
                        continue
                    if instance_class is not None:
                        out.add(make_bound_method(get_method, value.name))
                    else:
                        out.add(make_bound_class_method(get_method, value.name))
                    break
                out.add(value)
                continue

            out.add(value)
        return out

    def _resolve_attribute(
        self, base_values: Iterable[AbstractValue], attr_name: str
    ) -> Set[AbstractValue]:
        """
        Resolve attribute access over modules/classes/instances/containers.

        Also records dependency edges so future field/module updates can requeue
        impacted scopes.
        """
        out: Set[AbstractValue] = set()

        for base_value in base_values:
            if base_value.kind == STRING_KIND:
                if attr_name in {"join", "split"}:
                    out.add(make_func(f"<**PyStr**>.{attr_name}"))
                continue

            if base_value.kind == MODULE_KIND:
                self._register_module_dependency(base_value.name)
                module_bindings = self.module_bindings.get(base_value.name)
                if module_bindings and attr_name in module_bindings:
                    out.update(module_bindings[attr_name])
                else:
                    out.add(make_func(f"{base_value.name}.{attr_name}"))

            elif base_value.kind == CLASS_KIND:
                class_order = self._class_lookup_order(base_value.name)
                stop_after_first = base_value.name not in self._invalid_mro_classes
                for klass in class_order:
                    class_info = self.classes.get(klass)
                    if not class_info or attr_name not in class_info.methods:
                        continue
                    method_name = class_info.methods[attr_name]
                    if attr_name in class_info.static_methods:
                        out.add(make_func(method_name))
                    elif attr_name in class_info.class_methods:
                        out.add(make_bound_class_method(method_name, base_value.name))
                    else:
                        out.add(make_bound_method(method_name, base_value.name))
                    if stop_after_first:
                        break

                for klass in class_order:
                    self._register_class_field_dependency(klass, attr_name)
                    class_attr_values = self.class_fields.get(klass, {}).get(
                        attr_name, set()
                    )
                    out.update(
                        self._descriptor_bind_values(
                            class_attr_values,
                            owner_class=base_value.name,
                            instance_class=None,
                        )
                    )
                nested_class = f"{base_value.name}.{attr_name}"
                if nested_class in self.classes:
                    out.add(make_class(nested_class))

            elif base_value.kind == INSTANCE_KIND:
                base_instance_name = base_value.name
                base_class_name = instance_class_name(base_value)
                class_order = self._class_lookup_order(base_class_name)
                stop_after_first = base_class_name not in self._invalid_mro_classes
                for klass in class_order:
                    class_info = self.classes.get(klass)
                    if class_info and attr_name in class_info.methods:
                        method_name = class_info.methods[attr_name]
                        if attr_name in class_info.static_methods:
                            out.add(make_func(method_name))
                        elif attr_name in class_info.class_methods:
                            out.add(
                                make_bound_class_method(method_name, base_class_name)
                            )
                        else:
                            out.add(make_bound_method(method_name, base_instance_name))
                        if stop_after_first:
                            break
                    if class_info is None and "." in klass:
                        out.add(make_func(f"{klass}.{attr_name}"))
                self._register_instance_field_dependency(base_instance_name, attr_name)
                out.update(
                    self.instance_fields.get(base_instance_name, {}).get(
                        attr_name, set()
                    )
                )
                for klass in class_order:
                    self._register_instance_field_dependency(klass, attr_name)
                    out.update(
                        self.instance_fields.get(klass, {}).get(attr_name, set())
                    )
                    self._register_class_field_dependency(klass, attr_name)
                    class_attr_values = self.class_fields.get(klass, {}).get(
                        attr_name, set()
                    )
                    out.update(
                        self._descriptor_bind_values(
                            class_attr_values,
                            owner_class=klass,
                            instance_class=base_value.name,
                        )
                    )
                if (
                    not out
                    and base_class_name.startswith("dict:")
                    and attr_name == "items"
                ):
                    out.add(make_func("<**PyDict**>.items"))
                if (
                    not out
                    and base_class_name.startswith("dict:")
                    and attr_name == "update"
                ):
                    out.add(make_func("<**PyDict**>.update"))
                if (
                    not out
                    and base_class_name.startswith("dict:")
                    and attr_name == "setdefault"
                ):
                    out.add(make_func("<**PyDict**>.setdefault"))
                if (
                    not out
                    and base_class_name.startswith("dict:")
                    and attr_name == "pop"
                ):
                    out.add(make_func("<**PyDict**>.pop"))
                if (
                    not out
                    and base_class_name.startswith("dict:")
                    and attr_name == "get"
                ):
                    out.add(make_func("<**PyDict**>.get"))

            elif base_value.kind == CONTAINER_KIND:
                if base_value.name.startswith("dict:"):
                    if attr_name == "items":
                        out.add(make_func("<**PyDict**>.items"))
                    elif attr_name == "update":
                        out.add(make_func("<**PyDict**>.update"))
                    elif attr_name == "setdefault":
                        out.add(make_func("<**PyDict**>.setdefault"))
                    elif attr_name == "pop":
                        out.add(make_func("<**PyDict**>.pop"))
                    elif attr_name == "get":
                        out.add(make_func("<**PyDict**>.get"))

        return out

    def _owner_class_for_scope(self, scope_name: str) -> Optional[str]:
        function_info = self.functions.get(scope_name)
        if not function_info:
            return None
        return function_info.owner_class

    def _mro(self, class_name: str) -> List[str]:
        """Compute and cache class MRO (C3) with conservative fallback on failure."""
        if class_name in self._mro_cache:
            return list(self._mro_cache[class_name])

        class_info = self.classes.get(class_name)
        if not class_info:
            self._mro_cache[class_name] = [class_name]
            return [class_name]

        base_mros = [self._mro(base) for base in class_info.bases]
        merge_input = [list(seq) for seq in base_mros]
        merge_input.append(list(class_info.bases))

        linearized: List[str] = [class_name]
        merged = self._c3_merge(merge_input)
        if merged is None:
            self._invalid_mro_classes.add(class_name)
            warnings.warn(
                (
                    f"Inconsistent MRO detected for {class_name}; "
                    "falling back to conservative attribute dispatch."
                ),
                RuntimeWarning,
                stacklevel=2,
            )
            seen = {class_name}
            queue = list(class_info.bases)
            while queue:
                base = queue.pop(0)
                if base in seen:
                    continue
                seen.add(base)
                linearized.append(base)
                base_info = self.classes.get(base)
                if base_info:
                    queue.extend(base_info.bases)
        else:
            linearized.extend(merged)
        self._mro_cache[class_name] = list(linearized)
        return linearized

    def _c3_merge(self, sequences: List[List[str]]) -> Optional[List[str]]:
        """C3 merge step used by `_mro`; returns None when constraints conflict."""
        result: List[str] = []
        pending = [list(seq) for seq in sequences if seq]

        while pending:
            candidate: Optional[str] = None
            for seq in pending:
                head = seq[0]
                if any(head in other[1:] for other in pending):
                    continue
                candidate = head
                break

            if candidate is None:
                return None

            result.append(candidate)
            next_pending: List[List[str]] = []
            for seq in pending:
                filtered = [name for name in seq if name != candidate]
                if filtered:
                    next_pending.append(filtered)
            pending = next_pending

        return result
