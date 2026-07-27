"""Alias, call-effect, and container state helpers for local taint analysis."""

from __future__ import annotations

import ast
from typing import List, Optional, Set


class _TaintStateMixin:
    def _handle_container_calls(self, node: ast.Call):
        if not isinstance(node.func, ast.Attribute):
            return
        method = node.func.attr
        container_name = self._attribute_name(node.func.value)

        # Mutating container APIs.
        if method == "append":
            if not node.args:
                return
            value = node.args[0]
            if container_name in self.list_lengths:
                idx = self.list_lengths[container_name]
                self.list_lengths[container_name] = idx + 1
                idx_key = str(idx)
                if isinstance(value, (ast.Dict, ast.List, ast.Tuple)):
                    self._record_literal_taint_paths((container_name, idx_key), value)
                elif self._expr_is_tainted(value):
                    self._record_tainted_path((container_name, idx_key))
                if self._expr_is_tainted(value):
                    self._mark_container_key_tainted(container_name, idx_key)
            else:
                # Unknown index: conservatively taint an unknown element.
                if self._expr_is_tainted(value):
                    self._mark_container_key_tainted(container_name, None)
        elif method in {"extend", "insert"}:
            # Unknown or shifted indices conservatively taint an unknown
            # element when inputs are tainted.
            if any(self._expr_is_tainted(arg) for arg in node.args):
                self._mark_container_key_tainted(container_name, None)
        elif method == "add":
            # Sets can be tracked by element identity when it's syntactically simple.
            if node.args:
                elem = node.args[0]
                if self._expr_is_tainted(elem):
                    key = self._subscript_key(elem)
                    self._mark_container_key_tainted(
                        container_name, key if key is not None else None
                    )
        elif method in {"update"}:
            # dict.update(other) / set.update(iterable) / list.extend(iterable)
            # Conservatively treat tainted inputs as tainting an unknown key/element.
            if any(self._expr_is_tainted(arg) for arg in node.args) or any(
                self._expr_is_tainted(kwd.value) for kwd in node.keywords
            ):
                self._mark_container_key_tainted(container_name, None)
        elif method in {"setdefault"}:
            # setdefault(key, default) writes when missing; conservatively
            # treat a tainted key/default as tainting an unknown key.
            key_expr = node.args[0] if node.args else None
            default_expr = node.args[1] if len(node.args) > 1 else None
            if (key_expr is not None and self._expr_is_tainted(key_expr)) or (
                default_expr is not None and self._expr_is_tainted(default_expr)
            ):
                self._mark_container_key_tainted(container_name, None)
        elif method == "clear":
            for name in self._aliases_for(container_name):
                self.tainted_containers.discard(name)
                self.tainted_container_keys.pop(name, None)
                self.tainted_dict_keys.pop(name, None)
                self._clear_paths_for_root(name)
                if name in self.list_lengths:
                    self.list_lengths[name] = 0
                self.dict_key_order.pop(name, None)
        elif method == "discard":
            # discard removes a specific element from a set.
            if node.args:
                key = self._subscript_key(node.args[0])
                if key is not None:
                    self._clear_container_key(container_name, key)
        elif method == "pop":
            # pop removes and returns an arbitrary element
            # If the set is tainted, the popped element is tainted
            pass
        elif method == "remove":
            # remove is like discard but raises KeyError if not found
            # Same logic as discard
            pass

    def _collect_match_bindings(self, pattern: ast.pattern) -> Set[str]:
        names: Set[str] = set()
        if isinstance(pattern, ast.MatchAs):
            if pattern.name:
                names.add(pattern.name)
            if pattern.pattern:
                names.update(self._collect_match_bindings(pattern.pattern))
        elif isinstance(pattern, ast.MatchStar):
            if pattern.name:
                names.add(pattern.name)
        elif isinstance(pattern, ast.MatchMapping):
            for subpattern in pattern.patterns:
                names.update(self._collect_match_bindings(subpattern))
            if pattern.rest:
                names.add(pattern.rest)
        elif isinstance(pattern, ast.MatchSequence):
            for subpattern in pattern.patterns:
                names.update(self._collect_match_bindings(subpattern))
        elif isinstance(pattern, ast.MatchClass):
            for subpattern in pattern.patterns:
                names.update(self._collect_match_bindings(subpattern))
            for subpattern in pattern.kwd_patterns:
                names.update(self._collect_match_bindings(subpattern))
        return names

    def _binding_captures_subject(
        self, pattern: ast.pattern, binding_name: str, subject_is_tainted: bool
    ) -> bool:
        if not subject_is_tainted:
            return False
        if isinstance(pattern, ast.MatchAs):
            if pattern.name == binding_name:
                return True
            if pattern.pattern:
                return self._binding_captures_subject(
                    pattern.pattern, binding_name, subject_is_tainted
                )
        return False

    def _apply_callee_param_taint_outputs(self, node: ast.Call, callee: str) -> None:
        outputs = self.callee_param_taint_outputs.get(callee, set())
        # Apply receiver (`self`) taint outputs for instance methods.
        full_params = self.callee_param_names.get(callee, [])
        if (
            isinstance(node.func, ast.Attribute)
            and full_params
            and full_params[0] in {"self", "cls"}
            and full_params[0] in outputs
        ):
            for name in self._names_in_expr(node.func.value):
                self._mark_container_tainted(name)
        param_names = self._callee_param_names(node, callee)
        for idx, arg in enumerate(node.args):
            if isinstance(arg, ast.Starred):
                if idx < len(param_names) and param_names[idx] in outputs:
                    for name in self._names_in_expr(arg.value):
                        self._mark_container_tainted(name)
                continue
            if idx < len(param_names) and param_names[idx] in outputs:
                for name in self._names_in_expr(arg):
                    self._mark_container_tainted(name)
        for kwd in node.keywords:
            if kwd.arg and kwd.arg in outputs:
                for name in self._names_in_expr(kwd.value):
                    self._mark_container_tainted(name)
        self._apply_callee_param_key_effects(node, callee)

    def _apply_callee_param_key_effects(self, node: ast.Call, callee: str) -> None:
        writes = self.callee_param_key_writes.get(callee, {})
        taint_writes = self.callee_param_key_taint_writes.get(callee, {})
        if not writes and not taint_writes:
            return

        # Apply receiver (`self`) field effects for instance methods.
        full_params = self.callee_param_names.get(callee, [])
        if (
            isinstance(node.func, ast.Attribute)
            and full_params
            and full_params[0] in {"self", "cls"}
        ):
            self_param = full_params[0]
            keys = writes.get(self_param, set())
            tainted_keys = taint_writes.get(self_param, set())
            if keys or tainted_keys:
                self._apply_param_field_effects_to_names(
                    self._names_in_expr(node.func.value), keys, tainted_keys
                )

        param_names = self._callee_param_names(node, callee)
        for idx, arg in enumerate(node.args):
            if idx >= len(param_names):
                break
            param = param_names[idx]
            keys = writes.get(param, set())
            tainted_keys = taint_writes.get(param, set())
            if not keys and not tainted_keys:
                continue
            self._apply_param_field_effects_to_arg(arg, keys, tainted_keys)
        for kwd in node.keywords:
            if kwd.arg is None:
                continue
            param = kwd.arg
            keys = writes.get(param, set())
            tainted_keys = taint_writes.get(param, set())
            if not keys and not tainted_keys:
                continue
            self._apply_param_field_effects_to_arg(kwd.value, keys, tainted_keys)

    def _apply_param_field_effects_to_arg(
        self, arg: ast.AST, keys: Set[str], tainted_keys: Set[str]
    ) -> None:
        self._apply_param_field_effects_to_names(
            self._names_in_expr(arg), keys, tainted_keys
        )

    def _apply_param_field_effects_to_names(
        self, names: Set[str], keys: Set[str], tainted_keys: Set[str]
    ) -> None:
        for name in names:
            alias_key = self._alias_key(name)
            for key in tainted_keys:
                if key == "*":
                    self.tainted_attrs.setdefault(alias_key, set()).add("*")
                    self._mark_container_key_tainted(name, None)
                else:
                    self.tainted_attrs.setdefault(alias_key, set()).add(key)
                    self._mark_container_key_tainted(name, key)
            for key in keys - tainted_keys:
                if key == "*":
                    continue
                attrs = self.tainted_attrs.get(alias_key)
                if attrs:
                    attrs.discard(key)
                self._clear_container_key(name, key)

    def _names_in_expr(self, expr: ast.AST) -> Set[str]:
        if isinstance(expr, ast.Name):
            return {expr.id}
        if isinstance(expr, ast.Attribute):
            base = self._expr_base_name(expr)
            return {base} if base else set()
        if isinstance(expr, ast.Subscript):
            base = self._subscript_base_name(expr.value)
            return {base} if base else set()
        return set()

    def _record_param_key_write(
        self, base: str, key: Optional[str], tainted: bool
    ) -> None:
        param = self._param_name_for(base)
        if not param:
            return
        key_name = key if key is not None else "*"
        self.param_key_writes.setdefault(param, set()).add(key_name)
        if tainted:
            self.param_key_taint_writes.setdefault(param, set()).add(key_name)

    def _ensure_alias(self, name: str) -> None:
        if name not in self.alias_parent:
            self.alias_parent[name] = name
            self.alias_members[name] = {name}

    def _find_alias(self, name: str) -> str:
        self._ensure_alias(name)
        parent = self.alias_parent[name]
        if parent != name:
            parent = self._find_alias(parent)
            self.alias_parent[name] = parent
        return parent

    def _union_alias(self, left: str, right: str) -> None:
        left_root = self._find_alias(left)
        right_root = self._find_alias(right)
        if left_root == right_root:
            return
        left_members = self.alias_members.get(left_root, {left_root})
        right_members = self.alias_members.get(right_root, {right_root})
        if len(left_members) < len(right_members):
            left_root, right_root = right_root, left_root
            left_members, right_members = right_members, left_members
        self.alias_parent[right_root] = left_root
        left_members.update(right_members)
        self.alias_members[left_root] = left_members
        self.alias_members.pop(right_root, None)
        if any(member in self.tainted_containers for member in left_members):
            for member in left_members:
                self.tainted_containers.add(member)
        for member in left_members:
            if member in self.tainted_container_keys:
                self._merge_container_keys(left_root, member)
            if member in self.tainted_dict_keys:
                self._merge_dict_keys(left_root, member)

    def _aliases_for(self, name: str) -> Set[str]:
        root = self._find_alias(name)
        return set(self.alias_members.get(root, {name}))

    def _alias_key(self, name: str) -> str:
        return self._find_alias(name)

    def _mark_container_tainted(self, name: str) -> None:
        for alias in self._aliases_for(name):
            self.tainted_containers.add(alias)

    def _is_container_tainted(self, name: str) -> bool:
        for alias in self._aliases_for(name):
            if alias in self.tainted_containers:
                return True
            keys = self.tainted_container_keys.get(alias)
            if keys:
                return True
            dkeys = self.tainted_dict_keys.get(alias)
            if dkeys:
                return True
        return False

    def _is_container_values_tainted(self, name: str) -> bool:
        for alias in self._aliases_for(name):
            if alias in self.tainted_containers:
                return True
            keys = self.tainted_container_keys.get(alias)
            if keys:
                return True
        return False

    def _is_container_keys_tainted(self, name: str) -> bool:
        for alias in self._aliases_for(name):
            dkeys = self.tainted_dict_keys.get(alias)
            if dkeys:
                return True
        return False

    def _is_container_key_tainted(self, name: str, key: Optional[str]) -> bool:
        for alias in self._aliases_for(name):
            if alias in self.tainted_containers:
                return True
            keys = self.tainted_container_keys.get(alias, set())
            if not keys:
                continue
            if key is None:
                return "*" in keys
            if "*" in keys or key in keys:
                return True
        return False

    def _mark_container_key_tainted(self, name: str, key: Optional[str]) -> None:
        for alias in self._aliases_for(name):
            self._ensure_container_key(alias, key)

    def _clear_container_key(self, name: str, key: Optional[str]) -> None:
        for alias in self._aliases_for(name):
            if alias not in self.tainted_container_keys:
                continue
            if key is None:
                self.tainted_container_keys.pop(alias, None)
                continue
            keys = self.tainted_container_keys[alias]
            keys.discard(key)
            if not keys:
                self.tainted_container_keys.pop(alias, None)

    def _ensure_container_key(self, name: str, key: Optional[str]) -> None:
        if key is None:
            self.tainted_container_keys.setdefault(name, set()).add("*")
            return
        self.tainted_container_keys.setdefault(name, set()).add(key)

    def _merge_container_keys(self, root: str, member: str) -> None:
        keys = self.tainted_container_keys.get(member)
        if not keys:
            return
        self.tainted_container_keys.setdefault(root, set()).update(keys)
        if member != root:
            self.tainted_container_keys.pop(member, None)

    def _mark_dict_key_tainted(self, name: str, key: Optional[str]) -> None:
        for alias in self._aliases_for(name):
            self._ensure_dict_key(alias, key)

    def _clear_dict_key(self, name: str, key: Optional[str]) -> None:
        for alias in self._aliases_for(name):
            if alias not in self.tainted_dict_keys:
                continue
            if key is None:
                self.tainted_dict_keys.pop(alias, None)
                continue
            keys = self.tainted_dict_keys[alias]
            keys.discard(key)
            if not keys:
                self.tainted_dict_keys.pop(alias, None)

    def _ensure_dict_key(self, name: str, key: Optional[str]) -> None:
        if key is None:
            self.tainted_dict_keys.setdefault(name, set()).add("*")
            return
        self.tainted_dict_keys.setdefault(name, set()).add(key)

    def _merge_dict_keys(self, root: str, member: str) -> None:
        keys = self.tainted_dict_keys.get(member)
        if not keys:
            return
        self.tainted_dict_keys.setdefault(root, set()).update(keys)
        if member != root:
            self.tainted_dict_keys.pop(member, None)

    def _clear_container_taint(self, name: str) -> None:
        self.tainted_containers.discard(name)
        self.tainted_container_keys.pop(name, None)
        self.tainted_dict_keys.pop(name, None)
        self.list_lengths.pop(name, None)
        self.dict_key_order.pop(name, None)
        self._clear_paths_for_root(name)

    def _update_container_from_expr(self, name: str, expr: ast.AST) -> None:
        # Track dict-key taint separately to distinguish keys() from values().
        if isinstance(expr, ast.Dict):
            for k, v in zip(expr.keys, expr.values):
                if k is None:
                    # dict unpacking (**x): propagate tainted keys when available.
                    if isinstance(v, ast.Name):
                        source = v.id
                        if self._is_container_keys_tainted(source):
                            merged: Set[str] = set()
                            for alias in self._aliases_for(source):
                                merged.update(self.tainted_dict_keys.get(alias, set()))
                            if "*" in merged:
                                self._mark_dict_key_tainted(name, None)
                            else:
                                for key in merged:
                                    self._mark_dict_key_tainted(name, key)
                    elif self._expr_is_tainted(v):
                        self._mark_dict_key_tainted(name, None)
                else:
                    if self._expr_is_tainted(k):
                        self._mark_dict_key_tainted(name, None)

        keys = self._tainted_container_keys(expr)
        if keys is not None:
            for key in keys:
                self._mark_container_key_tainted(name, key)
        else:
            self._mark_container_tainted(name)

    def _tainted_container_keys(self, expr: ast.AST) -> Optional[Set[str]]:
        if isinstance(expr, ast.Dict):
            tainted_keys: Set[str] = set()
            for k, v in zip(expr.keys, expr.values):
                if k is None:
                    # Preserve per-key source-map taint across dict unpacking.
                    if isinstance(v, ast.Name):
                        source = v.id
                        if self._is_container_values_tainted(source):
                            if source in self.tainted_containers:
                                tainted_keys.add("*")
                            else:
                                merged: Set[str] = set()
                                for alias in self._aliases_for(source):
                                    merged.update(
                                        self.tainted_container_keys.get(alias, set())
                                    )
                                if "*" in merged:
                                    tainted_keys.add("*")
                                else:
                                    tainted_keys.update(merged)
                    elif self._expr_is_tainted(v):
                        tainted_keys.add("*")
                    continue

                value_is_tainted = self._expr_is_tainted(v)
                if not value_is_tainted:
                    continue

                key = self._subscript_key(k)
                if key is None:
                    tainted_keys.add("*")
                else:
                    tainted_keys.add(key)

            return tainted_keys or None

        if isinstance(expr, (ast.List, ast.Tuple)):
            tainted_indices: Set[str] = set()
            cur_index = 0
            for elt in expr.elts:
                if isinstance(elt, ast.Starred):
                    # Model `[*xs]` precisely when per-index taint and length
                    # information are available.
                    if isinstance(elt.value, ast.Name):
                        src = elt.value.id
                        merged_keys: Set[str] = set()
                        for alias in self._aliases_for(src):
                            merged_keys.update(
                                self.tainted_container_keys.get(alias, set())
                            )
                        if src in self.tainted_containers or "*" in merged_keys:
                            tainted_indices.add("*")
                            return tainted_indices
                        for k in merged_keys:
                            if k.isdigit():
                                tainted_indices.add(str(cur_index + int(k)))
                            else:
                                tainted_indices.add("*")
                                return tainted_indices
                        if src in self.list_lengths:
                            cur_index += self.list_lengths[src]
                        else:
                            # With unknown length, later indices become
                            # unknown after observed taint.
                            if merged_keys:
                                tainted_indices.add("*")
                                return tainted_indices
                    elif isinstance(elt.value, (ast.List, ast.Tuple)):
                        inner = self._tainted_container_keys(elt.value) or set()
                        if "*" in inner:
                            tainted_indices.add("*")
                            return tainted_indices
                        for k in inner:
                            if k.isdigit():
                                tainted_indices.add(str(cur_index + int(k)))
                            else:
                                tainted_indices.add("*")
                                return tainted_indices
                        cur_index += len(getattr(elt.value, "elts", []))
                    else:
                        if self._expr_is_tainted(elt.value):
                            tainted_indices.add("*")
                            return tainted_indices
                    continue

                if self._expr_is_tainted(elt):
                    tainted_indices.add(str(cur_index))
                cur_index += 1

            return tainted_indices or None

        if isinstance(expr, ast.Set):
            tainted_elems: Set[str] = set()
            for elt in expr.elts:
                if self._expr_is_tainted(elt):
                    key = self._subscript_key(elt)
                    tainted_elems.add(key if key is not None else "*")
            return tainted_elems or None

        return None

    def _callee_param_names(self, node: ast.Call, callee: str) -> List[str]:
        params = self.callee_param_names.get(callee, [])
        if (
            isinstance(node.func, ast.Attribute)
            and params
            and params[0] in {"self", "cls"}
        ):
            return params[1:]
        return params

    def _is_param_alias(self, name: str) -> bool:
        """Check if a variable is an alias to a function parameter."""
        param = self._param_name_for(name)
        return param is not None

    def _param_name_for(self, name: str) -> Optional[str]:
        """Get the parameter name that this variable may be aliased to."""
        alias_root = self._find_alias(name)
        for param in self.current_params:
            if self._find_alias(param) == alias_root:
                return param
        return None
