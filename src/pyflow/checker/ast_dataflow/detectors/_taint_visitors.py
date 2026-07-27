"""AST statement visitors for local taint dataflow."""

from __future__ import annotations

import ast


class _StatementVisitorMixin:
    def visit_FunctionDef(self, node: ast.FunctionDef):
        if self.function_depth > 0:
            return
        self.function_depth += 1
        self.current_params = set(self._collect_function_params(node.args))
        tainted_params = {
            arg
            for arg in self.current_params
            if arg in self.sources or arg in self.entry_tainted_params
        }
        if tainted_params:
            self.tainted.update(tainted_params)
            if tainted_params & self.sources:
                self.has_source = True

        # Seed per-key/per-index taint for parameters (e.g., *args, **kwargs).
        for param, keys in self.entry_tainted_param_keys.items():
            if param not in self.current_params:
                continue
            for key in keys:
                self._mark_container_key_tainted(param, None if key == "*" else key)

        self.generic_visit(node)
        self.function_depth -= 1

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self.visit_FunctionDef(node)

    def visit_Assign(self, node: ast.Assign):
        value_is_source = self._expr_is_source(node.value)
        value_is_tainted = self._expr_is_tainted(node.value)

        if value_is_source:
            self.has_source = True

        for target in node.targets:
            if isinstance(target, ast.Name):
                # Reset tracked constant/path metadata on reassignment.
                self.const_str_values.pop(target.id, None)
                self.dict_key_order.pop(target.id, None)
                self.list_lengths.pop(target.id, None)
                self.int_values.pop(target.id, None)
                self._clear_paths_for_root(target.id)

                if (
                    isinstance(node.value, ast.Call)
                    and self._call_fullname(node.value.func) == "len"
                    and node.value.args
                    and isinstance(node.value.args[0], ast.Name)
                    and node.value.args[0].id in self.list_lengths
                ):
                    arg_name = node.value.args[0].id
                    self.int_values[target.id] = self.list_lengths[arg_name]
                    self.tainted.discard(target.id)
                    self._clear_container_taint(target.id)
                    continue
                elif isinstance(node.value, ast.Constant) and isinstance(
                    node.value.value, int
                ):
                    self.int_values[target.id] = node.value.value

                # Track dict literal key order for destructuring `k1, k2 = d`.
                if isinstance(node.value, ast.Dict) and all(
                    isinstance(k, ast.Constant) and isinstance(k.value, str)
                    for k in node.value.keys
                    if k is not None
                ):
                    self.dict_key_order[target.id] = [
                        k.value for k in node.value.keys if isinstance(k, ast.Constant)
                    ]

                # Track list literal length for precise index modelling.
                if isinstance(node.value, ast.List):
                    self.list_lengths[target.id] = len(node.value.elts)

                # Track nested taint paths from container literals.
                if isinstance(node.value, (ast.Dict, ast.List, ast.Tuple)):
                    self._record_literal_taint_paths((target.id,), node.value)

                if isinstance(node.value, ast.Name):
                    self._union_alias(target.id, node.value.id)
                if value_is_source or value_is_tainted:
                    if self._expr_is_container(node.value):
                        self._update_container_from_expr(target.id, node.value)
                    else:
                        self.tainted.add(target.id)
                        self.int_values.pop(target.id, None)
                elif (
                    isinstance(node.value, ast.Name)
                    and node.value.id in self.tainted_containers
                ):
                    self._mark_container_tainted(target.id)
                elif isinstance(node.value, ast.Name):
                    src_key = self._alias_key(node.value.id)
                    if src_key in self.tainted_attrs:
                        key = self._alias_key(target.id)
                        self.tainted_attrs[key] = set(self.tainted_attrs[src_key])
                elif self._container_literal_is_tainted(node.value):
                    self._update_container_from_expr(target.id, node.value)
                else:
                    self.tainted_attrs.pop(self._alias_key(target.id), None)
                    self._clear_container_taint(target.id)
                    self.int_values.pop(target.id, None)
            elif isinstance(target, ast.Attribute):
                base, attr = self._attribute_base_and_attr(target)
                if base and attr:
                    base_key = self._alias_key(base)
                    if value_is_source or value_is_tainted:
                        self.tainted_attrs.setdefault(base_key, set()).add(attr)
                        if self._is_param_alias(base):
                            self.param_taint_outputs.add(self._param_name_for(base))
                        self._record_param_key_write(base, attr, value_is_tainted)
                    else:
                        attrs = self.tainted_attrs.get(base_key)
                        if attrs:
                            attrs.discard(attr)
                        self._record_param_key_write(base, attr, False)
            elif isinstance(target, ast.Subscript):
                base = self._subscript_base_name(target.value)
                key = self._subscript_key(target.slice)
                key_expr_is_tainted = self._expr_is_tainted(target.slice)

                # Tainted keys taint the container structure even when the
                # stored value is safe.
                if base and (
                    value_is_source or value_is_tainted or key_expr_is_tainted
                ):
                    if key_expr_is_tainted:
                        # Only dict keys are exposed via `keys()`; keep this
                        # separate so `values()` remains precise.
                        self._mark_dict_key_tainted(base, None)

                    if value_is_source or value_is_tainted:
                        self._mark_container_key_tainted(base, key)
                        self._record_param_key_write(base, key, True)

                        # Record path taint when a constant access path is
                        # available.
                        path = self._expr_path(target)
                        if path is not None:
                            if isinstance(node.value, (ast.Dict, ast.List, ast.Tuple)):
                                self._record_literal_taint_paths(path, node.value)
                            else:
                                self._record_tainted_path(path)

                    if self._is_param_alias(base):
                        self.param_taint_outputs.add(self._param_name_for(base))
                elif base:
                    self._clear_container_key(base, key)
                    self._record_param_key_write(base, key, False)
            elif isinstance(target, (ast.Tuple, ast.List)):
                # Destructuring assignment / unpacking.
                # 1) Dict-key iteration destructuring from a dict literal.
                if (
                    isinstance(node.value, ast.Name)
                    and node.value.id in self.dict_key_order
                ):
                    keys = self.dict_key_order[node.value.id]
                    for idx, elt in enumerate(target.elts):
                        if isinstance(elt, ast.Name) and idx < len(keys):
                            self.const_str_values[elt.id] = {keys[idx]}
                    # No taint is introduced by iterating keys alone.
                    continue

                # 2) Starred unpacking into a rest list: `a, *rest = [..]`
                star_indices = [
                    i
                    for i, elt in enumerate(target.elts)
                    if isinstance(elt, ast.Starred)
                ]
                if star_indices and len(star_indices) == 1:
                    star_i = star_indices[0]
                    star_elt = target.elts[star_i]
                    rest_name = (
                        star_elt.value.id
                        if isinstance(star_elt, ast.Starred)
                        and isinstance(star_elt.value, ast.Name)
                        else None
                    )
                    if rest_name and isinstance(node.value, (ast.List, ast.Tuple)):
                        values = list(node.value.elts)
                        left = target.elts[:star_i]
                        right = target.elts[star_i + 1 :]
                        if len(values) >= len(left) + len(right):
                            # Left bindings
                            for idx, elt in enumerate(left):
                                if (
                                    isinstance(elt, ast.Name)
                                    and idx < len(values)
                                    and self._expr_is_tainted(values[idx])
                                ):
                                    self.tainted.add(elt.id)
                            # Right bindings
                            for r_idx, elt in enumerate(reversed(right)):
                                src_idx = len(values) - 1 - r_idx
                                if isinstance(elt, ast.Name) and self._expr_is_tainted(
                                    values[src_idx]
                                ):
                                    self.tainted.add(elt.id)
                            # Rest list bindings
                            rest_values = values[len(left) : len(values) - len(right)]
                            self.list_lengths[rest_name] = len(rest_values)
                            self._clear_container_taint(rest_name)
                            self._clear_paths_for_root(rest_name)
                            for idx, v in enumerate(rest_values):
                                if isinstance(v, (ast.Dict, ast.List, ast.Tuple)):
                                    self._record_literal_taint_paths(
                                        (rest_name, str(idx)), v
                                    )
                                elif self._expr_is_tainted(v):
                                    self._record_tainted_path((rest_name, str(idx)))
                                if self._expr_is_tainted(v):
                                    self._mark_container_key_tainted(
                                        rest_name, str(idx)
                                    )
                            continue

                # 3) Simple positional destructuring.
                if value_is_source:
                    for elt in target.elts:
                        if isinstance(elt, ast.Name):
                            self.tainted.add(elt.id)
                elif value_is_tainted:
                    if isinstance(node.value, (ast.Tuple, ast.List, ast.Set)):
                        for idx, elt in enumerate(target.elts):
                            if isinstance(elt, ast.Name):
                                if idx < len(node.value.elts) and self._expr_is_tainted(
                                    node.value.elts[idx]
                                ):
                                    self.tainted.add(elt.id)
                    elif (
                        isinstance(node.value, ast.Name)
                        and node.value.id in self.tainted_containers
                    ):
                        for elt in target.elts:
                            if isinstance(elt, ast.Name):
                                self.tainted.add(elt.id)
                    else:
                        for elt in target.elts:
                            if isinstance(elt, ast.Name):
                                self.tainted.add(elt.id)

        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign):
        """Handle annotated assignments."""
        if not isinstance(node.target, ast.Name):
            self.generic_visit(node)
            return

        target_name = node.target.id
        value_is_source = node.value is not None and self._expr_is_source(node.value)
        value_is_tainted = node.value is not None and self._expr_is_tainted(node.value)

        if value_is_source:
            self.has_source = True

        if node.value is None:
            self.generic_visit(node)
            return

        if isinstance(node.value, ast.Name):
            self._union_alias(target_name, node.value.id)

        if value_is_source or value_is_tainted:
            if self._expr_is_container(node.value):
                self._update_container_from_expr(target_name, node.value)
            else:
                self.tainted.add(target_name)
        elif (
            isinstance(node.value, ast.Name)
            and node.value.id in self.tainted_containers
        ):
            self._mark_container_tainted(target_name)
        elif isinstance(node.value, ast.Name):
            src_key = self._alias_key(node.value.id)
            if src_key in self.tainted_attrs:
                key = self._alias_key(target_name)
                self.tainted_attrs[key] = set(self.tainted_attrs[src_key])
        elif self._container_literal_is_tainted(node.value):
            self._update_container_from_expr(target_name, node.value)
        else:
            self.tainted_attrs.pop(self._alias_key(target_name), None)
            self._clear_container_taint(target_name)

        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign):
        value_is_tainted = self._expr_is_tainted(node.value)
        if isinstance(node.target, ast.Name):
            if value_is_tainted:
                self.tainted.add(node.target.id)
            if (
                isinstance(node.value, ast.Name)
                and node.value.id in self.tainted_containers
            ):
                self._mark_container_tainted(node.target.id)
            if isinstance(node.value, ast.Name):
                src_key = self._alias_key(node.value.id)
                if src_key in self.tainted_attrs:
                    key = self._alias_key(node.target.id)
                    self.tainted_attrs[key] = set(self.tainted_attrs[src_key])
        elif isinstance(node.target, ast.Attribute):
            base, attr = self._attribute_base_and_attr(node.target)
            if base and attr and value_is_tainted:
                self.tainted_attrs.setdefault(self._alias_key(base), set()).add(attr)
                if self._is_param_alias(base):
                    self.param_taint_outputs.add(self._param_name_for(base))
                self._record_param_key_write(base, attr, True)
            elif base and attr:
                self._record_param_key_write(base, attr, False)
        elif isinstance(node.target, ast.Subscript):
            base = self._subscript_base_name(node.target.value)
            key = self._subscript_key(node.target.slice)
            if base and value_is_tainted:
                self._mark_container_key_tainted(base, key)
                if self._is_param_alias(base):
                    self.param_taint_outputs.add(self._param_name_for(base))
                self._record_param_key_write(base, key, True)
            elif base:
                self._clear_container_key(base, key)
                self._record_param_key_write(base, key, False)
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return):
        if node.value is not None and self._expr_is_tainted(node.value):
            self.returns_tainted = True
        # Continue visiting children for completeness
        self.generic_visit(node)

    def visit_Continue(self, node: ast.Continue):
        """Handle continue statements - no taint propagation."""
        # Continue just skips to the next iteration, no taint is added or removed
        pass

    def visit_Break(self, node: ast.Break):
        """Handle break statements - no taint propagation."""
        # Break exits the loop, no taint is added or removed
        pass

    def visit_Delete(self, node: ast.Delete):
        """Track del operations."""
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.tainted.discard(target.id)
                self._clear_container_taint(target.id)
            elif isinstance(target, ast.Attribute):
                base, attr = self._attribute_base_and_attr(target)
                if base and attr:
                    base_key = self._alias_key(base)
                    attrs = self.tainted_attrs.get(base_key)
                    if attrs:
                        attrs.discard(attr)
            elif isinstance(target, ast.Subscript):
                base = self._subscript_base_name(target.value)
                key = self._subscript_key(target.slice)
                if base:
                    self._clear_container_key(base, key)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        fullname = self._call_fullname(node.func)
        if fullname:
            callee = self._resolve_callee_name(fullname)
            if callee in self.known_callees:
                tainted_params, _ = self._tainted_params_for_call(node, callee)
                if tainted_params:
                    self.call_param_taints.setdefault(callee, set()).update(
                        tainted_params
                    )
                key_taints = self._tainted_param_keys_for_call(node, callee)
                if key_taints:
                    merged = self.call_param_key_taints.setdefault(callee, {})
                    for param, keys in key_taints.items():
                        merged.setdefault(param, set()).update(keys)
                self._apply_callee_param_taint_outputs(node, callee)

        if fullname in self.sinks:
            self.sinks_found.add(fullname)
            tainted_arg = False
            positions = self.sink_positions.get(fullname, set(range(len(node.args))))
            for index, arg in enumerate(node.args):
                if index not in positions:
                    continue
                if isinstance(arg, ast.Name):
                    if self._expr_is_tainted(arg):
                        self.params_to_sink.add(arg.id)
                        tainted_arg = True
                elif isinstance(arg, ast.Subscript):
                    base = self._subscript_base_name(arg.value)
                    if base and self._expr_is_tainted(arg):
                        self.params_to_sink.add(base)
                        tainted_arg = True
                elif self._expr_is_tainted(arg):
                    tainted_arg = True
            for kwd in node.keywords:
                if isinstance(kwd.value, ast.Name):
                    if self._expr_is_tainted(kwd.value):
                        self.params_to_sink.add(kwd.value.id)
                        tainted_arg = True
                elif self._expr_is_tainted(kwd.value):
                    tainted_arg = True
            if tainted_arg:
                self.tainted_sink = True
                self.tainted_sinks.add(fullname)
                lineno = getattr(node, "lineno", None)
                if isinstance(lineno, int):
                    self.tainted_sink_lines.setdefault(fullname, set()).add(lineno)

        if self._expr_is_source(node):
            self.has_source = True

        self._handle_container_calls(node)
        self.generic_visit(node)

    def visit_Match(self, node: ast.Match):
        """Handle match statements."""
        subject_is_tainted = self._expr_is_tainted(node.subject)
        for case in node.cases:
            bindings = self._collect_match_bindings(case.pattern)
            for name in bindings:
                if self._binding_captures_subject(
                    case.pattern, name, subject_is_tainted
                ):
                    self.tainted.add(name)
        self.generic_visit(node)

    def visit_For(self, node: ast.For):
        """Handle for loops including enumerate and zip patterns."""
        # Visit iterator expression first.
        self.visit(node.iter)

        # Handle enumerate pattern: for index, value in enumerate(iter)
        if isinstance(node.target, ast.Tuple) and isinstance(node.iter, ast.Call):
            iter_fullname = self._call_fullname(node.iter.func)
            if iter_fullname == "enumerate":
                # Mark both index and value as potentially tainted if iter is tainted
                iter_is_tainted = (
                    self._expr_is_tainted(node.iter.args[0])
                    if node.iter.args
                    else False
                )
                if iter_is_tainted:
                    for target in node.target.elts:
                        if isinstance(target, ast.Name):
                            self.tainted.add(target.id)
                self._visit_block(node.body)
                self._visit_block(node.orelse)
                return
            elif iter_fullname == "zip":
                # Mark loop variables if any zip argument is tainted.
                any_tainted = any(self._expr_is_tainted(arg) for arg in node.iter.args)
                if any_tainted:
                    for target in node.target.elts:
                        if isinstance(target, ast.Name):
                            self.tainted.add(target.id)
                self._visit_block(node.body)
                self._visit_block(node.orelse)
                return

        # Handle normal for loops: for target in iter
        iter_is_tainted = self._expr_is_tainted(node.iter)
        if iter_is_tainted and isinstance(node.target, ast.Name):
            self.tainted.add(node.target.id)
        elif iter_is_tainted and isinstance(node.target, ast.Tuple):
            for elt in node.target.elts:
                if isinstance(elt, ast.Name):
                    self.tainted.add(elt.id)

        self._visit_block(node.body)
        self._visit_block(node.orelse)

    def visit_AsyncFor(self, node: ast.AsyncFor):
        """Handle async for loops."""
        self.visit_For(node)

    def visit_Try(self, node: ast.Try):
        """Handle try-except statements with basic exception taint propagation."""
        exc_tainted = any(self._raise_is_tainted(stmt) for stmt in node.body)
        self._try_exc_taint_stack.append(exc_tainted)

        self._visit_block(node.body)
        for handler in node.handlers:
            self.visit(handler)
        self._visit_block(node.orelse)
        self._visit_block(node.finalbody)

        self._try_exc_taint_stack.pop()

    def visit_ExceptHandler(self, node: ast.ExceptHandler):
        """Handle except handlers - track exception variable."""
        if node.name and isinstance(node.name, str):
            if self._try_exc_taint_stack and self._try_exc_taint_stack[-1]:
                self.tainted.add(node.name)
        self._visit_block(node.body)

    def visit_If(self, node: ast.If):
        """Handle if statements with lightweight constant folding."""
        self.visit(node.test)
        decided = self._const_bool(node.test)
        if decided is True:
            self._visit_block(node.body)
            return
        if decided is False:
            self._visit_block(node.orelse)
            return
        # Unknown: conservatively visit both branches.
        self._visit_block(node.body)
        self._visit_block(node.orelse)

    def visit_IfExp(self, node: ast.IfExp):
        """Handle ternary expressions like x if cond else y."""
        self.visit(node.test)
        decided = self._const_bool(node.test)
        if decided is True:
            self.visit(node.body)
            return
        if decided is False:
            self.visit(node.orelse)
            return
        self.visit(node.body)
        self.visit(node.orelse)

    def visit_Await(self, node: ast.Await):
        self.visit(node.value)
