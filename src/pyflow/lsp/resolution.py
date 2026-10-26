"""Conservative source value and member resolution, independent of compiler IR."""


class WorkspaceResolver:
    def __init__(self, symbols, imports, values, returns, bases, modules=(), models=None):
        self.symbols = {}
        self.properties = {}
        self.overloads = {}
        self.function_groups = {}
        self.parameter_declarations = {}
        self.property_declarations = {}
        for symbol in symbols:
            if symbol.symbol_id.kind.value == "parameter":
                self.parameter_declarations.setdefault(symbol.qualified_name, []).append(symbol)
            if symbol.symbol_id.kind.value in {"function", "method"} and not symbol.accessor:
                self.function_groups.setdefault(symbol.qualified_name, []).append(symbol)
                if symbol.overload:
                    self.overloads.setdefault(symbol.qualified_name, []).append(symbol)
            if symbol.accessor:
                self.properties.setdefault(symbol.qualified_name, {})[symbol.accessor] = symbol
                self.property_declarations.setdefault(symbol.qualified_name, []).append(symbol)
            self.symbols[symbol.qualified_name] = symbol
        for name, group in self.function_groups.items():
            implementations = [item for item in group if not item.overload]
            self.symbols[name] = implementations[-1] if implementations else group[-1]
        for name, accessors in self.properties.items():
            self.symbols[name] = accessors.get("getter", self.symbols[name])
        self.modules = {symbol.qualified_name: symbol for symbol in modules}
        self.namespaces = {
            ".".join(name.split(".")[:end])
            for name in self.modules
            for end in range(1, len(name.split(".")) + 1)
        }
        self.by_id = {symbol.symbol_id: symbol for symbol in (*symbols, *modules)}
        self.imports = imports
        self.values = values
        self.returns = returns
        self.bases = bases
        self.models = models
        self.dynamic_declarations = {}
        # Keep memoized targets with their snapshot. A method-level cache
        # retains old resolvers (and whole workspaces) across many small edits.
        self._names_cache = {}

    def _canonical(self, symbol_id, seen=frozenset()):
        if symbol_id in seen:
            return symbol_id
        original = self.by_id.get(symbol_id)
        if original and original.overload:
            implementation = self.symbols.get(original.qualified_name)
            if implementation and implementation.symbol_id != symbol_id:
                return implementation.symbol_id
        target = self.import_target(symbol_id)
        symbol = self.symbols.get(target) or self.modules.get(target)
        if symbol is None and self.models is not None and target:
            symbol = self.models.class_symbol(target)
            if symbol:
                self.by_id[symbol.symbol_id] = symbol
                self.symbols.setdefault(symbol.qualified_name, symbol)
        return self._canonical(symbol.symbol_id, seen | {symbol_id}) if symbol else symbol_id

    def import_target(self, identity):
        """Resolve script-local imports without falling back to leaf names."""
        target = self.imports.get(identity)
        if not target:
            return target
        head = target.partition(".")[0]
        if head in self.namespaces:
            return target
        parts = identity.module.split(".")
        if not identity.uri.endswith("/__init__.py"):
            parts = parts[:-1]
        for end in range(len(parts), 0, -1):
            prefix = ".".join(parts[:end])
            if prefix + "." + head in self.namespaces:
                return prefix + "." + target
        return target

    def member(self, owner, name, seen=frozenset(), access="read"):
        if owner in seen:
            return None
        qualified = f"{owner}.{name}"
        role = {"read": "getter", "write": "setter", "delete": "deleter"}[access]
        symbol = (
            self.properties.get(qualified, {}).get(role)
            or self.symbols.get(qualified)
            or self.modules.get(qualified)
        )
        if symbol:
            return self.by_id.get(self._canonical(symbol.symbol_id), symbol)
        candidates = {}
        for base in self.bases.get(owner, ()):
            for parent in self.names(base):
                candidate = self.member(parent, name, seen | {owner}, access)
                if candidate:
                    candidates[candidate.symbol_id] = candidate
        if len(candidates) == 1:
            return next(iter(candidates.values()))
        if not candidates and self.models is not None:
            symbol = self.models.member(owner, name)
            if symbol:
                self.by_id[symbol.symbol_id] = symbol
                self.symbols.setdefault(symbol.qualified_name, symbol)
                projected = self.models.member_type(owner, name) or self.models.member_type(
                    symbol.container_name, name
                )
                if projected:
                    self.values.setdefault(symbol.symbol_id, (("external", projected),))
                return symbol
        return None

    def symbol(self, target, seen=frozenset()):
        if not target:
            return None
        if target[0] == "super":
            candidates = [
                self.symbols[name] for name in self.names(target, seen) if name in self.symbols
            ]
            return candidates[0] if len(candidates) == 1 else None
        if target[0] == "external":
            return self.modules.get(target[1]) or self.symbols.get(target[1])
        if target[0] == "symbol":
            return self.by_id.get(self._canonical(target[1]))
        if target[0] == "member":
            candidates = {}
            for owner in self.names(target[1], seen):
                candidate = self.member(
                    owner, target[2], access=target[3] if len(target) > 3 else "read"
                )
                if candidate:
                    candidates[candidate.symbol_id] = candidate
            return next(iter(candidates.values())) if len(candidates) == 1 else None
        return None

    def callable_candidates(self, target, seen=frozenset()):
        candidates = [
            self.symbols[name] for name in self.names(target, seen) if name in self.symbols
        ]
        if any(candidate.kind == 5 for candidate in candidates) and self.denotes_instance(
            target, seen
        ):
            candidates = [
                (
                    self.member(candidate.qualified_name, "__call__")
                    if candidate.kind == 5
                    else candidate
                )
                for candidate in candidates
            ]
        return [candidate for candidate in candidates if candidate is not None]

    def callable_symbol(self, target, seen=frozenset()):
        candidates = self.callable_candidates(target, seen)
        return candidates[0] if len(candidates) == 1 else None

    def constructor_keyword(self, cls, name, parameters, seen=frozenset()):
        if cls.qualified_name in seen:
            return None
        seen = seen | {cls.qualified_name}
        explicit = self.symbols.get(cls.qualified_name + ".__init__")
        if explicit is not None:
            return dict(parameters.get(explicit.symbol_id, ())).get(name)
        if cls.constructor_fields is None:
            inherited = self.member(cls.qualified_name, "__init__")
            if inherited is not None:
                return dict(parameters.get(inherited.symbol_id, ())).get(name)
        if cls.constructor_fields is not None and name in cls.constructor_fields:
            field = self.member(cls.qualified_name, name)
            return field.symbol_id if field else None
        if cls.constructor_fields is not None and cls.qualified_name + "." + name in self.symbols:
            return None
        for base in self.bases.get(cls.qualified_name, ()):
            for owner in self.names(base):
                parent = self.symbols.get(owner)
                if parent is not None:
                    if parent.constructor_fields is None:
                        continue
                    parameter = self.constructor_keyword(parent, name, parameters, seen)
                    if parameter is not None:
                        return parameter
        return None

    def denotes_instance(self, target, seen=frozenset()):
        if not target or target in seen or len(seen) > 64:
            return False
        seen = seen | {target}
        if target[0] == "super":
            return True
        if target[0] == "nonnull":
            return self.denotes_instance(target[1], seen)
        if target[0] == "alternatives":
            values = [value for value in target[1] if value != ("external", "builtins.NoneType")]
            return bool(values) and all(self.denotes_instance(value, seen) for value in values)
        if target[0] == "symbol":
            values = self.values.get(self._canonical(target[1]), ())
            values = self.preferred_values(values, seen)
            return bool(values) and all(self.denotes_instance(value, seen) for value in values)
        if target[0] == "member":
            member = self.symbol(target, seen)
            if member:
                values = (
                    self.return_targets(member.symbol_id, seen)
                    if member.accessor == "getter"
                    else self.values.get(member.symbol_id, ())
                )
                return bool(values) and all(self.denotes_instance(value, seen) for value in values)
        if target[0] == "instance":
            callee = self.symbol(target[1], seen)
            if callee and callee.kind == 5:
                return True
            callee = self.callable_symbol(target[1], seen)
            if callee and callee.kind == 5:
                return True
            if callee:
                values = self.return_targets(callee.symbol_id, seen)
                return bool(values) and all(self.denotes_instance(value, seen) for value in values)
        return False

    def names(self, target, seen=frozenset()):
        key = target, seen
        if key in self._names_cache:
            return self._names_cache[key]
        result = self._names_uncached(target, seen)
        if len(self._names_cache) >= 16384:
            del self._names_cache[next(iter(self._names_cache))]
        self._names_cache[key] = result
        return result

    def _names_uncached(self, target, seen):
        if not target or target in seen or len(seen) > 64:
            return frozenset()
        seen = seen | {target}
        kind = target[0]
        if kind == "annotation":
            return self.names(target[1], seen)
        if kind == "super":
            return frozenset().union(
                *(
                    self.names(base, seen)
                    for owner in self.names(target[1], seen)
                    for base in self.bases.get(owner, ())
                )
            )
        if kind == "external":
            return frozenset({target[1]})
        if kind == "match-args":
            return frozenset({"builtins.tuple"})
        if kind == "match-position":
            result = set()
            for owner in self.names(target[1], seen):
                definition = self.member(owner, "__match_args__")
                for value in self.values.get(definition.symbol_id, ()) if definition else ():
                    if value[0] == "match-args" and target[2] < len(value[1]):
                        result.update(
                            self.names(
                                ("member", ("external", owner), value[1][target[2]], "read"), seen
                            )
                        )
            return frozenset(result)
        if kind == "nonnull":
            return self.names(target[1], seen) - {"builtins.NoneType"}
        if kind == "alternatives":
            return frozenset().union(*(self.names(value, seen) for value in target[1]))
        if kind == "symbol":
            symbol_id = self._canonical(target[1])
            symbol = self.by_id.get(symbol_id)
            if symbol_id in self.values:
                values = self.preferred_values(self.values[symbol_id], seen)
                resolved = [self.names(value, seen) for value in values]
                # Navigation can offer known alternatives in a gradual value.
                # Rename separately requires complete receiver evidence.
                return frozenset().union(*resolved)
            if self.models is not None:
                from .framework_models import VALUE_TYPES

                value = VALUE_TYPES.get(self.imports.get(symbol_id)) or (
                    VALUE_TYPES.get(symbol.qualified_name) if symbol else None
                )
                if value and (
                    symbol is None or symbol.symbol_id.kind.value in {"import", "variable"}
                ):
                    return frozenset({value})
            if symbol_id in self.imports:
                imported = self.import_target(symbol_id)
                return frozenset(
                    {self.models.canonical_class(imported) or imported if self.models else imported}
                )
            return frozenset({symbol.qualified_name}) if symbol else frozenset()
        if kind == "member":
            candidates = set()
            for owner in self.names(target[1], seen):
                member = self.member(owner, target[2])
                projected = (
                    (
                        self.models.member_type(owner, target[2])
                        or (
                            self.models.member_type(member.container_name, target[2])
                            if member
                            else None
                        )
                    )
                    if self.models
                    else None
                )
                if projected:
                    candidates.add(projected)
                    continue
                if member:
                    if member.accessor == "getter":
                        for value in self.return_targets(member.symbol_id, seen):
                            candidates.update(self.names(value, seen))
                    else:
                        candidates.update(self.names(("symbol", member.symbol_id), seen))
                else:
                    # Retain an imported namespace for external module completion.
                    if owner not in self.symbols:
                        candidates.add(f"{owner}.{target[2]}")
            return frozenset(candidates)
        if kind == "instance":
            resolved = self.callable_symbol(target[1], seen)
            if resolved:
                if resolved.kind == 5:
                    return frozenset({resolved.qualified_name})
                return frozenset().union(
                    *(
                        self.names(value, seen)
                        for value in self.return_targets(resolved.symbol_id, seen)
                    )
                )
            candidates = set()
            for name in self.names(target[1], seen):
                symbol = self.symbols.get(name)
                if symbol and symbol.kind == 5:
                    candidates.add(name)
                elif symbol:
                    for value in self.return_targets(symbol.symbol_id, seen):
                        candidates.update(self.names(value, seen))
                elif (
                    name.startswith("builtins.")
                    or self.models
                    and self.models.canonical_class(name)
                ):
                    candidates.add(
                        self.models.canonical_class(name) or name if self.models else name
                    )
            return frozenset(candidates)
        return frozenset()

    def is_complete(self, target, seen=frozenset()):
        if not target or target in seen or len(seen) > 64 or target[0] == "unknown":
            return False
        seen = seen | {target}
        if target[0] == "super":
            return self.is_complete(target[1], seen) and bool(self.names(target, frozenset()))
        if target[0] == "external":
            return True
        if target[0] == "nonnull":
            return self.is_complete(target[1], seen) and bool(
                self.names(target[1], seen) - {"builtins.NoneType"}
            )
        if target[0] == "alternatives":
            return all(self.is_complete(value, seen) for value in target[1])
        if target[0] == "symbol":
            symbol_id = self._canonical(target[1])
            values = self.values.get(symbol_id)
            if values is not None:
                values = self.preferred_values(values, seen)
            if values is not None:
                return all(self.is_complete(value, seen) for value in values)
            symbol = self.by_id.get(symbol_id)
            if self.models is not None:
                from .framework_models import VALUE_TYPES

                if self.imports.get(symbol_id) in VALUE_TYPES:
                    return True
            return symbol is not None and symbol.symbol_id.kind.value in {
                "class",
                "function",
                "method",
                "module",
            }
        if target[0] == "member":
            owners = self.names(target[1], seen)
            # None cannot implement an arbitrary user member. Its presence in
            # a closed optional type does not create a second rename target.
            # Preserve it for real None members such as __repr__.
            if not hasattr(None, target[2]):
                owners = owners - {"builtins.NoneType"}
            members = [self.member(owner, target[2]) for owner in owners]
            return (
                self.is_complete(target[1], seen)
                and bool(members)
                and all(members)
                and len({member.symbol_id for member in members}) == 1
            )
        if target[0] == "instance":
            callees = self.names(target[1], seen)
            if not callees:
                return False
            for name in callees:
                symbol = self.symbols.get(name)
                if symbol is None:
                    if not name.startswith("builtins.") and not (
                        self.models and self.models.canonical_class(name)
                    ):
                        return False
                elif symbol.kind != 5:
                    values = self.return_targets(symbol.symbol_id, seen)
                    if not values or not all(self.is_complete(value, seen) for value in values):
                        return False
            return self.is_complete(target[1], seen)
        return False

    def preferred_values(self, values, seen=frozenset()):
        annotated = tuple(value[1] for value in values if value and value[0] == "annotation")
        if annotated and any(self.names(value, seen) for value in annotated):
            return annotated
        return tuple(value for value in values if value and value[0] != "annotation")

    def return_targets(self, identity, seen=frozenset()):
        marker = ("returns", identity)
        if marker in seen:
            return ()
        return self.preferred_values(self.returns.get(identity, ()), seen | {marker})

    def property_group(self, symbol):
        if symbol.symbol_id.kind.value == "parameter" and symbol.container_name in self.overloads:
            return self.parameter_declarations.get(symbol.qualified_name, [symbol])
        if symbol.qualified_name in self.overloads:
            return self.function_groups[symbol.qualified_name]
        return self.dynamic_declarations.get(
            symbol.qualified_name
        ) or self.property_declarations.get(symbol.qualified_name, [symbol])

    def dynamic_namespace(self, owner):
        from .framework_models import STATE_DOMAINS

        return owner in STATE_DOMAINS

    def members(self, target):
        result = {}
        pending = list(self.names(target))
        seen = set()
        while pending:
            owner = pending.pop()
            if owner in seen:
                continue
            seen.add(owner)
            for symbol in (*self.symbols.values(), *self.modules.values()):
                if symbol.container_name == owner:
                    result.setdefault(symbol.name, symbol)
            for base in self.bases.get(owner, ()):
                pending.extend(self.names(base))
            if self.models:
                for symbol in self.models.members(owner):
                    self.by_id[symbol.symbol_id] = symbol
                    result.setdefault(symbol.name, symbol)
        return list(result.values())
