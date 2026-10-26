"""Conservative source value and member resolution, independent of compiler IR."""

from functools import lru_cache


class WorkspaceResolver:
    def __init__(self, symbols, imports, values, returns, bases, modules=()):
        self.symbols = {}
        self.properties = {}
        self.property_declarations = {}
        for symbol in symbols:
            if symbol.accessor:
                self.properties.setdefault(symbol.qualified_name, {})[symbol.accessor] = symbol
                self.property_declarations.setdefault(symbol.qualified_name, []).append(symbol)
            self.symbols[symbol.qualified_name] = symbol
        for name, accessors in self.properties.items():
            self.symbols[name] = accessors.get("getter", self.symbols[name])
        self.modules = {symbol.qualified_name: symbol for symbol in modules}
        self.by_id = {symbol.symbol_id: symbol for symbol in (*symbols, *modules)}
        self.imports = imports
        self.values = values
        self.returns = returns
        self.bases = bases

    def _canonical(self, symbol_id, seen=frozenset()):
        if symbol_id in seen:
            return symbol_id
        target = self.imports.get(symbol_id)
        symbol = self.symbols.get(target) or self.modules.get(target)
        return self._canonical(symbol.symbol_id, seen | {symbol_id}) if symbol else symbol_id

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
        return next(iter(candidates.values())) if len(candidates) == 1 else None

    def symbol(self, target, seen=frozenset()):
        if not target:
            return None
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

    def denotes_instance(self, target, seen=frozenset()):
        if not target or target in seen or len(seen) > 64:
            return False
        seen = seen | {target}
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

    @lru_cache(maxsize=16384)
    def names(self, target, seen=frozenset()):
        if not target or target in seen or len(seen) > 64:
            return frozenset()
        seen = seen | {target}
        kind = target[0]
        if kind == "external":
            return frozenset({target[1]})
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
            if symbol_id in self.imports:
                return frozenset({self.imports[symbol_id]})
            return frozenset({symbol.qualified_name}) if symbol else frozenset()
        if kind == "member":
            candidates = set()
            for owner in self.names(target[1], seen):
                member = self.member(owner, target[2])
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
                elif name.startswith("builtins."):
                    candidates.add(name)
            return frozenset(candidates)
        return frozenset()

    def is_complete(self, target, seen=frozenset()):
        if not target or target in seen or len(seen) > 64 or target[0] == "unknown":
            return False
        seen = seen | {target}
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
                    if not name.startswith("builtins."):
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
        return self.property_declarations.get(symbol.qualified_name, [symbol])

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
        return list(result.values())
