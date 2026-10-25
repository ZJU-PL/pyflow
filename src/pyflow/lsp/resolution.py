"""Conservative source value and member resolution, independent of compiler IR."""

from functools import lru_cache


class WorkspaceResolver:
    def __init__(self, symbols, imports, values, returns, bases):
        self.symbols = {symbol.qualified_name: symbol for symbol in symbols}
        self.by_id = {symbol.symbol_id: symbol for symbol in symbols}
        self.imports = imports
        self.values = values
        self.returns = returns
        self.bases = bases

    def _canonical(self, symbol_id, seen=frozenset()):
        if symbol_id in seen:
            return symbol_id
        target = self.imports.get(symbol_id)
        symbol = self.symbols.get(target)
        return self._canonical(symbol.symbol_id, seen | {symbol_id}) if symbol else symbol_id

    def member(self, owner, name, seen=frozenset()):
        if owner in seen:
            return None
        symbol = self.symbols.get(f"{owner}.{name}")
        if symbol:
            return self.by_id.get(self._canonical(symbol.symbol_id), symbol)
        candidates = {}
        for base in self.bases.get(owner, ()):
            for parent in self.names(base):
                candidate = self.member(parent, name, seen | {owner})
                if candidate:
                    candidates[candidate.symbol_id] = candidate
        return next(iter(candidates.values())) if len(candidates) == 1 else None

    def symbol(self, target):
        if not target:
            return None
        if target[0] == "symbol":
            return self.by_id.get(self._canonical(target[1]))
        if target[0] == "member":
            candidates = {}
            for owner in self.names(target[1]):
                candidate = self.member(owner, target[2])
                if candidate:
                    candidates[candidate.symbol_id] = candidate
            return next(iter(candidates.values())) if len(candidates) == 1 else None
        return None

    def callable_symbol(self, target):
        candidates = [self.symbols[name] for name in self.names(target) if name in self.symbols]
        return candidates[0] if len(candidates) == 1 else None

    @lru_cache(maxsize=16384)
    def names(self, target, seen=frozenset()):
        if not target or target in seen:
            return frozenset()
        seen = seen | {target}
        kind = target[0]
        if kind == "external":
            return frozenset({target[1]})
        if kind == "symbol":
            symbol_id = self._canonical(target[1])
            symbol = self.by_id.get(symbol_id)
            if symbol_id in self.values:
                values = self.values[symbol_id]
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
                    candidates.update(self.names(("symbol", member.symbol_id), seen))
                else:
                    # Retain an imported namespace for external module completion.
                    if owner not in self.symbols:
                        candidates.add(f"{owner}.{target[2]}")
            return frozenset(candidates)
        if kind == "instance":
            candidates = set()
            for name in self.names(target[1], seen):
                symbol = self.symbols.get(name)
                if symbol and symbol.kind == 5:
                    candidates.add(name)
                elif symbol:
                    for value in self.returns.get(symbol.symbol_id, ()):
                        candidates.update(self.names(value, seen))
                elif name.startswith("builtins."):
                    candidates.add(name)
            return frozenset(candidates)
        return frozenset()

    def is_complete(self, target, seen=frozenset()):
        if not target or target in seen or target[0] == "unknown":
            return False
        seen = seen | {target}
        if target[0] == "external":
            return True
        if target[0] == "symbol":
            symbol_id = self._canonical(target[1])
            values = self.values.get(symbol_id)
            return (
                all(self.is_complete(value, seen) for value in values)
                if values is not None
                else True
            )
        if target[0] == "member":
            owners = self.names(target[1])
            members = [self.member(owner, target[2]) for owner in owners]
            return (
                self.is_complete(target[1], seen)
                and bool(members)
                and all(members)
                and len({member.symbol_id for member in members}) == 1
            )
        if target[0] == "instance":
            callees = self.names(target[1])
            if not callees:
                return False
            for name in callees:
                symbol = self.symbols.get(name)
                if symbol is None:
                    if not name.startswith("builtins."):
                        return False
                elif symbol.kind != 5:
                    values = self.returns.get(symbol.symbol_id, ())
                    if not values or not all(self.is_complete(value, seen) for value in values):
                        return False
            return self.is_complete(target[1], seen)
        return False

    def members(self, target):
        result = {}
        pending = list(self.names(target))
        seen = set()
        while pending:
            owner = pending.pop()
            if owner in seen:
                continue
            seen.add(owner)
            for symbol in self.symbols.values():
                if symbol.container_name == owner:
                    result.setdefault(symbol.name, symbol)
            for base in self.bases.get(owner, ()):
                pending.extend(self.names(base))
        return list(result.values())
