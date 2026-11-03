"""Resolve local copies at their definitions, rather than unioning lexical names."""

from pyflow.ir.core.build_semantics import _literal_name
from pyflow.ir.core.storage import (
    AttributeStorage,
    GlobalStorage,
    LocalStorage,
    SubscriptStorage,
    UnknownStorage,
)
from pyflow.language.python import ast

from .cfg_construction import reaching


class ValueOrigins:
    def __init__(self, dependencies):
        self.dependencies = dependencies
        self.catalog, self.code = dependencies.catalog, dependencies.code
        self.order = {point: index for index, point in enumerate(dependencies.points)}
        self.cache, self.active = {}, set()
        self.definitions, self.kills = {}, {}
        for point in dependencies.points:
            for key in point.definitions:
                self.definitions.setdefault(key, set()).add(point)
            for key in point.kills:
                self.kills.setdefault(key, set()).add(point)

    def before(self, point, symbol):
        key = point, symbol
        if key not in self.dependencies.local_reaching:
            incoming = reaching(
                self.dependencies.points,
                self.definitions.get(symbol, set()),
                self.kills.get(symbol, set()),
                readers=[point],
            )
            self.dependencies.local_reaching[key] = incoming.get(point, frozenset())
        return sorted(self.dependencies.local_reaching[key], key=self.order.__getitem__)

    def fresh(self, point, reference):
        identity = (
            self.catalog.node_id(reference, self.code)
            if self.catalog.has_node(reference, self.code)
            else point.anchor.stable_id
        )
        return ("definition", identity)

    def run(self, request):
        stack, result = [self.steps(request)], None
        try:
            while stack:
                try:
                    child = stack[-1].send(result)
                except StopIteration as done:
                    result = done.value
                    stack.pop()
                else:
                    stack.append(self.steps(child))
                    result = None
            return result
        finally:
            for continuation in reversed(stack):
                continuation.close()

    def steps(self, request):
        kind, point, value = request
        if kind == "definition":
            reference = value
            key = point, id(reference)
            if key in self.cache:
                return self.cache[key]
            if key in self.active:
                return frozenset({("alias-cycle",)})
            self.active.add(key)
            try:
                symbol = self.catalog.symbol_id(reference, self.code)
                if point.block is self.dependencies.cfg.entryTerminal:
                    base = (
                        LocalStorage(symbol)
                        if self.dependencies.owner.options.assume_distinct_parameters
                        else ("parameter-base",)
                    )
                    result = frozenset({base})
                else:
                    expression = point.definition_values.get(id(reference))
                    if expression is None:
                        result = frozenset({self.fresh(point, reference)})
                    else:
                        result = yield "expression", point, expression
                self.cache[key] = result
                return result
            finally:
                self.active.remove(key)
        if kind == "symbol":
            result = set()
            if value in point.uses:
                for writer in self.before(point, value):
                    result.update((yield "definition", writer, writer.definitions[value]))
            for reference_id, symbol in point.read_symbols.items():
                reference = point.read_bindings.get(reference_id)
                if symbol == value and reference is not None:
                    result.update((yield "definition", point, reference))
            if not result:
                for writer in self.before(point, value):
                    result.update((yield "definition", writer, writer.definitions[value]))
            return frozenset(result or {LocalStorage(value)})
        if kind == "item":
            container, index = value
            marker = ("item", point, id(container), index)
            if marker in self.active:
                return frozenset({("alias-cycle",)})
            self.active.add(marker)
            try:
                if isinstance(container, ast.BuildTuple):
                    if isinstance(index, int) and -len(container.args) <= index < len(
                        container.args
                    ):
                        return (yield "expression", point, container.args[index])
                elif isinstance(container, ast.Local):
                    symbol = self.catalog.symbol_id(container, self.code)
                    result = set()
                    reference = point.read_bindings.get(id(container))
                    candidates = (
                        [(point, reference)]
                        if reference is not None
                        else [
                            (writer, writer.definitions[symbol])
                            for writer in self.before(point, symbol)
                        ]
                    )
                    for writer, reference in candidates:
                        expression = writer.definition_values.get(id(reference))
                        if expression is not None:
                            result.update((yield "item", writer, (expression, index)))
                    if result:
                        return frozenset(result)
                origins = yield "expression", point, container
                return frozenset(SubscriptStorage(base, index) for base in origins)
            finally:
                self.active.remove(marker)
        if isinstance(value, tuple):
            if len(value) == 2 and isinstance(value[1], int):
                return (yield "item", point, value)
            result = set()
            for expression in value:
                if expression is not None:
                    result.update((yield "expression", point, expression))
            return frozenset(result)
        if isinstance(value, ast.Local):
            symbol = self.catalog.symbol_id(value, self.code)
            reference = point.read_bindings.get(id(value))
            if reference is not None:
                return (yield "definition", point, reference)
            result = set()
            for writer in self.before(point, symbol):
                result.update((yield "definition", writer, writer.definitions[symbol]))
            return frozenset(result or {LocalStorage(symbol)})
        if isinstance(value, ast.NamedExpr):
            return (yield "expression", point, value.value)
        if isinstance(value, ast.GetGlobal):
            return frozenset({("global", _literal_name(value.name))})
        if isinstance(value, ast.GetAttr):
            origins = yield "expression", point, value.expr
            return frozenset(AttributeStorage(base, _literal_name(value.name)) for base in origins)
        if isinstance(value, ast.GetSubscript):
            index = (
                _literal_name(value.subscript) if isinstance(value.subscript, ast.Existing) else "*"
            )
            return (yield "item", point, (value.expr, index))
        if isinstance(value, ast.Call) and isinstance(value.expr, ast.Existing):
            name = _literal_name(value.expr)
            if name == "interpreter_getitem" and len(value.args) == 2:
                index = (
                    _literal_name(value.args[1]) if isinstance(value.args[1], ast.Existing) else "*"
                )
                return (yield "item", point, (value.args[0], index))
            if name in {"interpreter_getattr", "interpreter_getattribute"} and len(value.args) >= 2:
                origins = yield "expression", point, value.args[0]
                return frozenset(
                    AttributeStorage(base, _literal_name(value.args[1])) for base in origins
                )
        return frozenset({self.fresh(point, value)})

    def locations(self, point, storage):
        # Attribute/subscript spines can be thousands of nodes deep.
        spine = []
        while isinstance(storage, (AttributeStorage, SubscriptStorage)):
            spine.append(storage)
            storage = storage.base
        if isinstance(storage, LocalStorage):
            origins = self.run(("symbol", point, storage.symbol))
        elif isinstance(storage, GlobalStorage):
            origins = frozenset({("global", storage.name)})
        elif isinstance(storage, UnknownStorage):
            origins = frozenset({UnknownStorage("unknown")})
        else:
            origins = frozenset({storage})
        for location in reversed(spine):
            if isinstance(location, AttributeStorage):
                origins = frozenset(AttributeStorage(base, location.field) for base in origins)
            else:
                origins = frozenset(SubscriptStorage(base, location.key) for base in origins)
        return origins
