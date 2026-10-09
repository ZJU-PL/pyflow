"""PyCG's assignment-graph fixed point over the seven-instruction MIR.

The analysis is context insensitive, flow insensitive and field sensitive.  It
only understands MIR: Python name lookup, argument binding, descriptors and
operator dispatch must already have been lowered to ordinary MIR instructions.
No input module is imported or executed, and no upstream PyCG installation or
precomputed call graph is used.

An abstract address identifies an allocation instruction, or one environment
per CFG.  Bindings are sets of addresses, while each address stores a union of
primitive values, closures and container fields.  ``Bind`` aliases an address;
``Alloc`` copies a value into a distinct allocation-site address.  Calls join
actual argument containers and captured environments into the callee's three
MIR parameters and propagate its return binding back to the caller.  This is
the assignment propagation/fixed-point/call-resolution algorithm of Salis et
al., *PyCG: Practical Call Graph Generation in Python* (ICSE 2021), specialized
to the memory and closure model of MIR (https://arxiv.org/abs/2103.00587).

Primitive arithmetic is widened to a finite domain consisting of literals and
statically present list indices, with a bounded set of alternatives at computed
allocation sites.  Primitive top values subsume their concrete alternatives;
unknown container keys use typed summary fields.  Abstract facts grow
monotonically under this subsumption order, including recursive call edges.  Assume
does not prune paths; deletion retains old bindings and conservatively models
the index shifts caused by deleting list elements.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field, fields, is_dataclass
from pathlib import Path
from typing import Iterable, Mapping
import warnings

from pyflow.ir.mir.model import (
    Alloc,
    Assume,
    Attr,
    Binary,
    Bind,
    Call,
    Delete,
    DictExpr,
    Env,
    Expr,
    Lambda,
    Length,
    ListExpr,
    Literal,
    LValue,
    NewObject,
    Not,
    Program,
    Skip,
    Var,
)

from .callgraph import CallGraph


class MIRCallGraph(CallGraph):
    """A compatible call graph that also retains direct recursive calls."""

    def add_edge(self, caller: str, callee: str) -> None:
        self.add_node(caller)
        self.add_node(callee)
        self._graph[caller].add(callee)


class PyCGMIRConvergenceWarning(RuntimeWarning):
    """A bounded run stopped before the assignment graph reached a fixed point."""


class PyCGMIRConvergenceError(RuntimeError):
    """Strict analysis exhausted its iteration budget.

    ``result`` exposes the explicitly incomplete graph for diagnostic use.
    """

    def __init__(self, result: "PyCGMIRResult") -> None:
        self.result = result
        super().__init__(
            f"MIR PyCG did not converge after {result.iterations} iterations; "
            "the call graph is incomplete"
        )


@dataclass(frozen=True)
class PyCGMIRResult:
    """Call graph, assignment graph, and explicit analysis completeness status.

    Assignment graph keys are scope-qualified variables (``scope::name``),
    allocation sites (``@alloc:scope:node``), or fields of allocation sites.
    Edges record bindings, points-to relations and closure targets.  Primitive
    terminals start with ``@literal:`` or ``@unknown:``.  Container containment
    is deliberately not an assignment edge: a list is not its elements.

    ``call_sites`` maps ``(CFG name, node id)`` to resolved CFG targets.  Unless
    ``include_synthetic`` is requested, synthetic helper CFGs are projected out
    of the call graph and call-site targets.  ``reachable_cfgs`` always records
    the actual analyzed MIR CFGs, including synthetic helpers and function
    definitions activated by ``analyze_all_functions``.
    """

    call_graph: MIRCallGraph
    assignment_graph: Mapping[str, frozenset[str]]
    converged: bool
    iterations: int
    reachable_cfgs: frozenset[str]
    call_sites: Mapping[tuple[str, int], frozenset[str]]
    diagnostics: tuple[str, ...] = ()
    unresolved_calls: tuple[tuple[str, int], ...] = ()

    @property
    def truncated(self) -> bool:
        return not self.converged


@dataclass(frozen=True)
class _Primitive:
    kind: str
    value: bool | int | str | None = None

    @property
    def unknown(self) -> bool:
        return self.value is None


@dataclass(frozen=True)
class _Closure:
    function: Lambda
    parent: str


@dataclass(frozen=True)
class _SummaryKey:
    kind: str


_INT_KEY = _SummaryKey("int")
_STR_KEY = _SummaryKey("str")
_ANY_KEY = _SummaryKey("any")
_UNKNOWN_INT = _Primitive("int")
_UNKNOWN_STR = _Primitive("str")
_TRUE = _Primitive("bool", True)
_FALSE = _Primitive("bool", False)
_BOOLS = frozenset((_TRUE, _FALSE))
# Bound *computed* alternatives independently of the largest literal/container
# in the input.  Literal allocation sites and exact field reads stay precise.
_MAX_COMPUTED_PRIMITIVES = 16
_Key = str | int | _SummaryKey
_Atom = _Primitive | _Closure


def _join_atoms(target: set, incoming: Iterable[_Atom], limit: int | None = None) -> bool:
    """Join primitive/closure alternatives, keeping type tops canonical.

    Replacing constants by their type's top is an increase in the abstract
    lattice, even though the concrete representation removes redundant atoms.
    In particular, joining a constant into an existing top changes nothing.
    The same operation also accepts the primitive-only set of list lengths.
    """
    changed = False
    for atom in incoming:
        if isinstance(atom, _Primitive):
            top = _Primitive(atom.kind)
            if top in target:
                continue
            if atom.unknown:
                target.difference_update(
                    value
                    for value in tuple(target)
                    if isinstance(value, _Primitive) and value.kind == atom.kind
                )
        if atom not in target:
            target.add(atom)
            changed = True
    if limit is not None:
        for kind in ("int", "str", "bool"):
            constants = {
                atom
                for atom in target
                if isinstance(atom, _Primitive) and atom.kind == kind and not atom.unknown
            }
            top = _Primitive(kind)
            if constants and (top in target or len(constants) > limit):
                target.difference_update(constants)
                target.add(top)
                changed = True
    return changed


@dataclass
class _Value:
    atoms: set[_Atom] = field(default_factory=set)
    kinds: set[str] = field(default_factory=set)
    fields: dict[_Key, set[str]] = field(default_factory=dict)
    lengths: set[_Primitive] = field(default_factory=set)

    def join(self, other: "_Value", primitive_limit: int | None = None) -> bool:
        """Join a value without sharing mutable field sets."""
        changed = _join_atoms(self.atoms, other.atoms, primitive_limit)
        changed |= _join_atoms(self.lengths, other.lengths, _MAX_COMPUTED_PRIMITIVES)
        before = len(self.kinds)
        self.kinds.update(other.kinds)
        changed |= len(self.kinds) != before
        for key, incoming in other.fields.items():
            changed |= key not in self.fields
            target = self.fields.setdefault(key, set())
            before = len(target)
            target.update(incoming)
            changed |= len(target) != before
        return changed


def _walk_expressions(value: object) -> Iterable[Expr]:
    if isinstance(value, Expr):
        yield value
    if is_dataclass(value):
        for item in fields(value):
            yield from _walk_expressions(getattr(value, item.name))
    elif isinstance(value, (tuple, list)):
        for item in value:
            yield from _walk_expressions(item)


class _Analysis:
    def __init__(self, program: Program, analyze_all_functions: bool) -> None:
        self.program = program
        self.analyze_all_functions = analyze_all_functions
        self.heap: dict[str, _Value] = {}
        self.environments = {name: f"@env:{name}" for name in program.cfgs}
        self.environment_owners = {address: name for name, address in self.environments.items()}
        self.active: set[str] = set()
        self.nodes: dict[str, tuple[int, ...]] = {}
        self.raw_calls: dict[str, set[str]] = defaultdict(set)
        self.raw_sites: dict[tuple[str, int], set[str]] = defaultdict(set)
        self.assignments: dict[str, set[str]] = defaultdict(set)
        self.changed = False
        self.integers: set[int] = {-1, 0, 1}
        self.strings: set[str] = set()

        for cfg in program.cfgs.values():
            for node in cfg.nodes.values():
                for expr in _walk_expressions(node.instruction):
                    if isinstance(expr, Literal):
                        if type(expr.value) is int:
                            self.integers.add(expr.value)
                        elif isinstance(expr.value, str):
                            self.strings.add(expr.value)
                    elif isinstance(expr, ListExpr):
                        self.integers.update(range(-len(expr.items), len(expr.items) + 1))
                    elif isinstance(expr, DictExpr):
                        self.strings.update(key for key, _ in expr.items)
                        self.integers.add(len(expr.items))

        self._activate(program.entry)

    def _activate(self, name: str) -> None:
        if name in self.active:
            return
        if name not in self.program.cfgs:
            raise ValueError(f"MIR closure references missing CFG {name!r}")
        self.active.add(name)
        self.changed = True
        address = self.environments[name]
        self.heap[address] = _Value(kinds={"env"})
        cfg = self.program.cfgs[name]
        reachable: set[int] = set()
        pending = [cfg.entry]
        while pending:
            node_id = pending.pop()
            if node_id not in reachable:
                reachable.add(node_id)
                pending.extend(cfg.nodes[node_id].successors)
        self.nodes[name] = tuple(sorted(reachable))

    def _field_label(self, address: str, key: _Key) -> str:
        if address in self.environment_owners and isinstance(key, str):
            return f"{self.environment_owners[address]}::{key}"
        if isinstance(key, _SummaryKey):
            return f"{address}[<{key.kind}>]"
        return f"{address}[{key!r}]"

    def _edge(self, source: str, targets: Iterable[str]) -> None:
        current = self.assignments[source]
        before = len(current)
        current.update(targets)
        self.changed |= len(current) != before

    def _update_value(self, address: str, value: _Value, *, computed: bool = False) -> None:
        self.changed |= self.heap.setdefault(address, _Value()).join(
            value, _MAX_COMPUTED_PRIMITIVES if computed else None
        )

    def _write_field(self, address: str, key: _Key, refs: Iterable[str]) -> None:
        value = self.heap.setdefault(address, _Value())
        self.changed |= key not in value.fields
        field_refs = value.fields.setdefault(key, set())
        before = len(field_refs)
        field_refs.update(refs)
        self.changed |= len(field_refs) != before

    @staticmethod
    def _key_matches(query: _Key, stored: _Key) -> bool:
        if query == stored or query == _ANY_KEY or stored == _ANY_KEY:
            return True
        if query == _INT_KEY:
            return type(stored) is int or stored == _INT_KEY
        if query == _STR_KEY:
            return isinstance(stored, str) or stored == _STR_KEY
        if stored == _INT_KEY:
            return type(query) is int
        if stored == _STR_KEY:
            return isinstance(query, str)
        return False

    def _keys(self, value: _Value) -> set[_Key]:
        result: set[_Key] = set()
        for atom in value.atoms:
            if not isinstance(atom, _Primitive):
                continue
            if atom.kind == "int":
                result.add(_INT_KEY if atom.unknown else int(atom.value))
            elif atom.kind == "str":
                result.add(_STR_KEY if atom.unknown else str(atom.value))
        return result

    def _read_slots(self, lvalue: LValue, scope: str) -> set[tuple[str, _Key]]:
        if isinstance(lvalue, Var):
            address = self.environments[scope]
            # An environment can be written through an unknown string key,
            # because Env exposes the very same object to ordinary Attr/Bind.
            value = self.heap.get(address, _Value())
            return {(address, lvalue.name)} | {
                (address, key) for key in (_STR_KEY, _ANY_KEY) if key in value.fields
            }
        if not isinstance(lvalue, Attr):
            raise TypeError(f"Unsupported MIR l-value: {type(lvalue).__name__}")
        queries = self._keys(self._eval(lvalue.key, scope))
        result: set[tuple[str, _Key]] = set()
        for address in self._resolve(lvalue.base, scope):
            value = self.heap.get(address)
            if value is None:
                continue
            for query in queries:
                if isinstance(query, _SummaryKey):
                    candidates = (key for key in value.fields if self._key_matches(query, key))
                else:
                    candidates = (
                        query,
                        _INT_KEY if type(query) is int else _STR_KEY,
                        _ANY_KEY,
                    )
                result.update((address, key) for key in candidates if key in value.fields)
        return result

    def _write_slots(self, lvalue: LValue, scope: str) -> set[tuple[str, _Key]]:
        if isinstance(lvalue, Var):
            return {(self.environments[scope], lvalue.name)}
        if not isinstance(lvalue, Attr):
            raise TypeError(f"Unsupported MIR l-value: {type(lvalue).__name__}")
        keys = self._keys(self._eval(lvalue.key, scope))
        return {(address, key) for address in self._resolve(lvalue.base, scope) for key in keys}

    def _resolve(self, lvalue: LValue, scope: str) -> set[str]:
        result: set[str] = set()
        for address, key in self._read_slots(lvalue, scope):
            value = self.heap.get(address)
            if value is not None:
                result.update(value.fields.get(key, ()))
        return result

    def _source_labels(self, lvalue: LValue, scope: str) -> set[str]:
        return {self._field_label(address, key) for address, key in self._read_slots(lvalue, scope)}

    def _bind(
        self, target: LValue, refs: Iterable[str], sources: Iterable[str], scope: str
    ) -> None:
        refs = tuple(refs)
        sources = tuple(sources)
        for address, key in self._write_slots(target, scope):
            self._write_field(address, key, refs)
            self._edge(self._field_label(address, key), sources)

    def _primitive(self, kind: str, value: bool | int | str) -> _Primitive:
        if kind == "int" and value not in self.integers:
            return _UNKNOWN_INT
        if kind == "str" and value not in self.strings:
            return _UNKNOWN_STR
        return _Primitive(kind, value)

    def _eval(self, expr: Expr, scope: str) -> _Value:
        if isinstance(expr, LValue):
            result = _Value()
            for address in self._resolve(expr, scope):
                result.join(self.heap.get(address, _Value()))
            return result
        if isinstance(expr, NewObject):
            return _Value(kinds={"object"})
        if isinstance(expr, Literal):
            if type(expr.value) is bool:
                kind = "bool"
            elif type(expr.value) is int:
                kind = "int"
            elif isinstance(expr.value, str):
                kind = "str"
            else:
                raise TypeError(f"Invalid MIR literal {expr.value!r}")
            return _Value(atoms={_Primitive(kind, expr.value)})
        if isinstance(expr, Lambda):
            closure = _Closure(expr, self.environments[scope])
            if self.analyze_all_functions and not self.program.cfgs[expr.body].is_synthetic:
                self._activate(expr.body)
                self._write_field(
                    self.environments[expr.body], expr.parent_param, (closure.parent,)
                )
            return _Value(atoms={closure})
        if isinstance(expr, ListExpr):
            return _Value(
                kinds={"list"},
                fields={
                    index: self._resolve(item, scope) for index, item in enumerate(expr.items, 1)
                },
                lengths={_Primitive("int", len(expr.items))},
            )
        if isinstance(expr, DictExpr):
            result = _Value(kinds={"dict"})
            for key, lvalue in expr.items:
                result.fields.setdefault(key, set()).update(self._resolve(lvalue, scope))
            return result
        if isinstance(expr, Not):
            result = _Value()
            for atom in self._eval(expr.operand, scope).atoms:
                if isinstance(atom, _Primitive) and atom.kind == "bool":
                    result.atoms.update(
                        _BOOLS if atom.unknown else (_Primitive("bool", not atom.value),)
                    )
            return result
        if isinstance(expr, Length):
            operand = self._eval(expr.operand, scope)
            result = _Value(atoms=set(operand.lengths))
            if operand.kinds & {"object", "dict", "env"}:
                count = sum(not isinstance(key, _SummaryKey) for key in operand.fields)
                result.atoms.add(self._primitive("int", count))
                # Joins and weak updates lose correlations about field presence.
                result.atoms.add(_UNKNOWN_INT)
            return result
        if isinstance(expr, Binary):
            return self._binary(
                expr.op, self._eval(expr.left, scope), self._eval(expr.right, scope)
            )
        raise TypeError(f"Unsupported MIR expression: {type(expr).__name__}")

    def _binary(self, op: str, left: _Value, right: _Value) -> _Value:
        # Operands are temporary expression values, never aliases of heap
        # cells.  Widening them avoids a Cartesian product of large constant
        # sets while preserving singleton literal allocations in the heap.
        for operand in (left, right):
            _join_atoms(operand.atoms, (), _MAX_COMPUTED_PRIMITIVES)
            _join_atoms(operand.lengths, (), _MAX_COMPUTED_PRIMITIVES)
        result = _Value()
        if op not in {"+", "-", "=", "==", "<", "or", "∨", "in"}:
            raise ValueError(f"Unsupported MIR binary operator {op!r}")
        if op == "+" and "list" in left.kinds and "list" in right.kinds:
            result.kinds.add("list")
            for key, refs in left.fields.items():
                if type(key) is int or key in {_INT_KEY, _ANY_KEY}:
                    result.fields.setdefault(key, set()).update(refs)
            for left_length in left.lengths:
                for right_length in right.lengths:
                    result.lengths.add(
                        _UNKNOWN_INT
                        if left_length.unknown or right_length.unknown
                        else self._primitive(
                            "int", int(left_length.value) + int(right_length.value)
                        )
                    )
                right_is_summary = _UNKNOWN_INT in right.lengths
                for key, refs in right.fields.items():
                    if type(key) is int:
                        shifted = (
                            _UNKNOWN_INT
                            if left_length.unknown or right_is_summary
                            else self._primitive("int", int(left_length.value) + key)
                        )
                        shifted_key = _INT_KEY if shifted.unknown else int(shifted.value)
                    elif key in {_INT_KEY, _ANY_KEY}:
                        shifted_key = _INT_KEY
                    else:
                        continue
                    result.fields.setdefault(shifted_key, set()).update(refs)
        if op == "in" and right.kinds & {"dict", "object", "env"}:
            if self._keys(left):
                result.atoms.update(_BOOLS)
            return result
        if op in {"=", "=="} and (left.kinds or right.kinds):
            result.atoms.update(_BOOLS)
        for lhs in left.atoms:
            for rhs in right.atoms:
                if not isinstance(lhs, _Primitive) or not isinstance(rhs, _Primitive):
                    if op in {"=", "=="}:
                        result.atoms.update(_BOOLS)
                    continue
                if op in {"=", "=="}:
                    result.atoms.update(
                        _BOOLS if lhs.unknown or rhs.unknown else (_Primitive("bool", lhs == rhs),)
                    )
                elif op in {"or", "∨"} and lhs.kind == rhs.kind == "bool":
                    result.atoms.update(
                        _BOOLS
                        if lhs.unknown or rhs.unknown
                        else (_Primitive("bool", bool(lhs.value or rhs.value)),)
                    )
                elif op == "<" and lhs.kind == rhs.kind == "int":
                    result.atoms.update(
                        _BOOLS
                        if lhs.unknown or rhs.unknown
                        else (_Primitive("bool", int(lhs.value) < int(rhs.value)),)
                    )
                elif op in {"+", "-"} and lhs.kind == rhs.kind == "int":
                    if lhs.unknown or rhs.unknown:
                        result.atoms.add(_UNKNOWN_INT)
                    else:
                        value = (
                            int(lhs.value) + int(rhs.value)
                            if op == "+"
                            else int(lhs.value) - int(rhs.value)
                        )
                        result.atoms.add(self._primitive("int", value))
                elif op == "+" and lhs.kind == rhs.kind == "str":
                    result.atoms.add(
                        _UNKNOWN_STR
                        if lhs.unknown or rhs.unknown
                        else self._primitive("str", str(lhs.value) + str(rhs.value))
                    )
        _join_atoms(result.atoms, (), _MAX_COMPUTED_PRIMITIVES)
        _join_atoms(result.lengths, (), _MAX_COMPUTED_PRIMITIVES)
        return result

    def _delete(self, target: LValue, scope: str) -> None:
        # Killing aliases is unsafe in a flow-insensitive may analysis.  List
        # deletion additionally shifts later slots, so retain the shifted
        # possibilities as well as the pre-deletion references.
        if not isinstance(target, Attr):
            return
        indices = self._keys(self._eval(target.key, scope))
        for address in self._resolve(target.base, scope):
            value = self.heap.get(address)
            if value is None or "list" not in value.kinds:
                continue
            for key, refs in list(value.fields.items()):
                if type(key) is int and key > 1:
                    if any(
                        index in {_INT_KEY, _ANY_KEY} or (type(index) is int and 1 <= index < key)
                        for index in indices
                    ):
                        shifted = self._primitive("int", key - 1)
                        self._write_field(
                            address,
                            _INT_KEY if shifted.unknown else int(shifted.value),
                            tuple(refs),
                        )
                elif key in {_INT_KEY, _ANY_KEY}:
                    self._write_field(address, _INT_KEY, tuple(refs))
            if indices:
                shorter = {
                    (
                        _UNKNOWN_INT
                        if length.unknown
                        else self._primitive("int", max(0, int(length.value) - 1))
                    )
                    for length in value.lengths
                }
                self._update_value(address, _Value(lengths=shorter))

    def _call(self, command: Call, scope: str, node_id: int) -> None:
        site = self.raw_sites[(scope, node_id)]
        functions = self._eval(command.function, scope)
        arguments = self._resolve(command.args, scope)
        keywords = self._resolve(command.kwargs, scope)
        for closure in functions.atoms:
            if not isinstance(closure, _Closure):
                continue
            function = closure.function
            self._activate(function.body)
            if function.body not in site:
                site.add(function.body)
                self.raw_calls[scope].add(function.body)
                self.changed = True
            environment = self.environments[function.body]
            for parameter, refs, sources in (
                (function.args_param, arguments, self._source_labels(command.args, scope)),
                (function.kwargs_param, keywords, self._source_labels(command.kwargs, scope)),
                (function.parent_param, (closure.parent,), (closure.parent,)),
            ):
                self._write_field(environment, parameter, refs)
                self._edge(self._field_label(environment, parameter), sources)
            returns = self._resolve(Var(function.return_var), function.body)
            self._bind(
                Var(command.target),
                tuple(returns),
                (self._field_label(environment, function.return_var),),
                scope,
            )

    def step(self) -> None:
        self.changed = False
        # Newly discovered callees are processed on the next fixed-point pass.
        for scope in sorted(self.active):
            cfg = self.program.cfgs[scope]
            environment = self.environments[scope]
            for node_id in self.nodes[scope]:
                command = cfg.nodes[node_id].instruction
                if isinstance(command, (Skip, Assume)):
                    continue
                if isinstance(command, Alloc):
                    address = f"@alloc:{scope}:{node_id}"
                    self._update_value(
                        address,
                        self._eval(command.value, scope),
                        computed=isinstance(command.value, (Binary, Length, Not)),
                    )
                    self._write_field(environment, command.target, (address,))
                    self._edge(self._field_label(environment, command.target), (address,))
                    if isinstance(command.value, LValue):
                        self._edge(address, self._source_labels(command.value, scope))
                elif isinstance(command, Bind):
                    self._bind(
                        command.target,
                        self._resolve(command.source, scope),
                        self._source_labels(command.source, scope),
                        scope,
                    )
                elif isinstance(command, Env):
                    self._write_field(environment, command.target, (environment,))
                    self._edge(self._field_label(environment, command.target), (environment,))
                elif isinstance(command, Delete):
                    self._delete(command.target, scope)
                elif isinstance(command, Call):
                    self._call(command, scope, node_id)
                else:
                    raise TypeError(f"Unsupported MIR instruction: {type(command).__name__}")

    def _project(self, targets: Iterable[str], include_synthetic: bool) -> frozenset[str]:
        result: set[str] = set()
        seen: set[str] = set()
        pending = list(targets)
        while pending:
            target = pending.pop()
            if target in seen:
                continue
            seen.add(target)
            if include_synthetic or not self.program.cfgs[target].is_synthetic:
                result.add(target)
            else:
                pending.extend(self.raw_calls.get(target, ()))
        return frozenset(result)

    def result(self, converged: bool, iterations: int, include_synthetic: bool) -> PyCGMIRResult:
        graph = MIRCallGraph()
        for name, cfg in self.program.cfgs.items():
            if include_synthetic or not cfg.is_synthetic:
                graph.add_node(name, cfg.filename or None)
                for target in self._project(self.raw_calls.get(name, ()), include_synthetic):
                    graph.add_edge(name, target)

        assignments = {name: set(targets) for name, targets in self.assignments.items()}
        for address, value in self.heap.items():
            targets = assignments.setdefault(address, set())
            for atom in value.atoms:
                if isinstance(atom, _Closure):
                    target = atom.function.body
                elif atom.unknown:
                    target = f"@unknown:{atom.kind}"
                else:
                    target = f"@literal:{atom.kind}:{atom.value!r}"
                targets.add(target)
                assignments.setdefault(target, set())
            for key, refs in value.fields.items():
                assignments.setdefault(self._field_label(address, key), set()).update(refs)
        sites = {
            site: self._project(targets, include_synthetic)
            for site, targets in self.raw_sites.items()
            if include_synthetic or not self.program.cfgs[site[0]].is_synthetic
        }
        unresolved = tuple(sorted(site for site, targets in self.raw_sites.items() if not targets))
        diagnostics = [
            f"Unresolved MIR call at {scope}:{node_id}: no closure target was established"
            for scope, node_id in unresolved
        ]
        if not converged:
            diagnostics.insert(
                0, f"Iteration limit reached after {iterations} passes; graph is incomplete"
            )
        result = PyCGMIRResult(
            call_graph=graph,
            assignment_graph={
                name: frozenset(targets) for name, targets in sorted(assignments.items())
            },
            converged=converged,
            iterations=iterations,
            reachable_cfgs=frozenset(self.active),
            call_sites=sites,
            diagnostics=tuple(diagnostics),
            unresolved_calls=unresolved,
        )
        graph.analysis_result = result
        return result


def analyze_program(
    program: Program,
    *,
    max_iterations: int | None = 256,
    raise_on_truncation: bool = False,
    include_synthetic: bool = False,
    analyze_all_functions: bool = True,
) -> PyCGMIRResult:
    """Analyze a MIR program without parsing, importing or executing Python.

    By default every encountered source function definition is analyzed, as in
    PyCG.  With ``analyze_all_functions=False``, only the entry CFG and resolved
    callees are visited.  Synthetic helper bodies always require a call.

    A positive iteration budget bounds work; ``None`` iterates to convergence.
    Hitting the budget returns ``converged=False`` and emits a warning.  Strict
    callers may request ``raise_on_truncation=True`` and inspect the exception's
    ``result``.  A truncated graph must not be treated as a complete may graph.
    """
    if max_iterations is not None and (type(max_iterations) is not int or max_iterations < 1):
        raise ValueError("max_iterations must be a positive integer or None")
    if program.entry not in program.cfgs:
        raise ValueError(f"MIR program entry {program.entry!r} is not a CFG")
    program.validate()
    analysis = _Analysis(program, analyze_all_functions)
    iterations = 0
    converged = False
    while max_iterations is None or iterations < max_iterations:
        analysis.step()
        iterations += 1
        if not analysis.changed:
            converged = True
            break
    result = analysis.result(converged, iterations, include_synthetic)
    if not converged:
        if raise_on_truncation:
            raise PyCGMIRConvergenceError(result)
        warnings.warn(
            f"MIR PyCG did not converge after {iterations} iterations; "
            "the call graph is incomplete",
            PyCGMIRConvergenceWarning,
            stacklevel=2,
        )
    return result


def extract_call_graph_pycg_mir(
    source_code: str,
    verbose: bool = False,
    source_path: str | None = None,
) -> MIRCallGraph:
    """Lower supplied source to MIR and run the native PyCG fixed point.

    ``source_code`` is always authoritative.  A source path provides filename
    and import-resolution context; it does not replace the supplied source.
    Detailed diagnostics and assignment relations are on ``analysis_result``.
    """
    from pyflow.ir.mir.lowering import _default_root, _module_name, lower_source

    kwargs = {}
    if source_path is not None:
        path = Path(source_path).resolve()
        project_root = _default_root(path)
        kwargs["filename"] = source_path
        kwargs["module_name"] = _module_name(path, project_root)
        kwargs["project_root"] = str(project_root)
    result = analyze_program(lower_source(source_code, **kwargs))
    if verbose:
        print(
            f"MIR PyCG: {result.iterations} iterations, "
            f"converged={result.converged}, "
            f"{len(result.reachable_cfgs)} analyzed CFGs"
        )
        for diagnostic in result.diagnostics:
            print(diagnostic)
    return result.call_graph


def analyze_file_pycg_mir(
    filepath: str,
    verbose: bool = False,
    *,
    project_root: str | None = None,
    format: str = "text",
) -> str:
    """Analyze a file and supported local imports, rendering text or JSON adjacency.

    Lowering, validation and I/O failures propagate to the caller.  They are
    never converted to an empty graph or a successful-looking result.
    """
    from pyflow.ir.mir.lowering import lower_file

    from .formats import generate_text_output

    kwargs = {} if project_root is None else {"project_root": project_root}
    result = analyze_program(lower_file(filepath, **kwargs))
    if verbose:
        print(f"MIR PyCG: {result.iterations} iterations, converged={result.converged}")
        for diagnostic in result.diagnostics:
            print(diagnostic)
    if format == "json":
        from .formats import generate_adjacency_json

        return generate_adjacency_json(result.call_graph)
    return generate_text_output(result.call_graph, None)


__all__ = [
    "MIRCallGraph",
    "PyCGMIRConvergenceError",
    "PyCGMIRConvergenceWarning",
    "PyCGMIRResult",
    "analyze_program",
    "extract_call_graph_pycg_mir",
    "analyze_file_pycg_mir",
]
