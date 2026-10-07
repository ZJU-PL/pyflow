"""A concrete, address-based reference interpreter for core MIR.

This executes MIR primitives only: it never executes host Python source or
silently supplies Python object protocols.  Branches require explicit Assume
guards.  A graph with multiple feasible successors is reported as nondeterministic
instead of choosing an arbitrary path.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from .model import (
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
    Instruction,
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


class MIRRuntimeError(RuntimeError):
    """Core MIR has no defined transition for the current state."""


class MIRTypeError(MIRRuntimeError):
    pass


class UnboundVariableError(MIRRuntimeError):
    pass


class MissingAttributeError(MIRRuntimeError):
    pass


class InvalidIndexError(MIRRuntimeError):
    pass


class PathPruned(MIRRuntimeError):
    pass


class NondeterministicControlFlow(MIRRuntimeError):
    pass


class StepLimitExceeded(MIRRuntimeError):
    pass


class CallDepthExceeded(MIRRuntimeError):
    pass


@dataclass(frozen=True)
class ObjectValue:
    fields: Mapping[str, int]

    def __post_init__(self) -> None:
        object.__setattr__(self, "fields", MappingProxyType(dict(self.fields)))


@dataclass(frozen=True)
class DictValue:
    fields: Mapping[str, int]

    def __post_init__(self) -> None:
        object.__setattr__(self, "fields", MappingProxyType(dict(self.fields)))


@dataclass(frozen=True)
class EnvironmentValue:
    fields: Mapping[str, int]

    def __post_init__(self) -> None:
        object.__setattr__(self, "fields", MappingProxyType(dict(self.fields)))


@dataclass(frozen=True)
class ListValue:
    items: tuple[int, ...]


@dataclass(frozen=True)
class ClosureValue:
    lambda_expr: Lambda
    parent_env: int


Value = bool | int | str | ObjectValue | DictValue | EnvironmentValue | ListValue | ClosureValue
_MAP_VALUES = (ObjectValue, DictValue, EnvironmentValue)


@dataclass(frozen=True)
class ExecutionResult:
    memory: Mapping[int, Value]
    environment: int
    steps: int

    def address(self, name: str) -> int:
        environment = self.memory[self.environment]
        assert isinstance(environment, EnvironmentValue)
        try:
            return environment.fields[name]
        except KeyError as exc:
            raise UnboundVariableError(f"Unbound MIR variable: {name!r}") from exc

    def value(self, name: str) -> Value:
        """Read a top-level value without erasing its reference representation."""
        return self.memory[self.address(name)]


class MIRInterpreter:
    """Execute a well-formed MIR Program and expose its exact memory state.

    List indexes are one-based.  CFG entry and exit nodes are visited like other
    nodes; use Skip at the entry to match the presentation's edge-entry convention.
    ``max_steps`` counts instructions across all calls and prevents unbounded
    execution; ``max_call_depth`` gives recursive programs an explicit diagnostic.
    """

    def __init__(
        self,
        program: Program | None = None,
        max_steps: int = 100_000,
        max_call_depth: int = 256,
    ) -> None:
        if max_steps < 1 or max_call_depth < 1:
            raise ValueError("Interpreter limits must be positive")
        self.program = program
        self.max_steps = max_steps
        self.max_call_depth = max_call_depth
        self.memory: dict[int, Value] = {}
        self.steps = 0
        self._next_address = 1

    def run(self, program: Program | None = None) -> ExecutionResult:
        if program is not None:
            self.program = program
        if self.program is None:
            raise ValueError("A MIR Program is required")
        self.program.validate()
        self.memory = {}
        self.steps = 0
        self._next_address = 1
        environment = self._allocate(EnvironmentValue({}))
        self._run_cfg(self.program.entry, environment, 0)
        return ExecutionResult(MappingProxyType(dict(self.memory)), environment, self.steps)

    def _allocate(self, value: Value) -> int:
        address = self._next_address
        self._next_address += 1
        self.memory[address] = value
        return address

    def _environment(self, address: int) -> EnvironmentValue:
        value = self.memory[address]
        if not isinstance(value, EnvironmentValue):
            raise MIRTypeError(f"Address {address} does not contain an environment")
        return value

    def _env_bind(self, environment: int, name: str, address: int) -> None:
        bindings = dict(self._environment(environment).fields)
        bindings[name] = address
        self.memory[environment] = EnvironmentValue(bindings)

    @staticmethod
    def _index(key: Value, size: int) -> int:
        if type(key) is not int:
            raise MIRTypeError("MIR list indexes must be integers")
        if not 1 <= key <= size:
            raise InvalidIndexError(f"MIR list index {key} is outside 1..{size}")
        return key - 1

    @staticmethod
    def _key(key: Value) -> str:
        if type(key) is not str:
            raise MIRTypeError("MIR map/object/environment keys must be strings")
        return key

    def address_of(self, reference: LValue, environment: int) -> int:
        if isinstance(reference, Var):
            try:
                return self._environment(environment).fields[reference.name]
            except KeyError as exc:
                raise UnboundVariableError(f"Unbound MIR variable: {reference.name!r}") from exc
        if isinstance(reference, Attr):
            container = self.memory[self.address_of(reference.base, environment)]
            key = self.evaluate(reference.key, environment)
            if isinstance(container, ListValue):
                return container.items[self._index(key, len(container.items))]
            if isinstance(container, _MAP_VALUES):
                name = self._key(key)
                try:
                    return container.fields[name]
                except KeyError as exc:
                    raise MissingAttributeError(f"Missing MIR member: {name!r}") from exc
            raise MIRTypeError(f"Cannot select a reference from {type(container).__name__}")
        raise MIRTypeError(f"Not a MIR l-value: {reference!r}")

    def evaluate(self, expression: Expr, environment: int) -> Value:
        """Evaluate without allocating addresses or mutating MIR memory."""
        if isinstance(expression, LValue):
            return self.memory[self.address_of(expression, environment)]
        if isinstance(expression, Literal):
            return expression.value
        if isinstance(expression, NewObject):
            return ObjectValue({})
        if isinstance(expression, ListExpr):
            return ListValue(tuple(self.address_of(item, environment) for item in expression.items))
        if isinstance(expression, DictExpr):
            return DictValue(
                {key: self.address_of(value, environment) for key, value in expression.items}
            )
        if isinstance(expression, Lambda):
            return ClosureValue(expression, environment)
        if isinstance(expression, Not):
            value = self.evaluate(expression.operand, environment)
            if type(value) is not bool:
                raise MIRTypeError("MIR logical negation requires a Boolean")
            return not value
        if isinstance(expression, Length):
            value = self.evaluate(expression.operand, environment)
            if isinstance(value, ListValue):
                return len(value.items)
            if isinstance(value, _MAP_VALUES):
                return len(value.fields)
            raise MIRTypeError("MIR length requires a list, map, object, or environment")
        if isinstance(expression, Binary):
            left = self.evaluate(expression.left, environment)
            right = self.evaluate(expression.right, environment)
            return self._binary(expression.op, left, right)
        raise MIRTypeError(f"Unknown MIR expression: {expression!r}")

    @staticmethod
    def _binary(op: str, left: Value, right: Value) -> Value:
        same_type = type(left) is type(right)
        if op == "+" and same_type:
            if type(left) in (int, str):
                return left + right
            if isinstance(left, ListValue):
                return ListValue(left.items + right.items)
        if op == "-" and type(left) is int and type(right) is int:
            return left - right
        if op == "=" and same_type:
            if type(left) in (bool, int, str):
                return left == right
            if isinstance(left, ObjectValue):
                return left.fields == right.fields
        if op == "<" and type(left) is int and type(right) is int:
            return left < right
        if op in ("or", "∨") and type(left) is bool and type(right) is bool:
            return left or right
        if op == "in" and type(left) is str and isinstance(right, _MAP_VALUES):
            return left in right.fields
        raise MIRTypeError(
            f"Undefined MIR primitive: {type(left).__name__} {op} {type(right).__name__}"
        )

    def _assumption(self, instruction: Assume, environment: int) -> bool:
        value = self.evaluate(instruction.condition, environment)
        if type(value) is not bool:
            raise MIRTypeError("MIR ASSUME requires a Boolean; Python truthiness must be lowered")
        return value

    def _bind(self, target: LValue, source: int, environment: int) -> None:
        if isinstance(target, Var):
            self._env_bind(environment, target.name, source)
            return
        if isinstance(target, Attr):
            address = self.address_of(target.base, environment)
            container = self.memory[address]
            key = self.evaluate(target.key, environment)
            if isinstance(container, ListValue):
                items = list(container.items)
                items[self._index(key, len(items))] = source
                self.memory[address] = ListValue(tuple(items))
                return
            if isinstance(container, _MAP_VALUES):
                members = dict(container.fields)
                members[self._key(key)] = source
                self.memory[address] = type(container)(members)
                return
            raise MIRTypeError("MIR BIND target is not a list, map, object, or environment")
        raise MIRTypeError(f"Not a MIR binding target: {target!r}")

    def _delete(self, target: LValue, environment: int) -> None:
        if isinstance(target, Var):
            bindings = dict(self._environment(environment).fields)
            if target.name not in bindings:
                raise UnboundVariableError(f"Unbound MIR variable: {target.name!r}")
            del bindings[target.name]
            self.memory[environment] = EnvironmentValue(bindings)
            return
        if isinstance(target, Attr):
            address = self.address_of(target.base, environment)
            container = self.memory[address]
            key = self.evaluate(target.key, environment)
            if isinstance(container, ListValue):
                items = list(container.items)
                del items[self._index(key, len(items))]
                self.memory[address] = ListValue(tuple(items))
                return
            if isinstance(container, _MAP_VALUES):
                members = dict(container.fields)
                name = self._key(key)
                if name not in members:
                    raise MissingAttributeError(f"Missing MIR member: {name!r}")
                del members[name]
                self.memory[address] = type(container)(members)
                return
            raise MIRTypeError("MIR DEL target is not a list, map, object, or environment")
        raise MIRTypeError(f"Not a MIR deletion target: {target!r}")

    def _execute(self, instruction: Instruction, environment: int, depth: int) -> None:
        if isinstance(instruction, Skip):
            return
        if isinstance(instruction, Assume):
            if not self._assumption(instruction, environment):
                raise PathPruned("MIR assumption is false")
        elif isinstance(instruction, Alloc):
            value = self.evaluate(instruction.value, environment)
            self._env_bind(environment, instruction.target, self._allocate(value))
        elif isinstance(instruction, Bind):
            source = self.address_of(instruction.source, environment)
            self._bind(instruction.target, source, environment)
        elif isinstance(instruction, Env):
            self._env_bind(environment, instruction.target, environment)
        elif isinstance(instruction, Delete):
            self._delete(instruction.target, environment)
        elif isinstance(instruction, Call):
            closure = self.evaluate(instruction.function, environment)
            if not isinstance(closure, ClosureValue):
                raise MIRTypeError("Core MIR CALL requires a closure; Python calls must be lowered")
            argument_address = self.address_of(instruction.args, environment)
            keyword_address = self.address_of(instruction.kwargs, environment)
            function = closure.lambda_expr
            callee_env = self._allocate(
                EnvironmentValue(
                    {
                        function.args_param: argument_address,
                        function.kwargs_param: keyword_address,
                        function.parent_param: closure.parent_env,
                    }
                )
            )
            self._run_cfg(function.body, callee_env, depth + 1)
            result = self.address_of(Var(function.return_var), callee_env)
            self._env_bind(environment, instruction.target, result)
        else:
            raise MIRTypeError(f"Unknown MIR instruction: {instruction!r}")

    def _run_cfg(self, name: str, environment: int, depth: int) -> None:
        if depth >= self.max_call_depth:
            raise CallDepthExceeded(f"MIR call depth exceeds {self.max_call_depth}")
        assert self.program is not None
        cfg = self.program.cfgs[name]
        current = cfg.entry
        while True:
            if self.steps >= self.max_steps:
                raise StepLimitExceeded(f"MIR execution exceeds {self.max_steps} instructions")
            node = cfg.nodes[current]
            self.steps += 1
            try:
                self._execute(node.instruction, environment, depth)
            except MIRRuntimeError as exc:
                if not getattr(exc, "mir_location", None):
                    exc.mir_location = (name, current, node.lineno)
                    exc.args = (f"{exc} [CFG {name!r}, node {current}]",)
                raise
            if current == cfg.exit:
                return
            feasible = []
            for successor in node.successors:
                instruction = cfg.nodes[successor].instruction
                if not isinstance(instruction, Assume) or self._assumption(
                    instruction, environment
                ):
                    feasible.append(successor)
            if not feasible:
                raise PathPruned(f"No feasible successor in CFG {name!r}, node {current}")
            if len(feasible) > 1:
                raise NondeterministicControlFlow(
                    f"Multiple feasible successors in CFG {name!r}, node {current}: {feasible}"
                )
            current = feasible[0]


def interpret(program: Program, max_steps: int = 100_000) -> ExecutionResult:
    """Convenience entry point for executing a core MIR program."""
    return MIRInterpreter(program, max_steps=max_steps).run()


__all__ = [
    "MIRRuntimeError",
    "MIRTypeError",
    "UnboundVariableError",
    "MissingAttributeError",
    "InvalidIndexError",
    "PathPruned",
    "NondeterministicControlFlow",
    "StepLimitExceeded",
    "CallDepthExceeded",
    "ObjectValue",
    "DictValue",
    "EnvironmentValue",
    "ListValue",
    "ClosureValue",
    "Value",
    "ExecutionResult",
    "MIRInterpreter",
    "interpret",
]
