"""Runtime values and public result types for concolic execution."""

from __future__ import annotations

import ast
import datetime
from dataclasses import dataclass, field as dataclass_field
from pathlib import Path
from typing import Any


FunctionNode = ast.FunctionDef | ast.AsyncFunctionDef


class ConcolicError(Exception):
    """Base error for concolic exploration."""


class UnsupportedSyntaxError(ConcolicError):
    """Raised when a target uses syntax outside the supported subset."""


@dataclass(frozen=True)
class _IntValue:
    concrete: int
    symbolic: Any


@dataclass(frozen=True)
class _BoolValue:
    concrete: bool
    symbolic: Any


@dataclass(frozen=True)
class _StringValue:
    concrete: str
    symbolic: Any


@dataclass(frozen=True)
class _BytesValue:
    concrete: bytes


@dataclass
class _HashValue:
    algorithm: str
    payload: bytes


@dataclass(frozen=True)
class _DateTimeValue:
    concrete: datetime.date | datetime.datetime


@dataclass(frozen=True)
class _TimedeltaValue:
    concrete: datetime.timedelta


@dataclass(frozen=True)
class _PathValue:
    """A lexical POSIX path used by the safe ``pathlib`` summary."""

    concrete: str


@dataclass(frozen=True)
class _URLParseValue:
    concrete: Any


@dataclass(frozen=True)
class _FloatValue:
    concrete: int | float
    symbolic: Any


@dataclass
class _ListValue:
    values: list[Any]

    @property
    def concrete(self) -> list[Any]:
        return [_concrete(value) for value in self.values]


@dataclass
class _DequeValue(_ListValue):
    pass


@dataclass
class _DictValue:
    values: dict[int | str | bool, Any]

    @property
    def concrete(self) -> dict[int | str | bool, Any]:
        return {key: _concrete(value) for key, value in self.values.items()}


@dataclass
class _DefaultDictValue(_DictValue):
    factory: Any


@dataclass
class _CounterValue(_DictValue):
    pass


@dataclass(frozen=True)
class _TupleValue:
    values: tuple[Any, ...]

    @property
    def concrete(self) -> tuple[Any, ...]:
        return tuple(_concrete(value) for value in self.values)


@dataclass(frozen=True)
class _NamedTupleClass:
    name: str
    fields: tuple[str, ...]


@dataclass(frozen=True)
class _NamedTupleValue:
    class_value: _NamedTupleClass
    values: tuple[Any, ...]

    @property
    def concrete(self) -> tuple[Any, ...]:
        return tuple(_concrete(value) for value in self.values)


@dataclass(frozen=True)
class _EnumClass:
    name: str
    members: dict[str, int | str | bool]
    kind: str = "Enum"


@dataclass(frozen=True)
class _EnumMember:
    class_value: _EnumClass
    name: str
    value: int | str | bool


@dataclass
class _SetValue:
    values: list[Any]

    @property
    def concrete(self) -> set[Any]:
        return {_concrete(value) for value in self.values}


@dataclass(frozen=True)
class _RangeValue:
    values: tuple[_IntValue, ...]


@dataclass
class _IteratorValue:
    values: tuple[Any, ...]
    position: int = 0


@dataclass(frozen=True)
class _ClassValue:
    definition: ast.ClassDef
    module: _ModuleValue | None = None
    closure: dict[str, Any] = dataclass_field(default_factory=dict)


@dataclass
class _InstanceValue:
    class_value: _ClassValue
    fields: dict[str, Any]


@dataclass(frozen=True)
class _SuperValue:
    instance: _InstanceValue
    start_class: _ClassValue


@dataclass
class _ModuleValue:
    path: Path
    functions: dict[str, FunctionNode]
    classes: dict[str, _ClassValue]
    globals: dict[str, Any]
    loading: bool = False


@dataclass(frozen=True)
class _FunctionValue:
    definition: FunctionNode | ast.Lambda
    closure: dict[str, Any]
    module: _ModuleValue | None = None


@dataclass(frozen=True)
class _RegexModule:
    pass


@dataclass(frozen=True)
class _SummaryModule:
    name: str


@dataclass(frozen=True)
class _SummaryFunction:
    module: str
    name: str


@dataclass(frozen=True)
class _OperatorItemGetter:
    items: tuple[Any, ...]


@dataclass(frozen=True)
class _OperatorAttrGetter:
    attributes: tuple[str, ...]


@dataclass(frozen=True)
class _OperatorMethodCaller:
    name: str
    args: tuple[Any, ...]
    keywords: dict[str, Any]


@dataclass(frozen=True)
class _ImportlibModule:
    path: Path
    cache: dict[Path, _ModuleValue]


@dataclass(frozen=True)
class _ImportlibFunction:
    path: Path
    cache: dict[Path, _ModuleValue]


@dataclass(frozen=True)
class _BuiltinFunction:
    name: str


@dataclass(frozen=True)
class _ExceptionType:
    name: str


@dataclass(frozen=True)
class _SuppressContext:
    exception_names: tuple[str, ...]


@dataclass(frozen=True)
class _NullContext:
    value: Any


@dataclass(frozen=True)
class _ContextManagerFactory:
    function: Any


@dataclass
class _GeneratorContext:
    iterator: _IteratorValue


@dataclass(frozen=True)
class _PartialValue:
    function: Any
    args: tuple[Any, ...]
    keywords: dict[str, Any]


@dataclass(frozen=True)
class _IdentityDecorator:
    """A metadata or caching decorator with no semantic effect here."""


@dataclass(frozen=True)
class _RegexPattern:
    pattern: Any


@dataclass(frozen=True)
class _RegexMatch:
    match: Any


@dataclass(frozen=True)
class _Branch:
    expression: Any
    taken: bool

    def key(self) -> tuple[str, bool]:
        return (self.expression.sexpr(), self.taken)


@dataclass(frozen=True)
class RunRecord:
    """One concrete replay performed during exploration."""

    inputs: tuple[int, ...]
    result: Any
    path_length: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "inputs": list(self.inputs),
            "result": self.result,
            "path_length": self.path_length,
        }


@dataclass(frozen=True)
class ContractCounterexample:
    """A concrete execution that violates a declared postcondition."""

    clause: str
    inputs: tuple[Any, ...]
    result: Any
    path_length: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "clause": self.clause,
            "inputs": list(self.inputs),
            "result": self.result,
            "path_length": self.path_length,
        }


@dataclass(frozen=True)
class ExplorationResult:
    """The generated inputs and concrete outcomes of an exploration."""

    entry: str
    parameter_names: tuple[str, ...]
    runs: tuple[RunRecord, ...]
    unsatisfiable_paths: int
    counterexamples: tuple[ContractCounterexample, ...] = ()

    @property
    def generated_inputs(self) -> tuple[tuple[int, ...], ...]:
        return tuple(run.inputs for run in self.runs)

    def to_dict(self) -> dict[str, Any]:
        return {
            "entry": self.entry,
            "parameters": list(self.parameter_names),
            "generated_inputs": [list(inputs) for inputs in self.generated_inputs],
            "runs": [run.to_dict() for run in self.runs],
            "unsatisfiable_paths": self.unsatisfiable_paths,
            "counterexamples": [
                counterexample.to_dict() for counterexample in self.counterexamples
            ],
        }


class _Return:
    def __init__(self, value: Any):
        self.value = value


class _Break:
    pass


class _Continue:
    pass


class _TargetException(Exception):
    def __init__(self, name: str, message: str = "") -> None:
        self.name = name
        self.message = message
        super().__init__(message)


def _concrete(value: Any) -> Any:
    """Return the ordinary Python value represented by a runtime wrapper."""

    return value.concrete if hasattr(value, "concrete") else value
