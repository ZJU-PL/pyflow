"""Runtime values and public result types for concolic execution."""

from __future__ import annotations

import ast
import datetime
from dataclasses import dataclass, field as dataclass_field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Protocol


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


class _ResumeKind(Enum):
    NEXT = auto()
    SEND = auto()
    THROW = auto()
    CLOSE = auto()


@dataclass(frozen=True)
class _ResumeOperation:
    kind: _ResumeKind
    value: Any = None


@dataclass(frozen=True)
class _Yielded:
    value: Any


@dataclass(frozen=True)
class _Awaiting:
    value: Any


@dataclass(frozen=True)
class _Returned:
    value: Any = None


@dataclass(frozen=True)
class _Raised:
    exception: BaseException


_ResumeOutcome = _Yielded | _Awaiting | _Returned | _Raised


class _ResumeExecutor(Protocol):
    def _resume_frame(
        self, frame: "_ResumableFrame", operation: _ResumeOperation
    ) -> _ResumeOutcome: ...


class _IteratorValue:
    """Runtime iterator protocol advanced one operation at a time."""

    def resume(
        self, executor: _ResumeExecutor, operation: _ResumeOperation
    ) -> _ResumeOutcome:
        raise NotImplementedError


@dataclass
class _SequenceIteratorValue(_IteratorValue):
    values: tuple[Any, ...]
    position: int = 0

    def resume(
        self, executor: _ResumeExecutor, operation: _ResumeOperation
    ) -> _ResumeOutcome:
        del executor
        if operation.kind is _ResumeKind.CLOSE:
            self.position = len(self.values)
            return _Returned()
        if operation.kind is _ResumeKind.THROW:
            exception = operation.value
            if not isinstance(exception, BaseException):
                exception = _TargetException(
                    "TypeError", "exceptions must derive from BaseException"
                )
            return _Raised(exception)
        if operation.kind is _ResumeKind.SEND and operation.value is not None:
            return _Raised(
                _TargetException(
                    "AttributeError", "sequence iterators do not support send()"
                )
            )
        if self.position >= len(self.values):
            return _Returned()
        value = self.values[self.position]
        self.position += 1
        return _Yielded(value)


def _forward_close(
    executor: _ResumeExecutor, iterators: tuple[_IteratorValue, ...]
) -> _ResumeOutcome:
    for iterator in iterators:
        outcome = iterator.resume(executor, _ResumeOperation(_ResumeKind.CLOSE))
        if isinstance(outcome, _Raised):
            return outcome
    return _Returned()


@dataclass
class _MapIteratorValue(_IteratorValue):
    function: Any
    iterators: tuple[_IteratorValue, ...]

    def resume(self, executor, operation):
        if operation.kind is _ResumeKind.CLOSE:
            return _forward_close(executor, self.iterators)
        if operation.kind is _ResumeKind.THROW:
            return _Raised(operation.value)
        if operation.kind is _ResumeKind.SEND and operation.value is not None:
            return _Raised(_TargetException("AttributeError", "map has no send()"))
        arguments = []
        for iterator in self.iterators:
            outcome = iterator.resume(executor, _ResumeOperation(_ResumeKind.NEXT))
            if isinstance(outcome, (_Returned, _Raised)):
                return outcome
            arguments.append(outcome.value)
        try:
            return _Yielded(executor._call_value(self.function, arguments, {}))
        except BaseException as error:
            return _Raised(error)


@dataclass
class _FilterIteratorValue(_IteratorValue):
    function: Any
    iterator: _IteratorValue

    def resume(self, executor, operation):
        if operation.kind is _ResumeKind.CLOSE:
            return self.iterator.resume(executor, operation)
        if operation.kind is _ResumeKind.THROW:
            return _Raised(operation.value)
        if operation.kind is _ResumeKind.SEND and operation.value is not None:
            return _Raised(_TargetException("AttributeError", "filter has no send()"))
        while True:
            outcome = self.iterator.resume(
                executor, _ResumeOperation(_ResumeKind.NEXT)
            )
            if isinstance(outcome, (_Returned, _Raised)):
                return outcome
            try:
                predicate = (
                    outcome.value
                    if self.function is None
                    else executor._call_value(self.function, [outcome.value], {})
                )
                if executor._truthy(predicate).concrete:
                    return outcome
            except BaseException as error:
                return _Raised(error)


@dataclass
class _ZipIteratorValue(_IteratorValue):
    iterators: tuple[_IteratorValue, ...]
    strict: bool = False

    def resume(self, executor, operation):
        if operation.kind is _ResumeKind.CLOSE:
            return _forward_close(executor, self.iterators)
        if operation.kind is _ResumeKind.THROW:
            return _Raised(operation.value)
        if operation.kind is _ResumeKind.SEND and operation.value is not None:
            return _Raised(_TargetException("AttributeError", "zip has no send()"))
        if not self.iterators:
            return _Returned()
        row: list[Any] = []
        for index, iterator in enumerate(self.iterators):
            outcome = iterator.resume(executor, _ResumeOperation(_ResumeKind.NEXT))
            if isinstance(outcome, _Raised):
                return outcome
            if isinstance(outcome, _Returned):
                if self.strict and (row or self._later_iterator_has_value(executor, index)):
                    return _Raised(
                        _TargetException("ValueError", "zip() arguments have different lengths")
                    )
                return _Returned()
            row.append(outcome.value)
        return _Yielded(_TupleValue(tuple(row)))

    def _later_iterator_has_value(self, executor, exhausted_index: int) -> bool:
        for iterator in self.iterators[exhausted_index + 1 :]:
            outcome = iterator.resume(executor, _ResumeOperation(_ResumeKind.NEXT))
            if isinstance(outcome, _Raised):
                raise outcome.exception
            if isinstance(outcome, _Yielded):
                return True
        return False


@dataclass
class _EnumerateIteratorValue(_IteratorValue):
    iterator: _IteratorValue
    index: int = 0

    def resume(self, executor, operation):
        if operation.kind is _ResumeKind.CLOSE:
            return self.iterator.resume(executor, operation)
        if operation.kind is _ResumeKind.THROW:
            return _Raised(operation.value)
        if operation.kind is _ResumeKind.SEND and operation.value is not None:
            return _Raised(
                _TargetException("AttributeError", "enumerate has no send()")
            )
        outcome = self.iterator.resume(executor, _ResumeOperation(_ResumeKind.NEXT))
        if isinstance(outcome, (_Returned, _Raised)):
            return outcome
        result = _TupleValue((executor._literal(self.index), outcome.value))
        self.index += 1
        return _Yielded(result)


@dataclass
class _ChainIteratorValue(_IteratorValue):
    iterators: tuple[_IteratorValue, ...]
    index: int = 0

    def resume(self, executor, operation):
        if operation.kind is _ResumeKind.CLOSE:
            return _forward_close(executor, self.iterators[self.index :])
        if operation.kind is _ResumeKind.THROW:
            return _Raised(operation.value)
        if operation.kind is _ResumeKind.SEND and operation.value is not None:
            return _Raised(_TargetException("AttributeError", "chain has no send()"))
        while self.index < len(self.iterators):
            outcome = self.iterators[self.index].resume(
                executor, _ResumeOperation(_ResumeKind.NEXT)
            )
            if isinstance(outcome, _Raised):
                return outcome
            if isinstance(outcome, _Yielded):
                return outcome
            self.index += 1
        return _Returned()


@dataclass
class _ISliceIteratorValue(_IteratorValue):
    iterator: _IteratorValue
    start: int
    stop: int | None
    step: int
    source_index: int = 0
    next_index: int = 0

    def __post_init__(self):
        self.next_index = self.start

    def resume(self, executor, operation):
        if operation.kind is _ResumeKind.CLOSE:
            return self.iterator.resume(executor, operation)
        if operation.kind is _ResumeKind.THROW:
            return _Raised(operation.value)
        if operation.kind is _ResumeKind.SEND and operation.value is not None:
            return _Raised(_TargetException("AttributeError", "islice has no send()"))
        if self.stop is not None and self.next_index >= self.stop:
            return _Returned()
        while self.source_index <= self.next_index:
            outcome = self.iterator.resume(
                executor, _ResumeOperation(_ResumeKind.NEXT)
            )
            if isinstance(outcome, (_Returned, _Raised)):
                return outcome
            current = self.source_index
            self.source_index += 1
            if current == self.next_index:
                self.next_index += self.step
                return outcome
        return _Returned()


@dataclass
class _RepeatIteratorValue(_IteratorValue):
    value: Any
    remaining: int | None = None

    def resume(self, executor, operation):
        del executor
        if operation.kind is _ResumeKind.CLOSE:
            self.remaining = 0
            return _Returned()
        if operation.kind is _ResumeKind.THROW:
            return _Raised(operation.value)
        if operation.kind is _ResumeKind.SEND and operation.value is not None:
            return _Raised(_TargetException("AttributeError", "repeat has no send()"))
        if self.remaining is not None:
            if self.remaining <= 0:
                return _Returned()
            self.remaining -= 1
        return _Yielded(self.value)


@dataclass
class _AccumulateIteratorValue(_IteratorValue):
    iterator: _IteratorValue
    function: Any = None
    accumulator: Any = None
    initialized: bool = False
    has_initial: bool = False

    def resume(self, executor, operation):
        if operation.kind is _ResumeKind.CLOSE:
            return self.iterator.resume(executor, operation)
        if operation.kind is _ResumeKind.THROW:
            return _Raised(operation.value)
        if operation.kind is _ResumeKind.SEND and operation.value is not None:
            return _Raised(
                _TargetException("AttributeError", "accumulate has no send()")
            )
        try:
            if not self.initialized:
                self.initialized = True
                if self.has_initial:
                    return _Yielded(self.accumulator)
                outcome = self.iterator.resume(
                    executor, _ResumeOperation(_ResumeKind.NEXT)
                )
                if isinstance(outcome, (_Returned, _Raised)):
                    return outcome
                self.accumulator = outcome.value
                return outcome
            outcome = self.iterator.resume(
                executor, _ResumeOperation(_ResumeKind.NEXT)
            )
            if isinstance(outcome, (_Returned, _Raised)):
                return outcome
            self.accumulator = (
                executor._binary(self.accumulator, ast.Add(), outcome.value)
                if self.function is None
                else executor._call_value(
                    self.function, [self.accumulator, outcome.value], {}
                )
            )
            return _Yielded(self.accumulator)
        except BaseException as error:
            return _Raised(error)


@dataclass
class _PairwiseIteratorValue(_IteratorValue):
    iterator: _IteratorValue
    previous: Any = None
    initialized: bool = False

    def resume(self, executor, operation):
        if operation.kind is _ResumeKind.CLOSE:
            return self.iterator.resume(executor, operation)
        if operation.kind is _ResumeKind.THROW:
            return _Raised(operation.value)
        if operation.kind is _ResumeKind.SEND and operation.value is not None:
            return _Raised(_TargetException("AttributeError", "pairwise has no send()"))
        if not self.initialized:
            first = self.iterator.resume(executor, _ResumeOperation(_ResumeKind.NEXT))
            if isinstance(first, (_Returned, _Raised)):
                return first
            self.previous = first.value
            self.initialized = True
        current = self.iterator.resume(executor, _ResumeOperation(_ResumeKind.NEXT))
        if isinstance(current, (_Returned, _Raised)):
            return current
        result = _TupleValue((self.previous, current.value))
        self.previous = current.value
        return _Yielded(result)


@dataclass
class _ZipLongestIteratorValue(_IteratorValue):
    iterators: tuple[_IteratorValue, ...]
    fillvalue: Any = None
    exhausted: list[bool] = dataclass_field(default_factory=list)

    def __post_init__(self):
        if not self.exhausted:
            self.exhausted = [False] * len(self.iterators)

    def resume(self, executor, operation):
        if operation.kind is _ResumeKind.CLOSE:
            return _forward_close(executor, self.iterators)
        if operation.kind is _ResumeKind.THROW:
            return _Raised(operation.value)
        if operation.kind is _ResumeKind.SEND and operation.value is not None:
            return _Raised(
                _TargetException("AttributeError", "zip_longest has no send()")
            )
        if not self.iterators or all(self.exhausted):
            return _Returned()
        row: list[Any] = []
        produced = False
        for index, iterator in enumerate(self.iterators):
            if self.exhausted[index]:
                row.append(self.fillvalue)
                continue
            outcome = iterator.resume(executor, _ResumeOperation(_ResumeKind.NEXT))
            if isinstance(outcome, _Raised):
                return outcome
            if isinstance(outcome, _Returned):
                self.exhausted[index] = True
                row.append(self.fillvalue)
            else:
                produced = True
                row.append(outcome.value)
        if not produced and all(self.exhausted):
            return _Returned()
        return _Yielded(_TupleValue(tuple(row)))


@dataclass
class _ResumableFrame(_IteratorValue):
    """A suspended generator/coroutine frame owned by an executor."""

    machine: Any
    environment: dict[str, Any]
    function: FunctionNode | ast.GeneratorExp
    module: "_ModuleValue | None"
    functions: dict[str, FunctionNode]
    classes: dict[str, "_ClassValue"]
    globals: dict[str, Any]
    closure: dict[str, Any] | None = None
    current_class: "_ClassValue | None" = None
    current_instance: "_InstanceValue | None" = None
    is_coroutine: bool = False
    is_async_generator: bool = False
    state: str = "created"
    return_value: Any = None
    cfg: Any = None
    program_counter: int | None = None

    def resume(
        self, executor: _ResumeExecutor, operation: _ResumeOperation
    ) -> _ResumeOutcome:
        return executor._resume_frame(self, operation)


@dataclass
class _GeneratorFrame(_ResumableFrame):
    """CFG-indexed suspended generator frame."""


@dataclass
class _CoroutineFrame(_ResumableFrame):
    """CFG-indexed suspended coroutine frame."""


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
    entered: bool = False
    exited: bool = False


@dataclass(frozen=True)
class _AsyncContextOperation:
    context: _GeneratorContext
    entering: bool
    args: tuple[Any, ...] = ()


@dataclass(frozen=True)
class _SchedulerYield:
    result: Any = None


@dataclass(frozen=True)
class _TaskWait:
    task: "_TaskValue"


@dataclass
class _TaskValue:
    frame: _ResumableFrame
    name: str | None = None
    done: bool = False
    result: Any = None
    exception: BaseException | None = None
    blocked_on: "_TaskValue | None" = None
    cancel_requested: bool = False


@dataclass(frozen=True)
class _GatherValue:
    tasks: tuple[_TaskValue, ...]
    return_exceptions: bool = False


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
    schedule: tuple[int, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "inputs": list(self.inputs),
            "result": self.result,
            "path_length": self.path_length,
            "schedule": list(self.schedule),
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
