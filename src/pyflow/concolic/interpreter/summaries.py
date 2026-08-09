"""summary support for the AST executor."""

from __future__ import annotations

import ast

import base64

import bisect

import datetime

import heapq

import itertools

import json

import math

import posixpath

import statistics

from urllib import parse as urlparse

from typing import Any

from ..core.runtime import (
    ConcolicError,
    UnsupportedSyntaxError,
    _AccumulateIteratorValue,
    _BoolValue,
    _BytesValue,
    _ContextManagerFactory,
    _ChainIteratorValue,
    _CounterValue,
    _DateTimeValue,
    _DefaultDictValue,
    _DequeValue,
    _DictValue,
    _ExceptionType,
    _FloatValue,
    _FunctionValue,
    _HashValue,
    _IdentityDecorator,
    _InstanceValue,
    _ISliceIteratorValue,
    _IntValue,
    _ListValue,
    _NamedTupleClass,
    _NullContext,
    _OperatorAttrGetter,
    _OperatorItemGetter,
    _OperatorMethodCaller,
    _PartialValue,
    _PathValue,
    _PairwiseIteratorValue,
    _RepeatIteratorValue,
    _StringValue,
    _SuppressContext,
    _SchedulerYield,
    _TimedeltaValue,
    _TupleValue,
    _URLParseValue,
    _ZipLongestIteratorValue,
)

from ..core.support import _concrete


class _SummaryMixin:
    def _call_summary(
        self, module: str, name: str, args: list[Any], keywords: dict[str, Any]
    ) -> Any:
        if module == "asyncio" and name == "sleep" and 1 <= len(args) <= 2:
            if set(keywords) - {"result"}:
                raise UnsupportedSyntaxError("asyncio.sleep() supports only the result keyword")
            result = keywords.get("result", args[1] if len(args) == 2 else None)
            return _SchedulerYield(result)
        if module == "asyncio" and name == "create_task" and len(args) == 1:
            if set(keywords) - {"name", "context"}:
                raise UnsupportedSyntaxError("asyncio.create_task() supports name and context")
            name_value = keywords.get("name")
            task_name = self._to_string(name_value).concrete if name_value is not None else None
            return self._create_task(args[0], task_name)
        if module == "asyncio" and name == "gather":
            if set(keywords) - {"return_exceptions"}:
                raise UnsupportedSyntaxError("asyncio.gather() supports only return_exceptions")
            return self._create_gather(
                args,
                (
                    self._truthy(keywords["return_exceptions"]).concrete
                    if "return_exceptions" in keywords
                    else False
                ),
            )
        if module == "contextlib" and name == "suppress" and args and not keywords:
            if not all(isinstance(value, _ExceptionType) for value in args):
                raise UnsupportedSyntaxError("contextlib.suppress() requires exception classes")
            return _SuppressContext(tuple(value.name for value in args))
        if module == "contextlib" and name == "nullcontext" and len(args) <= 1:
            if keywords:
                raise UnsupportedSyntaxError(
                    "contextlib.nullcontext() does not support keyword arguments"
                )
            return _NullContext(args[0] if args else None)
        if (
            module == "contextlib"
            and name in {"contextmanager", "asynccontextmanager"}
            and len(args) == 1
            and not keywords
        ):
            return _ContextManagerFactory(args[0])
        if module == "copy" and name in {"copy", "deepcopy"} and len(args) == 1:
            if keywords:
                raise UnsupportedSyntaxError(f"copy.{name}() does not support keyword arguments")
            return self._copy_value(args[0], deep=name == "deepcopy")
        if module == "functools" and name == "partial" and args:
            return _PartialValue(args[0], tuple(args[1:]), dict(keywords))
        if module == "functools" and name in {"cache", "lru_cache"}:
            if len(args) == 1 and isinstance(args[0], _FunctionValue) and not keywords:
                return args[0]
            if name == "lru_cache" and len(args) <= 1:
                return _IdentityDecorator()
        if module == "functools" and name == "wraps" and len(args) == 1:
            return _IdentityDecorator()
        if module == "operator":
            if name == "itemgetter" and args and not keywords:
                return _OperatorItemGetter(tuple(args))
            if name == "attrgetter" and args and not keywords:
                return _OperatorAttrGetter(
                    tuple(self._to_string(argument).concrete for argument in args)
                )
            if name == "methodcaller" and args:
                return _OperatorMethodCaller(
                    self._to_string(args[0]).concrete,
                    tuple(args[1:]),
                    dict(keywords),
                )
            binary_operators = {
                "add": ast.Add,
                "sub": ast.Sub,
                "mul": ast.Mult,
                "truediv": ast.Div,
                "floordiv": ast.FloorDiv,
                "mod": ast.Mod,
                "lshift": ast.LShift,
                "rshift": ast.RShift,
                "and_": ast.BitAnd,
                "or_": ast.BitOr,
                "xor": ast.BitXor,
            }
            if name in binary_operators and len(args) == 2 and not keywords:
                return self._binary(args[0], binary_operators[name](), args[1])
            if name == "contains" and len(args) == 2 and not keywords:
                return self._contains(args[0], args[1])
            if name == "getitem" and len(args) == 2 and not keywords:
                return self._subscript(args[0], ast.Constant(value=_concrete(args[1])))
        if module == "bisect":
            if keywords:
                raise UnsupportedSyntaxError("bisect summaries do not support keyword arguments")
            search_names = {"bisect", "bisect_left", "bisect_right"}
            insert_names = {"insort", "insort_left", "insort_right"}
            if name in search_names and 2 <= len(args) <= 4:
                values = self._iter_values(args[0])
                lo = self._as_int(args[2]).concrete if len(args) >= 3 else 0
                hi = self._as_int(args[3]).concrete if len(args) == 4 else len(values)
                try:
                    concrete = getattr(bisect, name)(
                        [_concrete(value) for value in values],
                        _concrete(args[1]),
                        lo,
                        hi,
                    )
                except TypeError as error:
                    raise ConcolicError(str(error)) from error
                return _IntValue(concrete, self._z3.IntVal(concrete))
            if name in insert_names and 2 <= len(args) <= 4:
                if not isinstance(args[0], _ListValue):
                    raise UnsupportedSyntaxError("bisect.insort() requires a list")
                values = args[0].values
                lo = self._as_int(args[2]).concrete if len(args) >= 3 else 0
                hi = self._as_int(args[3]).concrete if len(args) == 4 else len(values)
                search_name = "bisect_left" if name == "insort_left" else "bisect_right"
                try:
                    position = getattr(bisect, search_name)(
                        [_concrete(value) for value in values],
                        _concrete(args[1]),
                        lo,
                        hi,
                    )
                except TypeError as error:
                    raise ConcolicError(str(error)) from error
                values.insert(position, args[1])
                return None
        if module == "heapq":
            if keywords:
                raise UnsupportedSyntaxError("heapq summaries do not support keyword arguments")
            if name == "heapify" and len(args) == 1:
                if not isinstance(args[0], _ListValue):
                    raise UnsupportedSyntaxError("heapq.heapify() requires a list")
                args[0].values[:] = [entry[2] for entry in self._heap_entries(args[0].values)]
                return None
            if name == "heappush" and len(args) == 2:
                if not isinstance(args[0], _ListValue):
                    raise UnsupportedSyntaxError("heapq.heappush() requires a list")
                entries = self._heap_entries(args[0].values)
                try:
                    heapq.heappush(
                        entries,
                        (_concrete(args[1]), len(entries), args[1]),
                    )
                except TypeError as error:
                    raise ConcolicError(str(error)) from error
                args[0].values[:] = [entry[2] for entry in entries]
                return None
            if name in {"heappop", "heapreplace", "heappushpop"} and (
                len(args) == 1 if name == "heappop" else len(args) == 2
            ):
                if not isinstance(args[0], _ListValue):
                    raise UnsupportedSyntaxError(f"heapq.{name}() requires a list")
                entries = self._heap_entries(args[0].values)
                try:
                    if name == "heappop":
                        result = heapq.heappop(entries)
                    else:
                        entry = (_concrete(args[1]), len(entries), args[1])
                        result = getattr(heapq, name)(entries, entry)
                except (IndexError, TypeError) as error:
                    raise ConcolicError(str(error)) from error
                args[0].values[:] = [entry[2] for entry in entries]
                return result[2]
            if name in {"nsmallest", "nlargest"} and len(args) == 2:
                count = self._as_int(args[0]).concrete
                entries = [
                    (_concrete(value), index, value)
                    for index, value in enumerate(self._iter_values(args[1]))
                ]
                try:
                    selected = getattr(heapq, name)(count, entries)
                except TypeError as error:
                    raise ConcolicError(str(error)) from error
                return _ListValue([entry[2] for entry in selected])
        if module == "dataclasses" and name == "replace" and len(args) == 1:
            value = args[0]
            if not isinstance(value, _InstanceValue) or not self._is_dataclass(value.class_value):
                raise UnsupportedSyntaxError(
                    "dataclasses.replace() requires a local dataclass instance"
                )
            fields = {field.target.id for field in self._dataclass_fields(value.class_value)}
            if set(keywords) - fields:
                unknown = next(iter(set(keywords) - fields))
                raise ConcolicError(f"unexpected dataclass field {unknown!r}")
            return _InstanceValue(value.class_value, {**value.fields, **keywords})
        if module == "datetime" and name == "timedelta":
            allowed = {
                "days",
                "seconds",
                "microseconds",
                "milliseconds",
                "minutes",
                "hours",
                "weeks",
            }
            if args or set(keywords) - allowed:
                raise UnsupportedSyntaxError(
                    "datetime.timedelta supports its standard keyword arguments"
                )
            return _TimedeltaValue(
                datetime.timedelta(
                    **{key: self._numeric_concrete(value) for key, value in keywords.items()}
                )
            )
        if module == "json":
            if name == "loads" and len(args) == 1 and not keywords:
                try:
                    decoded = json.loads(self._to_string(args[0]).concrete)
                except json.JSONDecodeError as error:
                    raise ConcolicError(str(error)) from error
                return self._constant_value(decoded)
            if name == "dumps" and len(args) == 1:
                allowed = {"ensure_ascii", "indent", "separators", "sort_keys"}
                if set(keywords) - allowed:
                    raise UnsupportedSyntaxError(
                        "json.dumps() supports ensure_ascii, indent, separators, " "and sort_keys"
                    )
                options: dict[str, Any] = {}
                if "ensure_ascii" in keywords:
                    options["ensure_ascii"] = self._truthy(keywords["ensure_ascii"]).concrete
                if "sort_keys" in keywords:
                    options["sort_keys"] = self._truthy(keywords["sort_keys"]).concrete
                if "indent" in keywords:
                    options["indent"] = self._as_int(keywords["indent"]).concrete
                if "separators" in keywords:
                    options["separators"] = tuple(
                        self._to_string(item).concrete
                        for item in self._iter_values(keywords["separators"])
                    )
                try:
                    encoded = json.dumps(_concrete(args[0]), **options)
                except (TypeError, ValueError) as error:
                    raise ConcolicError(str(error)) from error
                return _StringValue(encoded, self._z3.StringVal(encoded))
        if module == "itertools" and name == "accumulate":
            if not 1 <= len(args) <= 2 or set(keywords) - {"func", "initial"}:
                raise UnsupportedSyntaxError(
                    "itertools.accumulate() supports iterable, func, and initial"
                )
            if len(args) == 2 and "func" in keywords:
                raise ConcolicError("accumulate() received func more than once")
            function = keywords.get("func", args[1] if len(args) == 2 else None)
            has_initial = "initial" in keywords
            return _AccumulateIteratorValue(
                self._as_iterator(args[0]),
                function,
                keywords.get("initial"),
                False,
                has_initial,
            )
        if module == "itertools" and name == "zip_longest":
            if set(keywords) - {"fillvalue"}:
                raise UnsupportedSyntaxError("itertools.zip_longest() supports only fillvalue")
            fillvalue = keywords.get("fillvalue", None)
            return _ZipLongestIteratorValue(
                tuple(self._as_iterator(argument) for argument in args), fillvalue
            )
        if keywords:
            raise UnsupportedSyntaxError(f"{module}.{name} does not support keyword arguments")
        if module == "math":
            if name == "sqrt" and len(args) == 1:
                value = self._numeric_concrete(args[0])
                if value < 0:
                    raise ConcolicError("math domain error")
                concrete = math.sqrt(value)
                return _FloatValue(concrete, self._z3.RealVal(str(concrete)))
            if name == "fabs" and len(args) == 1:
                concrete = abs(self._numeric_concrete(args[0]))
                return _FloatValue(concrete, self._z3.RealVal(str(concrete)))
            if name in {"floor", "ceil"} and len(args) == 1:
                concrete = getattr(math, name)(self._numeric_concrete(args[0]))
                return _IntValue(concrete, self._z3.IntVal(concrete))
            if name == "trunc" and len(args) == 1:
                concrete = math.trunc(self._numeric_concrete(args[0]))
                return _IntValue(concrete, self._z3.IntVal(concrete))
            if name == "isfinite" and len(args) == 1:
                concrete = math.isfinite(self._numeric_concrete(args[0]))
                return _BoolValue(concrete, self._z3.BoolVal(concrete))
            if name == "isclose" and len(args) == 2:
                concrete = math.isclose(
                    self._numeric_concrete(args[0]), self._numeric_concrete(args[1])
                )
                return _BoolValue(concrete, self._z3.BoolVal(concrete))
            if name == "gcd" and len(args) == 2:
                concrete = math.gcd(self._as_int(args[0]).concrete, self._as_int(args[1]).concrete)
                return _IntValue(concrete, self._z3.IntVal(concrete))
            if name == "factorial" and len(args) == 1:
                concrete = math.factorial(self._as_int(args[0]).concrete)
                return _IntValue(concrete, self._z3.IntVal(concrete))
            if name in {"comb", "perm"} and 1 <= len(args) <= 2:
                integers = [self._as_int(argument).concrete for argument in args]
                concrete = getattr(math, name)(*integers)
                return _IntValue(concrete, self._z3.IntVal(concrete))
            if name in {"degrees", "exp", "log10", "radians"} and len(args) == 1:
                try:
                    concrete = getattr(math, name)(self._numeric_concrete(args[0]))
                except (OverflowError, ValueError) as error:
                    raise ConcolicError(str(error)) from error
                return _FloatValue(concrete, self._z3.RealVal(str(concrete)))
            if name == "log" and 1 <= len(args) <= 2:
                try:
                    concrete = math.log(*(self._numeric_concrete(argument) for argument in args))
                except (OverflowError, ValueError) as error:
                    raise ConcolicError(str(error)) from error
                return _FloatValue(concrete, self._z3.RealVal(str(concrete)))
        if module == "dataclasses" and name in {"asdict", "astuple"} and len(args) == 1:
            value = args[0]
            if not isinstance(value, _InstanceValue) or not self._is_dataclass(value.class_value):
                raise UnsupportedSyntaxError(
                    f"dataclasses.{name}() requires a local dataclass instance"
                )
            values = [
                self._dataclass_serialized(value.fields[field.target.id])
                for field in self._dataclass_fields(value.class_value)
            ]
            if name == "astuple":
                return _TupleValue(tuple(values))
            return _DictValue(
                {
                    field.target.id: item
                    for field, item in zip(
                        self._dataclass_fields(value.class_value), values, strict=True
                    )
                }
            )
        if module == "base64" and name in {"b64encode", "b64decode"} and len(args) == 1:
            payload = self._to_bytes(args[0]).concrete
            try:
                concrete = getattr(base64, name)(payload)
            except ValueError as error:
                raise ConcolicError(str(error)) from error
            return _BytesValue(concrete)
        if module == "datetime":
            if name == "date" and len(args) == 3:
                return _DateTimeValue(
                    datetime.date(*(self._as_int(value).concrete for value in args))
                )
            if name == "datetime" and 3 <= len(args) <= 7:
                return _DateTimeValue(
                    datetime.datetime(*(self._as_int(value).concrete for value in args))
                )
            if name in {"date.fromisoformat", "datetime.fromisoformat"} and len(args) == 1:
                factory = datetime.datetime if name.startswith("datetime") else datetime.date
                return _DateTimeValue(factory.fromisoformat(self._to_string(args[0]).concrete))
        if (
            module == "hashlib"
            and name
            in {
                "md5",
                "sha1",
                "sha224",
                "sha256",
                "sha384",
                "sha512",
            }
            and len(args) <= 1
        ):
            return _HashValue(name, b"" if not args else self._to_bytes(args[0]).concrete)
        if module == "pathlib" and name == "Path":
            if not args:
                return _PathValue(".")
            return _PathValue(
                posixpath.join(*(self._to_string(argument).concrete for argument in args))
            )
        if module == "urllib.parse":
            if name in {"quote", "unquote"} and len(args) == 1:
                concrete = getattr(urlparse, name)(self._to_string(args[0]).concrete)
                return _StringValue(concrete, self._z3.StringVal(concrete))
            if name == "urljoin" and len(args) == 2:
                concrete = urlparse.urljoin(
                    self._to_string(args[0]).concrete,
                    self._to_string(args[1]).concrete,
                )
                return _StringValue(concrete, self._z3.StringVal(concrete))
            if name == "urlencode" and len(args) == 1:
                concrete = urlparse.urlencode(_concrete(args[0]), doseq=True)
                return _StringValue(concrete, self._z3.StringVal(concrete))
            if name == "parse_qs" and len(args) == 1:
                return self._constant_value(urlparse.parse_qs(self._to_string(args[0]).concrete))
            if name == "parse_qsl" and len(args) == 1:
                return _ListValue(
                    [
                        _TupleValue(
                            tuple(_StringValue(item, self._z3.StringVal(item)) for item in pair)
                        )
                        for pair in urlparse.parse_qsl(self._to_string(args[0]).concrete)
                    ]
                )
            if name in {"urlparse", "urlsplit"} and len(args) == 1:
                return _URLParseValue(getattr(urlparse, name)(self._to_string(args[0]).concrete))
        if (
            module == "statistics"
            and name in {"fmean", "mean", "median", "pvariance", "pstdev"}
            and len(args) == 1
        ):
            values = [self._numeric_concrete(value) for value in self._iter_values(args[0])]
            try:
                concrete = getattr(statistics, name)(values)
            except statistics.StatisticsError as error:
                raise ConcolicError(str(error)) from error
            return _FloatValue(float(concrete), self._z3.RealVal(str(concrete)))
        if module == "itertools":
            if name == "chain":
                return _ChainIteratorValue(tuple(self._as_iterator(argument) for argument in args))
            if name == "islice" and 2 <= len(args) <= 4:
                offsets = [
                    None if argument is None else self._as_int(argument).concrete
                    for argument in args[1:]
                ]
                start, stop, step = (
                    (0, offsets[0], 1)
                    if len(offsets) == 1
                    else (
                        offsets[0],
                        offsets[1],
                        offsets[2] if len(offsets) == 3 else 1,
                    )
                )
                if start is None:
                    start = 0
                if step is None:
                    step = 1
                if start < 0 or (stop is not None and stop < 0) or step <= 0:
                    raise ConcolicError("islice indices must be non-negative")
                return _ISliceIteratorValue(self._as_iterator(args[0]), start, stop, step)
            if name == "repeat" and 1 <= len(args) <= 2:
                times = self._as_int(args[1]).concrete if len(args) == 2 else None
                return _RepeatIteratorValue(args[0], times)
            if name == "product" and args:
                rows: list[tuple[Any, ...]] = [()]
                for argument in args:
                    rows = [(*row, item) for row in rows for item in self._iter_values(argument)]
                return _ListValue([_TupleValue(row) for row in rows])
            if name in {"combinations", "permutations"} and 1 <= len(args) <= 2:
                values = self._iter_values(args[0])
                size = self._as_int(args[1]).concrete if len(args) == 2 else len(values)
                return _ListValue(
                    [_TupleValue(tuple(row)) for row in getattr(itertools, name)(values, size)]
                )
            if name == "pairwise" and len(args) == 1:
                return _PairwiseIteratorValue(self._as_iterator(args[0]))
        if module == "collections" and name == "Counter" and len(args) <= 1:
            values = () if not args else self._iter_values(args[0])
            counts: dict[int | str | bool, Any] = {}
            for item in values:
                key = self._key(item)
                previous = counts.get(key, self._literal(0))
                counts[key] = self._binary(previous, ast.Add(), self._literal(1))
            return _CounterValue(counts)
        if module == "collections" and name == "namedtuple" and len(args) == 2:
            class_name = self._to_string(args[0]).concrete
            field_specification = args[1]
            if isinstance(field_specification, _StringValue):
                fields = tuple(
                    field
                    for field in field_specification.concrete.replace(",", " ").split()
                    if field
                )
            else:
                fields = tuple(
                    self._to_string(field).concrete
                    for field in self._iter_values(field_specification)
                )
            if not fields or len(set(fields)) != len(fields):
                raise ConcolicError("namedtuple fields must be distinct and non-empty")
            return _NamedTupleClass(class_name, fields)
        if module == "collections" and name == "defaultdict" and len(args) == 1:
            return _DefaultDictValue({}, args[0])
        if module == "collections" and name == "deque" and len(args) <= 1:
            return _DequeValue([] if not args else list(self._iter_values(args[0])))
        if module == "functools" and name == "reduce" and 2 <= len(args) <= 3:
            values = list(self._iter_values(args[1]))
            if len(args) == 3:
                accumulator = args[2]
            elif values:
                accumulator = values.pop(0)
            else:
                raise ConcolicError("reduce() of empty iterable with no initial value")
            for item in values:
                accumulator = self._call_value(args[0], [accumulator, item], {})
            return accumulator
        if (
            module == "os.path"
            and name
            in {
                "basename",
                "dirname",
                "normpath",
                "splitext",
            }
            and len(args) == 1
        ):
            path = self._to_string(args[0]).concrete
            result = getattr(posixpath, name)(path)
            if name == "splitext":
                return _TupleValue(
                    tuple(_StringValue(item, self._z3.StringVal(item)) for item in result)
                )
            return _StringValue(result, self._z3.StringVal(result))
        if module == "os.path" and name == "join" and args:
            result = posixpath.join(*(self._to_string(argument).concrete for argument in args))
            return _StringValue(result, self._z3.StringVal(result))
        raise UnsupportedSyntaxError(f"unsupported library summary {module}.{name}")
