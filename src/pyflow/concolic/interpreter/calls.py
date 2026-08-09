"""call support for the AST executor."""

from __future__ import annotations

import ast

import datetime

import hashlib

import posixpath

import re

from pathlib import Path

from typing import Any

from ..runtime import (
    ConcolicError,
    FunctionNode,
    UnsupportedSyntaxError,
    _BoolValue,
    _AsyncContextOperation,
    _AsyncGeneratorOperation,
    _BytesValue,
    _ClassValue,
    _DateTimeValue,
    _DequeValue,
    _DictValue,
    _ExceptionType,
    _FloatValue,
    _FunctionValue,
    _GeneratorContext,
    _HashValue,
    _ImportlibModule,
    _InstanceValue,
    _IntValue,
    _IteratorValue,
    _ListValue,
    _ModuleValue,
    _NamedTupleValue,
    _NullContext,
    _PathValue,
    _RegexMatch,
    _RegexModule,
    _RegexPattern,
    _ResumeKind,
    _ResumeOperation,
    _ResumableFrame,
    _Returned,
    _Return,
    _SetValue,
    _StringValue,
    _SummaryFunction,
    _SummaryModule,
    _SuperValue,
    _SuppressContext,
    _TimedeltaValue,
    _TaskValue,
    _TargetException,
    _TupleValue,
    _URLParseValue,
)

from ..module_loader import _contains_yield, _import_local_module
from ..support import _concrete


class _CallMixin:
    def _call_function(
        self,
        function: FunctionNode,
        args: list[Any],
        keywords: dict[str, Any] | None = None,
        current_class: _ClassValue | None = None,
        current_instance: _InstanceValue | None = None,
    ) -> Any:
        bound = self._bind_arguments(function, args, keywords or {})
        if _contains_yield(function) or isinstance(function, ast.AsyncFunctionDef):
            return self._make_resumable_frame(
                function,
                bound,
                current_class=current_class,
                current_instance=current_instance,
            )
        previous_env = self.env
        previous_globals = self._global_names
        previous_class = self._current_class
        previous_instance = self._current_instance
        self.env = bound
        self._global_names = set()
        self._current_class = current_class
        self._current_instance = current_instance
        try:
            outcome = self._execute_block(function.body)
        finally:
            self.env = previous_env
            self._global_names = previous_globals
            self._current_class = previous_class
            self._current_instance = previous_instance
        return outcome.value if isinstance(outcome, _Return) else None

    def _call_scoped_function(
        self,
        function: FunctionNode,
        args: list[Any],
        keywords: dict[str, Any],
        module: _ModuleValue | None,
        current_class: _ClassValue | None = None,
        current_instance: _InstanceValue | None = None,
    ) -> Any:
        if module is None:
            return self._call_function(
                function, args, keywords, current_class, current_instance
            )
        previous_functions = self._functions
        previous_classes = self._classes
        previous_globals = self._globals
        previous_module = self._current_module
        self._functions = module.functions
        self._classes = module.classes
        self._globals = module.globals
        self._current_module = module
        try:
            return self._call_function(
                function, args, keywords, current_class, current_instance
            )
        finally:
            self._functions = previous_functions
            self._classes = previous_classes
            self._globals = previous_globals
            self._current_module = previous_module

    def _call_function_value(
        self, value: _FunctionValue, args: list[Any], keywords: dict[str, Any]
    ) -> Any:
        if value.module is not None:
            return self._call_scoped_function(
                value.definition, args, keywords, value.module
            )
        if isinstance(value.definition, ast.Lambda):
            bound = self._bind_arguments(value.definition, args, keywords)
            previous_env = self.env
            previous_global_names = self._global_names
            previous_nonlocal_names = self._nonlocal_names
            previous_closure_env = self._closure_env
            self.env = {**value.closure, **bound}
            self._global_names = set()
            self._nonlocal_names = set()
            self._closure_env = value.closure
            try:
                return self._evaluate(value.definition.body)
            finally:
                self.env = previous_env
                self._global_names = previous_global_names
                self._nonlocal_names = previous_nonlocal_names
                self._closure_env = previous_closure_env
        bound = self._bind_arguments(value.definition, args, keywords)
        environment = {**value.closure, **bound}
        if _contains_yield(value.definition) or isinstance(
            value.definition, ast.AsyncFunctionDef
        ):
            return self._make_resumable_frame(
                value.definition,
                environment,
                closure=value.closure,
            )
        previous_env = self.env
        previous_global_names = self._global_names
        previous_nonlocal_names = self._nonlocal_names
        previous_closure_env = self._closure_env
        self.env = environment
        self._global_names = set()
        self._nonlocal_names = set()
        self._closure_env = value.closure
        try:
            outcome = self._execute_block(value.definition.body)
        finally:
            self.env = previous_env
            self._global_names = previous_global_names
            self._nonlocal_names = previous_nonlocal_names
            self._closure_env = previous_closure_env
        return outcome.value if isinstance(outcome, _Return) else None

    def _function_value(self, function: FunctionNode) -> Any:
        key = (id(function), id(self._current_module))
        if key in self._decorated_functions:
            return self._decorated_functions[key]
        value: Any = _FunctionValue(function, self.env, self._current_module)
        self._decorated_functions[key] = value
        for decorator in reversed(function.decorator_list):
            value = self._call_value(self._evaluate(decorator), [value], {})
        self._decorated_functions[key] = value
        return value

    def _class_value(self, class_value: _ClassValue) -> Any:
        key = (id(class_value), id(class_value.module))
        if key in self._decorated_classes:
            return self._decorated_classes[key]
        value: Any = class_value
        self._decorated_classes[key] = value
        previous_env = self.env
        previous_functions = self._functions
        previous_classes = self._classes
        previous_globals = self._globals
        previous_module = self._current_module
        self.env = dict(class_value.closure)
        if class_value.module is not None:
            self._functions = class_value.module.functions
            self._classes = class_value.module.classes
            self._globals = class_value.module.globals
            self._current_module = class_value.module
        try:
            for decorator in reversed(class_value.definition.decorator_list):
                if self._is_dataclass_decorator(decorator):
                    continue
                value = self._call_value(self._evaluate(decorator), [value], {})
        finally:
            self.env = previous_env
            self._functions = previous_functions
            self._classes = previous_classes
            self._globals = previous_globals
            self._current_module = previous_module
        self._decorated_classes[key] = value
        return value

    def _bind_arguments(
        self,
        function: FunctionNode | ast.Lambda,
        args: list[Any],
        keywords: dict[str, Any],
    ) -> dict[str, Any]:
        signature = function.args
        positional = tuple(signature.posonlyargs) + tuple(signature.args)
        if len(args) > len(positional) and signature.vararg is None:
            raise ConcolicError(
                f"{getattr(function, 'name', '<lambda>')} received too many arguments"
            )
        bound = {parameter.arg: value for parameter, value in zip(positional, args)}
        positional_only = {parameter.arg for parameter in signature.posonlyargs}
        regular = {parameter.arg for parameter in signature.args}
        extra_keywords: dict[str, Any] = {}
        for name, value in keywords.items():
            if name in positional_only:
                raise ConcolicError(
                    f"positional-only argument passed as keyword: {name!r}"
                )
            if name in regular or name in {
                parameter.arg for parameter in signature.kwonlyargs
            }:
                if name in bound:
                    raise ConcolicError(f"multiple values for argument {name!r}")
                bound[name] = value
            else:
                extra_keywords[name] = value
        default_offset = len(positional) - len(signature.defaults)
        for index, parameter in enumerate(positional):
            if parameter.arg not in bound:
                if index < default_offset:
                    raise ConcolicError(f"missing required argument {parameter.arg!r}")
                bound[parameter.arg] = self._evaluate(
                    signature.defaults[index - default_offset]
                )
        if signature.vararg is not None:
            bound[signature.vararg.arg] = _TupleValue(tuple(args[len(positional) :]))
        if signature.kwarg is not None:
            bound[signature.kwarg.arg] = _DictValue(extra_keywords)
        elif extra_keywords:
            name = next(iter(extra_keywords))
            raise ConcolicError(f"unexpected keyword argument {name!r}")
        for parameter, default in zip(signature.kwonlyargs, signature.kw_defaults):
            if parameter.arg not in bound:
                if default is None:
                    raise ConcolicError(
                        f"missing required keyword-only argument {parameter.arg!r}"
                    )
                bound[parameter.arg] = self._evaluate(default)
        return bound

    def _call_attribute(
        self, value: Any, name: str, args: list[Any], keywords: dict[str, Any]
    ) -> Any:
        if isinstance(value, _ResumableFrame) and value.is_async_generator:
            if name == "__aiter__" and not args and not keywords:
                return value
            if name == "__anext__" and not args and not keywords:
                return _AsyncGeneratorOperation(
                    value, _ResumeOperation(_ResumeKind.NEXT)
                )
            if name == "asend" and len(args) == 1 and not keywords:
                return _AsyncGeneratorOperation(
                    value, _ResumeOperation(_ResumeKind.SEND, args[0])
                )
            if name == "athrow" and 1 <= len(args) <= 3 and not keywords:
                exception = args[0]
                if isinstance(exception, _ExceptionType):
                    message = str(_concrete(args[1])) if len(args) >= 2 else ""
                    exception = _TargetException(exception.name, message)
                if not isinstance(exception, BaseException):
                    raise ConcolicError("async generator athrow() requires an exception")
                return _AsyncGeneratorOperation(
                    value, _ResumeOperation(_ResumeKind.THROW, exception)
                )
            if name == "aclose" and not args and not keywords:
                return _AsyncGeneratorOperation(
                    value,
                    _ResumeOperation(
                        _ResumeKind.THROW, _TargetException("GeneratorExit")
                    ),
                    closing=True,
                )
        if isinstance(value, _IteratorValue):
            if name == "__iter__" and not args and not keywords:
                return value
            if (
                name == "__next__"
                and not (
                    isinstance(value, _ResumableFrame) and value.is_async_generator
                )
                and not keywords
            ):
                if args:
                    raise ConcolicError("iterator.__next__() takes no arguments")
                resumed = self._resume_iterator(
                    value, _ResumeOperation(_ResumeKind.NEXT)
                )
                if isinstance(resumed, _Returned):
                    raise _TargetException("StopIteration", str(resumed.value or ""))
                return resumed.value
            if (
                name == "send"
                and isinstance(value, _ResumableFrame)
                and not value.is_async_generator
                and not keywords
            ):
                if len(args) != 1:
                    raise ConcolicError("generator.send() takes one argument")
                resumed = self._resume_iterator(
                    value, _ResumeOperation(_ResumeKind.SEND, args[0])
                )
                if isinstance(resumed, _Returned):
                    raise _TargetException("StopIteration", str(resumed.value or ""))
                return resumed.value
            if (
                name == "throw"
                and isinstance(value, _ResumableFrame)
                and not value.is_async_generator
                and 1 <= len(args) <= 3
                and not keywords
            ):
                exception = args[0]
                if isinstance(exception, _ExceptionType):
                    message = str(_concrete(args[1])) if len(args) >= 2 else ""
                    exception = _TargetException(exception.name, message)
                if not isinstance(exception, BaseException):
                    raise ConcolicError("generator.throw() requires an exception")
                resumed = self._resume_iterator(
                    value, _ResumeOperation(_ResumeKind.THROW, exception)
                )
                if isinstance(resumed, _Returned):
                    raise _TargetException("StopIteration", str(resumed.value or ""))
                return resumed.value
            if (
                name == "close"
                and isinstance(value, _ResumableFrame)
                and not value.is_async_generator
                and not args
                and not keywords
            ):
                self._resume_iterator(value, _ResumeOperation(_ResumeKind.CLOSE))
                return None
        if isinstance(value, _TaskValue):
            if name == "done" and not args and not keywords:
                return _BoolValue(value.done, self._z3.BoolVal(value.done))
            if name == "cancelled" and not args and not keywords:
                cancelled = value.done and isinstance(
                    value.exception, _TargetException
                ) and value.exception.name == "CancelledError"
                return _BoolValue(cancelled, self._z3.BoolVal(cancelled))
            if name == "result" and not args and not keywords:
                if not value.done:
                    raise _TargetException(
                        "InvalidStateError", "result is not ready"
                    )
                if value.exception is not None:
                    raise value.exception
                return value.result
            if name == "exception" and not args and not keywords:
                if not value.done:
                    raise _TargetException(
                        "InvalidStateError", "exception is not set"
                    )
                if isinstance(value.exception, _TargetException) and (
                    value.exception.name == "CancelledError"
                ):
                    raise value.exception
                return value.exception
            if name == "get_name" and not args and not keywords:
                concrete = value.name or "Task"
                return _StringValue(concrete, self._z3.StringVal(concrete))
            if name == "cancel" and not args and not keywords:
                if value.done:
                    return _BoolValue(False, self._z3.BoolVal(False))
                value.cancel_requested = True
                return _BoolValue(True, self._z3.BoolVal(True))
        if isinstance(value, _GeneratorContext):
            if name == "__aenter__" and not args and not keywords:
                return _AsyncContextOperation(value, True)
            if name == "__aexit__" and len(args) == 3 and not keywords:
                return _AsyncContextOperation(value, False, tuple(args))
            if name in {"__enter__", "__aenter__"} and not args and not keywords:
                if value.entered:
                    raise _TargetException(
                        "RuntimeError", "generator context manager cannot be re-entered"
                    )
                value.entered = True
                resumed = self._resume_iterator(
                    value.iterator, _ResumeOperation(_ResumeKind.NEXT)
                )
                if isinstance(resumed, _Returned):
                    raise _TargetException(
                        "RuntimeError", "contextmanager generator did not yield"
                    )
                return resumed.value
            if name in {"__exit__", "__aexit__"} and len(args) == 3 and not keywords:
                if value.exited:
                    return _BoolValue(False, self._z3.BoolVal(False))
                value.exited = True
                if args[0] is None:
                    resumed = self._resume_iterator(
                        value.iterator, _ResumeOperation(_ResumeKind.NEXT)
                    )
                    if not isinstance(resumed, _Returned):
                        raise _TargetException(
                            "RuntimeError", "contextmanager generator did not stop"
                        )
                    return _BoolValue(False, self._z3.BoolVal(False))
                exception = _TargetException(
                    self._to_string(args[0]).concrete,
                    self._to_string(args[1]).concrete,
                )
                try:
                    resumed = self._resume_iterator(
                        value.iterator,
                        _ResumeOperation(_ResumeKind.THROW, exception),
                    )
                except _TargetException as raised:
                    if raised.name == exception.name and raised.message == exception.message:
                        return _BoolValue(False, self._z3.BoolVal(False))
                    raise
                if not isinstance(resumed, _Returned):
                    raise _TargetException(
                        "RuntimeError", "contextmanager generator did not stop"
                    )
                return _BoolValue(True, self._z3.BoolVal(True))
        if isinstance(value, _URLParseValue) and name == "geturl" and not args:
            if keywords:
                raise UnsupportedSyntaxError(
                    "urllib.parse result methods do not support keyword arguments"
                )
            concrete = value.concrete.geturl()
            return _StringValue(concrete, self._z3.StringVal(concrete))
        if isinstance(value, _SuppressContext):
            if keywords:
                raise UnsupportedSyntaxError(
                    "contextlib.suppress methods do not support keyword arguments"
                )
            if name in {"__enter__", "__aenter__"} and not args:
                return None
            if name in {"__exit__", "__aexit__"} and len(args) == 3:
                if args[0] is None:
                    return _BoolValue(False, self._z3.BoolVal(False))
                error_name = self._to_string(args[0]).concrete
                concrete = (
                    error_name in value.exception_names
                    or "Exception" in value.exception_names
                    or "BaseException" in value.exception_names
                    or (
                        error_name in {"IndexError", "KeyError"}
                        and "LookupError" in value.exception_names
                    )
                )
                return _BoolValue(concrete, self._z3.BoolVal(concrete))
        if isinstance(value, _NullContext):
            if name in {"__enter__", "__aenter__"} and not args:
                return value.value
            if name in {"__exit__", "__aexit__"} and len(args) == 3:
                return _BoolValue(False, self._z3.BoolVal(False))
        if isinstance(value, _NamedTupleValue):
            if name == "_asdict" and not args and not keywords:
                return _DictValue(
                    dict(zip(value.class_value.fields, value.values, strict=True))
                )
            if name == "_replace" and not args:
                replacements = dict(
                    zip(value.class_value.fields, value.values, strict=True)
                )
                if set(keywords) - set(replacements):
                    unknown = next(iter(set(keywords) - set(replacements)))
                    raise ConcolicError(f"unknown namedtuple field {unknown!r}")
                replacements.update(keywords)
                return _NamedTupleValue(
                    value.class_value,
                    tuple(replacements[field] for field in value.class_value.fields),
                )
            if name in {"count", "index"} and len(args) == 1 and not keywords:
                matches = [
                    index
                    for index, item in enumerate(value.values)
                    if self._equals(item, args[0]).concrete
                ]
                if name == "count":
                    return _IntValue(len(matches), self._z3.IntVal(len(matches)))
                if not matches:
                    raise ConcolicError("namedtuple.index(x): x not in tuple")
                return _IntValue(matches[0], self._z3.IntVal(matches[0]))
        if isinstance(value, _SummaryFunction):
            return self._call_summary(
                value.module, f"{value.name}.{name}", args, keywords
            )
        if isinstance(value, _DateTimeValue):
            if keywords:
                raise UnsupportedSyntaxError(
                    "datetime methods do not support keyword arguments"
                )
            if name == "isoformat" and not args:
                concrete = value.concrete.isoformat()
                return _StringValue(concrete, self._z3.StringVal(concrete))
            if name == "strftime" and len(args) == 1:
                concrete = value.concrete.strftime(self._to_string(args[0]).concrete)
                return _StringValue(concrete, self._z3.StringVal(concrete))
            if (
                name == "date"
                and not args
                and isinstance(value.concrete, datetime.datetime)
            ):
                return _DateTimeValue(value.concrete.date())
            if name in {"weekday", "isoweekday"} and not args:
                concrete = getattr(value.concrete, name)()
                return _IntValue(concrete, self._z3.IntVal(concrete))
        if isinstance(value, _TimedeltaValue):
            if keywords:
                raise UnsupportedSyntaxError(
                    "timedelta methods do not support keyword arguments"
                )
            if name == "total_seconds" and not args:
                concrete = value.concrete.total_seconds()
                return _FloatValue(concrete, self._z3.RealVal(str(concrete)))
        if isinstance(value, _HashValue):
            if keywords:
                raise UnsupportedSyntaxError(
                    "hashlib hash methods do not support keyword arguments"
                )
            digest = getattr(hashlib, value.algorithm)(value.payload)
            if name == "digest" and not args:
                return _BytesValue(digest.digest())
            if name == "hexdigest" and not args:
                concrete = digest.hexdigest()
                return _StringValue(concrete, self._z3.StringVal(concrete))
            if name == "update" and len(args) == 1:
                value.payload += self._to_bytes(args[0]).concrete
                return None
            if name == "copy" and not args:
                return _HashValue(value.algorithm, value.payload)
        if isinstance(value, _PathValue):
            if keywords:
                raise UnsupportedSyntaxError(
                    "pathlib path methods do not support keyword arguments"
                )
            if name == "as_posix" and not args:
                return _StringValue(value.concrete, self._z3.StringVal(value.concrete))
            if name == "joinpath":
                return _PathValue(
                    posixpath.join(
                        value.concrete,
                        *(self._to_string(argument).concrete for argument in args),
                    )
                )
            if name == "with_suffix" and len(args) == 1:
                suffix = self._to_string(args[0]).concrete
                stem, _ = posixpath.splitext(value.concrete)
                return _PathValue(stem + suffix)
            if name == "is_absolute" and not args:
                concrete = posixpath.isabs(value.concrete)
                return _BoolValue(concrete, self._z3.BoolVal(concrete))
        if isinstance(value, _StringValue):
            if name == "format":
                return self._string_format(value, args, keywords)
            if keywords:
                raise UnsupportedSyntaxError(
                    "keyword arguments are only supported for user functions"
                )
            return self._string_method(value, name, args)
        if isinstance(value, _BytesValue):
            if keywords:
                raise UnsupportedSyntaxError(
                    "keyword arguments are only supported for user functions"
                )
            return self._bytes_method(value, name, args)
        if isinstance(value, _ListValue):
            if isinstance(value, _DequeValue):
                return self._deque_method(value, name, args, keywords)
            return self._list_method(value, name, args, keywords)
        if isinstance(value, _SetValue):
            if keywords:
                raise UnsupportedSyntaxError(
                    "set methods do not support keyword arguments"
                )
            return self._set_method(value, name, args)
        if isinstance(value, _DictValue):
            return self._dict_method(value, name, args, keywords)
        if isinstance(value, _InstanceValue):
            method_with_owner = self._method_with_owner(value.class_value, name)
            if method_with_owner is not None:
                method, owner = method_with_owner
                return self._call_method(method, owner, value, args, keywords)
            fallback = self._method_with_owner(value.class_value, "__getattr__")
            if fallback is not None:
                method, owner = fallback
                dynamic_value = self._call_method(
                    method,
                    owner,
                    value,
                    [_StringValue(name, self._z3.StringVal(name))],
                    {},
                )
                return self._call_value(dynamic_value, args, keywords)
        if isinstance(value, _ClassValue):
            method_with_owner = self._method_with_owner(value, name)
            if method_with_owner is not None:
                method, owner = method_with_owner
                return self._call_method(method, owner, None, args, keywords)
        if isinstance(value, _SuperValue):
            method_with_owner = self._method_after(
                value.instance.class_value, value.start_class, name
            )
            if method_with_owner is not None:
                method, owner = method_with_owner
                return self._call_method(method, owner, value.instance, args, keywords)
        if isinstance(value, _ModuleValue):
            if name in value.functions:
                return self._call_scoped_function(
                    value.functions[name], args, keywords, value
                )
            if name in value.classes:
                class_value = self._class_value(value.classes[name])
                if isinstance(class_value, _ClassValue):
                    return self._construct(class_value, args, keywords)
                return self._call_value(class_value, args, keywords)
        if isinstance(value, _SummaryModule):
            if value.name == "os" and name == "path" and not args and not keywords:
                return _SummaryModule("os.path")
            return self._call_summary(value.name, name, args, keywords)
        if isinstance(value, _ImportlibModule) and name == "import_module":
            return self._import_local_by_name(value.path, value.cache, args, keywords)
        if isinstance(value, _RegexModule):
            if name == "compile" and 1 <= len(args) <= 2 and not keywords:
                flags = self._as_int(args[1]).concrete if len(args) == 2 else 0
                return _RegexPattern(
                    re.compile(self._to_string(args[0]).concrete, flags)
                )
            if name == "escape" and len(args) == 1 and not keywords:
                concrete = re.escape(self._to_string(args[0]).concrete)
                return _StringValue(concrete, self._z3.StringVal(concrete))
            if name in {"match", "search", "fullmatch", "findall"}:
                if not 2 <= len(args) <= 3:
                    raise UnsupportedSyntaxError(f"re.{name} requires a pattern")
                flags = self._as_int(args[2]).concrete if len(args) == 3 else 0
                pattern = _RegexPattern(
                    re.compile(self._to_string(args[0]).concrete, flags)
                )
                return self._call_attribute(pattern, name, [args[1]], keywords)
            if name == "sub":
                if not 3 <= len(args) <= 4:
                    raise UnsupportedSyntaxError("re.sub requires a pattern")
                pattern = _RegexPattern(re.compile(self._to_string(args[0]).concrete))
                return self._call_attribute(pattern, name, args[1:], keywords)
            if name == "split" and 2 <= len(args) <= 4 and not keywords:
                maxsplit = self._as_int(args[2]).concrete if len(args) >= 3 else 0
                flags = self._as_int(args[3]).concrete if len(args) == 4 else 0
                pattern = _RegexPattern(
                    re.compile(self._to_string(args[0]).concrete, flags)
                )
                return self._call_attribute(
                    pattern, name, [args[1], self._literal(maxsplit)], {}
                )
        if (
            isinstance(value, _RegexPattern)
            and name in {"match", "search", "fullmatch"}
            and len(args) == 1
        ):
            if keywords:
                raise UnsupportedSyntaxError(
                    "keyword arguments are only supported for user functions"
                )
            match = getattr(value.pattern, name)(self._to_string(args[0]).concrete)
            return _RegexMatch(match) if match is not None else None
        if isinstance(value, _RegexPattern) and name == "findall" and len(args) == 1:
            if keywords:
                raise UnsupportedSyntaxError(
                    "keyword arguments are only supported for user functions"
                )
            matches = value.pattern.findall(self._to_string(args[0]).concrete)
            if matches and isinstance(matches[0], tuple):
                return _ListValue(
                    [
                        _TupleValue(
                            tuple(
                                _StringValue(item, self._z3.StringVal(item))
                                for item in match
                            )
                        )
                        for match in matches
                    ]
                )
            return _ListValue(
                [_StringValue(match, self._z3.StringVal(match)) for match in matches]
            )
        if isinstance(value, _RegexPattern) and name == "sub" and 2 <= len(args) <= 3:
            if keywords:
                raise UnsupportedSyntaxError(
                    "keyword arguments are only supported for user functions"
                )
            count = self._as_int(args[2]).concrete if len(args) == 3 else 0
            concrete = value.pattern.sub(
                self._to_string(args[0]).concrete,
                self._to_string(args[1]).concrete,
                count=count,
            )
            return _StringValue(concrete, self._z3.StringVal(concrete))
        if isinstance(value, _RegexPattern) and name == "split" and 1 <= len(args) <= 2:
            if keywords:
                raise UnsupportedSyntaxError(
                    "keyword arguments are only supported for user functions"
                )
            maxsplit = self._as_int(args[1]).concrete if len(args) == 2 else 0
            return _ListValue(
                [
                    _StringValue(item, self._z3.StringVal(item))
                    for item in value.pattern.split(
                        self._to_string(args[0]).concrete, maxsplit=maxsplit
                    )
                ]
            )
        if isinstance(value, _RegexMatch) and name == "group" and len(args) <= 1:
            if keywords:
                raise UnsupportedSyntaxError(
                    "keyword arguments are only supported for user functions"
                )
            index = (
                self._as_int(args[0]).concrete
                if args and isinstance(args[0], _IntValue)
                else self._to_string(args[0]).concrete
                if args
                else 0
            )
            concrete = value.match.group(index)
            if concrete is None:
                return None
            return _StringValue(concrete, self._z3.StringVal(concrete))
        if isinstance(value, _RegexMatch) and name == "groups" and not args:
            if keywords:
                raise UnsupportedSyntaxError(
                    "keyword arguments are only supported for user functions"
                )
            return _TupleValue(
                tuple(
                    None
                    if item is None
                    else _StringValue(item, self._z3.StringVal(item))
                    for item in value.match.groups()
                )
            )
        if isinstance(value, _RegexMatch) and name == "groupdict" and not args:
            if keywords:
                raise UnsupportedSyntaxError(
                    "keyword arguments are only supported for user functions"
                )
            return _DictValue(
                {
                    key: None
                    if item is None
                    else _StringValue(item, self._z3.StringVal(item))
                    for key, item in value.match.groupdict().items()
                }
            )
        raise UnsupportedSyntaxError(f"unsupported method {name!r}")

    def _import_local_by_name(
        self,
        path: Path,
        cache: dict[Path, _ModuleValue],
        args: list[Any],
        keywords: dict[str, Any],
    ) -> _ModuleValue:
        if keywords or not 1 <= len(args) <= 2:
            raise UnsupportedSyntaxError(
                "importlib.import_module() expects one module name"
            )
        module_name = self._to_string(args[0]).concrete
        level = len(module_name) - len(module_name.lstrip("."))
        resolved = _import_local_module(path, module_name[level:], cache, level)
        if resolved is None:
            raise ConcolicError(f"local module {module_name!r} could not be resolved")
        return resolved[1]
