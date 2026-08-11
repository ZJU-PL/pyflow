"""summary support for the AST executor."""

from __future__ import annotations

import ast

import base64

import binascii

import bisect

import codecs

import copy

import datetime

import fnmatch

import heapq

import html

import importlib

import itertools

import json

import math

import posixpath

import statistics

import struct

import unicodedata

import zlib

from urllib import parse as urlparse

from typing import Any

from ..core.runtime import (
    ConcolicError,
    ExecutionOutcome,
    OperationObservation,
    OutcomeKind,
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
    _SetValue,
    _TargetException,
    _TimedeltaValue,
    _TupleValue,
    _URLParseValue,
    _ZipLongestIteratorValue,
)

from ..core.support import _concrete, _deep_concrete
from .model_registry import (
    ModelPrecision,
    ModelResult,
    OpaqueCallSample,
    OpaqueCallSignature,
    SummaryModelRegistry,
    register_model_families,
)


def _builtin_model_family(
    executor: Any, module: str, name: str, args: list[Any], keywords: dict[str, Any]
) -> Any:
    return executor._call_builtin_summary(module, name, args, keywords)


DEFAULT_MODEL_REGISTRY = SummaryModelRegistry()
register_model_families(
    DEFAULT_MODEL_REGISTRY,
    (
        "asyncio",
        "base64",
        "binascii",
        "bisect",
        "collections",
        "codecs",
        "contextlib",
        "copy",
        "dataclasses",
        "datetime",
        "functools",
        "fnmatch",
        "hashlib",
        "heapq",
        "html",
        "itertools",
        "json",
        "math",
        "operator",
        "os.path",
        "pathlib",
        "statistics",
        "struct",
        "unicodedata",
        "urllib.parse",
        "zlib",
    ),
    _builtin_model_family,
)


class _SummaryMixin:
    _model_registry = DEFAULT_MODEL_REGISTRY

    def _call_summary(
        self, module: str, name: str, args: list[Any], keywords: dict[str, Any]
    ) -> Any:
        handler = self._model_registry.resolve(module, name)
        if handler is not None:
            try:
                result = handler(self, module, name, args, keywords)
            except UnsupportedSyntaxError:
                if not self._refine_opaque_calls:
                    raise
            else:
                return self._apply_model_result(result)
        if self._refine_opaque_calls:
            return self._call_opaque_summary(module, name, args, keywords)
        raise UnsupportedSyntaxError(f"unsupported library summary {module}.{name}")

    def _apply_model_result(self, result: Any) -> Any:
        if not isinstance(result, ModelResult):
            return result
        self.input_constraints.extend(result.assumptions)
        self.guidance_constraints.extend(result.guidance)
        return result.value

    def _call_opaque_summary(
        self,
        module: str,
        name: str,
        args: list[Any],
        keywords: dict[str, Any],
    ) -> Any:
        if module not in _OPAQUE_SAFE_MODULES or "." in name or name.startswith("_"):
            raise UnsupportedSyntaxError(f"unsafe opaque library call {module}.{name}")
        terms = tuple(self._opaque_term(value) for value in args)
        keyword_terms = tuple(
            (key, self._opaque_term(value)) for key, value in sorted(keywords.items())
        )
        if any(term is None for term in terms) or any(term is None for _, term in keyword_terms):
            raise UnsupportedSyntaxError(
                f"opaque library call {module}.{name} requires primitive arguments"
            )
        concrete_args = tuple(_deep_concrete(value) for value in args)
        concrete_keywords = tuple(
            (key, _deep_concrete(value)) for key, value in sorted(keywords.items())
        )
        signature = OpaqueCallSignature(
            module,
            name,
            tuple(self._opaque_kind(value) for value in concrete_args),
            tuple((key, self._opaque_kind(value)) for key, value in concrete_keywords),
        )
        function = self._resolve_opaque_callable(module, name)
        invoked_args = copy.deepcopy(concrete_args)
        invoked_keywords = copy.deepcopy(dict(concrete_keywords))
        original_args = copy.deepcopy(invoked_args)
        original_keywords = copy.deepcopy(invoked_keywords)
        result: Any = None
        error: Exception | None = None
        try:
            result = function(*invoked_args, **invoked_keywords)
        except Exception as caught:
            error = caught
        mutated = invoked_args != original_args or invoked_keywords != original_keywords
        if mutated:
            sources = (*args, *keywords.values())
            self._apply_opaque_mutations(args, invoked_args, sources)
            self._apply_opaque_keyword_mutations(keywords, invoked_keywords, sources)
        result_kind = None if error is not None else self._opaque_kind(result)
        if error is None and result_kind not in _OPAQUE_RESULT_KINDS:
            raise UnsupportedSyntaxError(
                f"opaque library call {signature.display_name} returned unsupported "
                f"type {type(result).__name__}"
            )
        sample = OpaqueCallSample(
            arguments=concrete_args,
            keywords=concrete_keywords,
            result_kind=result_kind,
            result=result,
            exception_type=type(error).__name__ if error is not None else None,
            exception_message=str(error) if error is not None else None,
        )
        added = self._opaque_refinements.observe(
            signature,
            sample,
            max_refinements=self._max_opaque_refinements,
        )
        if added is None:
            raise ConcolicError(
                "opaque refinement limit exceeded " f"({self._max_opaque_refinements})"
            )
        operation_outcome = (
            ExecutionOutcome(
                OutcomeKind.TARGET_EXCEPTION,
                type(error).__name__,
                str(error) or None,
            )
            if error is not None
            else ExecutionOutcome(OutcomeKind.RETURNED)
        )
        self._operation_observations.append(
            OperationObservation(
                module=module,
                name=name,
                arguments=concrete_args,
                keywords=concrete_keywords,
                outcome=operation_outcome,
                result=result,
                post_arguments=tuple(invoked_args),
                post_keywords=tuple(sorted(invoked_keywords.items())),
                precision=(
                    ModelPrecision.OPAQUE.value if mutated else ModelPrecision.REFINED.value
                ),
            )
        )
        all_terms = (*terms, *(term for _, term in keyword_terms))
        exception_expression = self._opaque_function(
            signature, "raises", all_terms, self._z3.BoolSort()
        )
        self._add_opaque_sample_constraints(signature, all_terms, exception_expression)
        exception_guidance = self._synthesize_opaque_exception_guidance(
            function,
            signature,
            terms,
            keyword_terms,
            concrete_args,
            concrete_keywords,
            exception_expression,
        )
        if exception_guidance is not None:
            self.guidance_constraints.append(exception_guidance)
        if error is not None or any(
            observed.raised for observed in self._opaque_refinements.samples(signature)
        ):
            self._record_branch(
                exception_expression,
                error is not None,
                None,
                "opaque_exception",
            )
        if error is not None:
            raise _TargetException(type(error).__name__, str(error))
        if result is None:
            return None
        if result_kind in {"bytes", "list", "tuple", "dict", "set"}:
            return self._constant_value(result)
        assert result_kind is not None
        result_sort = self._opaque_sort(result_kind)
        result_expression = self._opaque_function(
            signature, f"result_{result_kind}", all_terms, result_sort
        )
        self._add_opaque_result_constraints(
            signature,
            all_terms,
            result_expression,
            result_kind,
        )
        guidance = self._synthesize_opaque_guidance(
            function,
            signature,
            terms,
            keyword_terms,
            concrete_args,
            concrete_keywords,
            result_expression,
            result,
        )
        return self._apply_model_result(
            ModelResult(
                self._opaque_value(result, result_expression),
                ModelPrecision.REFINED,
                guidance=(guidance,) if guidance is not None else (),
            )
        )

    def _opaque_term(self, value: Any) -> Any | None:
        if isinstance(value, (_BoolValue, _IntValue, _FloatValue, _StringValue)):
            return value.symbolic
        concrete = _deep_concrete(value)
        if isinstance(concrete, bool):
            return self._z3.BoolVal(concrete)
        if isinstance(concrete, int):
            return self._z3.IntVal(concrete)
        if isinstance(concrete, float) and math.isfinite(concrete):
            return self._z3.RealVal(str(concrete))
        if isinstance(concrete, str):
            return self._z3.StringVal(concrete)
        if isinstance(concrete, (bytes, list, tuple, dict, set)):
            return self._z3.StringVal(_opaque_container_token(concrete))
        return None

    @staticmethod
    def _opaque_kind(value: Any) -> str:
        if value is None:
            return "none"
        if isinstance(value, bool):
            return "bool"
        if isinstance(value, int):
            return "int"
        if isinstance(value, float) and math.isfinite(value):
            return "float"
        if isinstance(value, str):
            return "str"
        if isinstance(value, bytes):
            return "bytes"
        if isinstance(value, list):
            return "list"
        if isinstance(value, tuple):
            return "tuple"
        if isinstance(value, dict):
            return "dict"
        if isinstance(value, set):
            return "set"
        return type(value).__name__

    def _opaque_sort(self, kind: str) -> Any:
        return {
            "bool": self._z3.BoolSort(),
            "int": self._z3.IntSort(),
            "float": self._z3.RealSort(),
            "str": self._z3.StringSort(),
        }[kind]

    def _opaque_literal(self, value: Any) -> Any:
        kind = self._opaque_kind(value)
        if kind == "bool":
            return self._z3.BoolVal(value)
        if kind == "int":
            return self._z3.IntVal(value)
        if kind == "float":
            return self._z3.RealVal(str(value))
        if kind == "str":
            return self._z3.StringVal(value)
        if kind in {"bytes", "list", "tuple", "dict", "set"}:
            return self._z3.StringVal(_opaque_container_token(value))
        raise UnsupportedSyntaxError(f"unsupported opaque literal {value!r}")

    def _opaque_function(
        self,
        signature: OpaqueCallSignature,
        suffix: str,
        terms: tuple[Any, ...],
        result_sort: Any,
    ) -> Any:
        name = _opaque_symbol_name(signature, suffix)
        function = self._opaque_functions.get(name)
        if function is None:
            function = self._z3.Function(
                name,
                *(term.sort() for term in terms),
                result_sort,
            )
            self._opaque_functions[name] = function
        return function(*terms)

    def _add_opaque_sample_constraints(
        self,
        signature: OpaqueCallSignature,
        terms: tuple[Any, ...],
        exception_expression: Any,
    ) -> None:
        for sample in self._opaque_refinements.samples(signature):
            values = (*sample.arguments, *(value for _, value in sample.keywords))
            condition = self._z3.And(
                *(term == self._opaque_literal(value) for term, value in zip(terms, values))
            )
            self.input_constraints.append(
                self._z3.Implies(condition, exception_expression == sample.raised)
            )

    def _add_opaque_result_constraints(
        self,
        signature: OpaqueCallSignature,
        terms: tuple[Any, ...],
        result_expression: Any,
        result_kind: str,
    ) -> None:
        for sample in self._opaque_refinements.samples(signature):
            if sample.raised or sample.result_kind != result_kind:
                continue
            values = (*sample.arguments, *(value for _, value in sample.keywords))
            condition = self._z3.And(
                *(term == self._opaque_literal(value) for term, value in zip(terms, values))
            )
            self.input_constraints.append(
                self._z3.Implies(
                    condition,
                    result_expression == self._opaque_literal(sample.result),
                )
            )

    def _opaque_value(self, concrete: Any, symbolic: Any) -> Any:
        kind = self._opaque_kind(concrete)
        if kind == "bool":
            return _BoolValue(concrete, symbolic)
        if kind == "int":
            return _IntValue(concrete, symbolic)
        if kind == "float":
            return _FloatValue(concrete, symbolic)
        if kind == "str":
            return _StringValue(concrete, symbolic)
        if kind in {"bytes", "list", "tuple", "dict", "set"}:
            return self._constant_value(concrete)
        raise UnsupportedSyntaxError(f"unsupported opaque result {concrete!r}")

    def _apply_opaque_mutations(
        self,
        original: list[Any],
        concrete: tuple[Any, ...],
        sources: tuple[Any, ...],
    ) -> None:
        for value, updated in zip(original, concrete):
            self._apply_opaque_mutation(value, updated, sources)

    def _apply_opaque_keyword_mutations(
        self,
        original: dict[str, Any],
        concrete: dict[str, Any],
        sources: tuple[Any, ...],
    ) -> None:
        for name, value in original.items():
            self._apply_opaque_mutation(value, concrete[name], sources)

    def _apply_opaque_mutation(
        self,
        value: Any,
        updated: Any,
        sources: tuple[Any, ...],
    ) -> None:
        if isinstance(value, _ListValue) and isinstance(updated, list):
            previous_list = tuple(value.values)
            value.values[:] = [
                self._reify_opaque_effect(
                    item,
                    sources,
                    previous_list[index] if index < len(previous_list) else None,
                )
                for index, item in enumerate(updated)
            ]
            return
        if isinstance(value, _DictValue) and isinstance(updated, dict):
            previous_dict = dict(value.values)
            value.values.clear()
            value.values.update(
                {
                    key: self._reify_opaque_effect(item, sources, previous_dict.get(key))
                    for key, item in updated.items()
                }
            )
            return
        if isinstance(value, _SetValue) and isinstance(updated, set):
            previous_set = tuple(value.values)
            value.values[:] = [
                self._reify_opaque_effect(
                    item,
                    sources,
                    next(
                        (
                            candidate
                            for candidate in previous_set
                            if _deep_concrete(candidate) == item
                        ),
                        None,
                    ),
                )
                for item in updated
            ]
            return
        if _deep_concrete(value) != updated:
            raise UnsupportedSyntaxError(
                "opaque library mutation requires a list, dictionary, or set"
            )

    def _reify_opaque_effect(
        self,
        concrete: Any,
        sources: tuple[Any, ...],
        previous: Any = None,
    ) -> Any:
        if previous is not None and _deep_concrete(previous) == concrete:
            return previous
        matching_sources = tuple(
            source
            for source in sources
            if isinstance(
                source,
                (_BoolValue, _IntValue, _FloatValue, _StringValue),
            )
            and _deep_concrete(source) == concrete
        )
        for source in matching_sources:
            if self._opaque_term_has_input(source.symbolic):
                return source
        if matching_sources:
            return matching_sources[0]
        return self._constant_value(concrete)

    @staticmethod
    def _resolve_opaque_callable(module: str, name: str) -> Any:
        try:
            value = getattr(importlib.import_module(module), name)
        except (AttributeError, ImportError) as error:
            raise UnsupportedSyntaxError(
                f"cannot resolve opaque library call {module}.{name}"
            ) from error
        if not callable(value):
            raise UnsupportedSyntaxError(f"opaque library value {module}.{name} is not callable")
        return value

    def _synthesize_opaque_guidance(
        self,
        function: Any,
        signature: OpaqueCallSignature,
        terms: tuple[Any, ...],
        keyword_terms: tuple[tuple[str, Any], ...],
        arguments: tuple[Any, ...],
        keywords: tuple[tuple[str, Any], ...],
        result_expression: Any,
        result: Any,
    ) -> Any | None:
        symbolic_values = (*terms, *(term for _, term in keyword_terms))
        concrete_values = (*arguments, *(value for _, value in keywords))
        if isinstance(result, bool):
            result_kind = "bool"
            candidates = self._opaque_boolean_candidates(symbolic_values, concrete_values)
        elif isinstance(result, int):
            result_kind = "int"
            candidates = self._opaque_integer_candidates(
                symbolic_values,
                concrete_values,
                result,
            )
        elif isinstance(result, str):
            result_kind = "str"
            candidates = self._opaque_string_candidates(
                symbolic_values,
                concrete_values,
                result,
            )
        else:
            return None
        dynamic = tuple(
            self._opaque_term_has_input(term)
            for term in (*terms, *(term for _, term in keyword_terms))
        )
        probes = _opaque_probe_arguments(arguments, keywords, dynamic)
        samples = self._opaque_refinements.samples(signature)
        for symbolic_candidate, concrete_candidate in candidates:
            if not all(
                sample.raised
                or sample.result_kind != result_kind
                or concrete_candidate((*sample.arguments, *(value for _, value in sample.keywords)))
                == sample.result
                for sample in samples
            ):
                continue
            if not _opaque_candidate_matches_probes(
                function,
                probes,
                concrete_candidate,
                result_kind,
            ):
                continue
            return result_expression == symbolic_candidate
        return None

    def _opaque_integer_candidates(
        self,
        terms: tuple[Any, ...],
        values: tuple[Any, ...],
        result: int,
    ) -> tuple[tuple[Any, Any], ...]:
        candidates: list[tuple[Any, Any]] = []
        for index, value in enumerate(values):
            if not isinstance(value, int) or isinstance(value, bool):
                continue
            term = terms[index]
            if term.sort() != self._z3.IntSort():
                continue
            candidates.extend(
                (
                    (term, lambda vals, i=index: vals[i]),
                    (-term, lambda vals, i=index: -vals[i]),
                    (
                        self._z3.If(term >= 0, term, -term),
                        lambda vals, i=index: abs(vals[i]),
                    ),
                )
            )
            delta = result - value
            if delta:
                candidates.append(
                    (
                        term + delta,
                        lambda vals, i=index, amount=delta: vals[i] + amount,
                    )
                )
        return tuple(candidates)

    def _opaque_string_candidates(
        self,
        terms: tuple[Any, ...],
        values: tuple[Any, ...],
        result: str,
    ) -> tuple[tuple[Any, Any], ...]:
        candidates: list[tuple[Any, Any]] = []
        for index, value in enumerate(values):
            if not isinstance(value, str):
                continue
            term = terms[index]
            if term.sort() != self._z3.StringSort():
                continue
            candidates.append((term, lambda vals, i=index: vals[i]))
            if result.startswith(value):
                suffix = result[len(value) :]
                if suffix:
                    candidates.append(
                        (
                            self._z3.Concat(term, self._z3.StringVal(suffix)),
                            lambda vals, i=index, text=suffix: vals[i] + text,
                        )
                    )
            if result.endswith(value):
                prefix = result[: len(result) - len(value)] if value else result
                if prefix:
                    candidates.append(
                        (
                            self._z3.Concat(self._z3.StringVal(prefix), term),
                            lambda vals, i=index, text=prefix: text + vals[i],
                        )
                    )
        return tuple(candidates)

    def _synthesize_opaque_exception_guidance(
        self,
        function: Any,
        signature: OpaqueCallSignature,
        terms: tuple[Any, ...],
        keyword_terms: tuple[tuple[str, Any], ...],
        arguments: tuple[Any, ...],
        keywords: tuple[tuple[str, Any], ...],
        exception_expression: Any,
    ) -> Any | None:
        symbolic_values = (*terms, *(term for _, term in keyword_terms))
        concrete_values = (*arguments, *(value for _, value in keywords))
        candidates = self._opaque_boolean_candidates(symbolic_values, concrete_values)
        dynamic = tuple(self._opaque_term_has_input(term) for term in symbolic_values)
        probes = _opaque_probe_arguments(arguments, keywords, dynamic)
        samples = self._opaque_refinements.samples(signature)
        for symbolic_candidate, concrete_candidate in candidates:
            if not all(
                bool(
                    concrete_candidate(
                        (*sample.arguments, *(value for _, value in sample.keywords))
                    )
                )
                == sample.raised
                for sample in samples
            ):
                continue
            if not _opaque_exception_candidate_matches_probes(function, probes, concrete_candidate):
                continue
            return exception_expression == symbolic_candidate
        return None

    def _opaque_term_has_input(self, term: Any) -> bool:
        if (
            self._z3.is_true(term)
            or self._z3.is_false(term)
            or self._z3.is_int_value(term)
            or self._z3.is_rational_value(term)
            or self._z3.is_string_value(term)
        ):
            return False
        if term.num_args() == 0:
            return True
        return any(self._opaque_term_has_input(child) for child in term.children())

    def _opaque_boolean_candidates(
        self,
        terms: tuple[Any, ...],
        values: tuple[Any, ...],
    ) -> tuple[tuple[Any, Any], ...]:
        candidates: list[tuple[Any, Any]] = []
        for left_index, left in enumerate(values):
            if not isinstance(left, (int, float, str)) or isinstance(left, bool):
                continue
            for right_index, right in enumerate(values):
                if right_index <= left_index or not isinstance(right, type(left)):
                    continue
                left_term = terms[left_index]
                right_term = terms[right_index]
                comparisons = (
                    (
                        left_term == right_term,
                        lambda vals, a=left_index, b=right_index: vals[a] == vals[b],
                    ),
                    (
                        left_term != right_term,
                        lambda vals, a=left_index, b=right_index: vals[a] != vals[b],
                    ),
                    (
                        left_term < right_term,
                        lambda vals, a=left_index, b=right_index: vals[a] < vals[b],
                    ),
                    (
                        left_term <= right_term,
                        lambda vals, a=left_index, b=right_index: vals[a] <= vals[b],
                    ),
                    (
                        left_term > right_term,
                        lambda vals, a=left_index, b=right_index: vals[a] > vals[b],
                    ),
                    (
                        left_term >= right_term,
                        lambda vals, a=left_index, b=right_index: vals[a] >= vals[b],
                    ),
                )
                candidates.extend(comparisons)
        for index, value in enumerate(values):
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                continue
            term = terms[index]
            constants = {
                0,
                1,
                -1,
                *(
                    candidate
                    for candidate in values
                    if isinstance(candidate, (int, float)) and not isinstance(candidate, bool)
                ),
            }
            for constant in sorted(constants, key=repr):
                literal = self._opaque_literal(constant)
                candidates.extend(
                    (
                        (
                            term == literal,
                            lambda vals, i=index, c=constant: vals[i] == c,
                        ),
                        (
                            term != literal,
                            lambda vals, i=index, c=constant: vals[i] != c,
                        ),
                        (
                            term < literal,
                            lambda vals, i=index, c=constant: vals[i] < c,
                        ),
                        (
                            term <= literal,
                            lambda vals, i=index, c=constant: vals[i] <= c,
                        ),
                        (
                            term > literal,
                            lambda vals, i=index, c=constant: vals[i] > c,
                        ),
                        (
                            term >= literal,
                            lambda vals, i=index, c=constant: vals[i] >= c,
                        ),
                    )
                )
            candidates.extend(
                (
                    (term == 0, lambda vals, i=index: vals[i] == 0),
                    (term < 0, lambda vals, i=index: vals[i] < 0),
                    (term <= 0, lambda vals, i=index: vals[i] <= 0),
                    (term > 0, lambda vals, i=index: vals[i] > 0),
                    (term >= 0, lambda vals, i=index: vals[i] >= 0),
                )
            )
        return tuple(candidates)

    def _call_builtin_summary(
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
        if module == "fnmatch":
            if keywords:
                raise UnsupportedSyntaxError("fnmatch summaries do not support keyword arguments")
            if name in {"fnmatch", "fnmatchcase"} and len(args) == 2:
                concrete = getattr(fnmatch, name)(
                    self._to_string(args[0]).concrete,
                    self._to_string(args[1]).concrete,
                )
                return _BoolValue(concrete, self._z3.BoolVal(concrete))
            if name == "filter" and len(args) == 2:
                names = [self._to_string(item).concrete for item in self._iter_values(args[0])]
                pattern = self._to_string(args[1]).concrete
                selected = fnmatch.filter(names, pattern)
                return _ListValue(
                    [_StringValue(item, self._z3.StringVal(item)) for item in selected]
                )
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
        if module == "html" and name == "escape" and 1 <= len(args) <= 2:
            if set(keywords) - {"quote"}:
                raise UnsupportedSyntaxError("html.escape() supports only quote")
            quote = (
                self._truthy(keywords["quote"]).concrete
                if "quote" in keywords
                else self._truthy(args[1]).concrete if len(args) == 2 else True
            )
            concrete = html.escape(self._to_string(args[0]).concrete, quote=quote)
            return _StringValue(concrete, self._z3.StringVal(concrete))
        if module == "codecs" and name in {"encode", "decode"} and 1 <= len(args) <= 3:
            if keywords:
                raise UnsupportedSyntaxError(f"codecs.{name}() does not support keyword arguments")
            values = [_concrete(argument) for argument in args]
            try:
                concrete = getattr(codecs, name)(*values)
            except (LookupError, TypeError, UnicodeError) as error:
                raise ConcolicError(str(error)) from error
            return self._constant_value(concrete)
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
        if module == "binascii" and name in {"hexlify", "unhexlify"} and len(args) == 1:
            try:
                concrete = getattr(binascii, name)(self._to_bytes(args[0]).concrete)
            except (binascii.Error, ValueError) as error:
                raise ConcolicError(str(error)) from error
            return _BytesValue(concrete)
        if module == "binascii" and name == "crc32" and 1 <= len(args) <= 2:
            values = [self._to_bytes(args[0]).concrete]
            if len(args) == 2:
                values.append(self._as_int(args[1]).concrete)
            concrete = binascii.crc32(*values)
            return _IntValue(concrete, self._z3.IntVal(concrete))
        if module == "struct" and name == "calcsize" and len(args) == 1:
            try:
                concrete = struct.calcsize(self._to_string(args[0]).concrete)
            except struct.error as error:
                raise ConcolicError(str(error)) from error
            return _IntValue(concrete, self._z3.IntVal(concrete))
        if module == "struct" and name == "pack" and args:
            try:
                concrete = struct.pack(
                    self._to_string(args[0]).concrete,
                    *(_concrete(argument) for argument in args[1:]),
                )
            except (struct.error, TypeError) as error:
                raise ConcolicError(str(error)) from error
            return _BytesValue(concrete)
        if module == "struct" and name == "unpack" and len(args) == 2:
            try:
                concrete = struct.unpack(
                    self._to_string(args[0]).concrete,
                    self._to_bytes(args[1]).concrete,
                )
            except struct.error as error:
                raise ConcolicError(str(error)) from error
            return self._constant_value(concrete)
        if (
            module == "unicodedata"
            and name
            in {
                "category",
                "combining",
                "east_asian_width",
                "mirrored",
            }
            and len(args) == 1
        ):
            concrete = getattr(unicodedata, name)(self._to_string(args[0]).concrete)
            return self._constant_value(concrete)
        if module == "unicodedata" and name == "normalize" and len(args) == 2:
            try:
                concrete = unicodedata.normalize(
                    self._to_string(args[0]).concrete,
                    self._to_string(args[1]).concrete,
                )
            except ValueError as error:
                raise ConcolicError(str(error)) from error
            return _StringValue(concrete, self._z3.StringVal(concrete))
        if module == "html" and name == "unescape" and len(args) == 1:
            concrete = html.unescape(self._to_string(args[0]).concrete)
            return _StringValue(concrete, self._z3.StringVal(concrete))
        if module == "zlib" and name in {"compress", "decompress"} and 1 <= len(args) <= 2:
            values: list[Any] = [self._to_bytes(args[0]).concrete]
            if len(args) == 2:
                values.append(self._as_int(args[1]).concrete)
            try:
                concrete = getattr(zlib, name)(*values)
            except zlib.error as error:
                raise ConcolicError(str(error)) from error
            return _BytesValue(concrete)
        if module == "zlib" and name in {"crc32", "adler32"} and 1 <= len(args) <= 2:
            values = [self._to_bytes(args[0]).concrete]
            if len(args) == 2:
                values.append(self._as_int(args[1]).concrete)
            concrete = getattr(zlib, name)(*values)
            return _IntValue(concrete, self._z3.IntVal(concrete))
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
            return _DefaultDictValue({}, factory=args[0])
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


_OPAQUE_SAFE_MODULES = {
    "base64",
    "binascii",
    "codecs",
    "fnmatch",
    "html",
    "math",
    "operator",
    "os.path",
    "statistics",
    "struct",
    "unicodedata",
    "urllib.parse",
    "zlib",
}
_OPAQUE_RESULT_KINDS = {
    "none",
    "bool",
    "int",
    "float",
    "str",
    "bytes",
    "list",
    "tuple",
    "dict",
    "set",
}


def _opaque_symbol_name(signature: OpaqueCallSignature, suffix: str) -> str:
    raw = "_".join(
        (
            "pyflow_opaque",
            signature.module,
            signature.name,
            *signature.argument_kinds,
            *(f"{name}_{kind}" for name, kind in signature.keyword_kinds),
            suffix,
        )
    )
    return "".join(character if character.isalnum() else "_" for character in raw)


def _opaque_container_token(value: Any) -> str:
    if isinstance(value, bytes):
        return f"bytes:{value.hex()}"
    if isinstance(value, list):
        return "list:[" + ",".join(_opaque_container_token(item) for item in value) + "]"
    if isinstance(value, tuple):
        return "tuple:(" + ",".join(_opaque_container_token(item) for item in value) + ")"
    if isinstance(value, dict):
        entries = sorted(value.items(), key=lambda item: repr(item[0]))
        return (
            "dict:{"
            + ",".join(
                f"{_opaque_container_token(key)}:{_opaque_container_token(item)}"
                for key, item in entries
            )
            + "}"
        )
    if isinstance(value, set):
        return "set:{" + ",".join(sorted((_opaque_container_token(item) for item in value))) + "}"
    return f"{type(value).__name__}:{value!r}"


def _opaque_probe_arguments(
    arguments: tuple[Any, ...],
    keywords: tuple[tuple[str, Any], ...],
    dynamic: tuple[bool, ...],
) -> tuple[tuple[tuple[Any, ...], tuple[tuple[str, Any], ...], tuple[Any, ...]], ...]:
    values = [*arguments, *(value for _, value in keywords)]
    numeric_constants = {
        value for value in values if isinstance(value, (int, float)) and not isinstance(value, bool)
    }
    string_constants = {value for value in values if isinstance(value, str)}
    probes: list[tuple[tuple[Any, ...], tuple[tuple[str, Any], ...], tuple[Any, ...]]] = []
    for index, (value, is_dynamic) in enumerate(zip(values, dynamic)):
        if not is_dynamic:
            continue
        alternatives: set[Any]
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            alternatives = {
                0,
                1,
                -1,
                value - 1,
                value + 1,
                *numeric_constants,
                *(constant - 1 for constant in numeric_constants),
                *(constant + 1 for constant in numeric_constants),
            }
        elif isinstance(value, str):
            alternatives = {"", "a", value + "a", *string_constants}
        else:
            continue
        for alternative in sorted(alternatives, key=repr):
            if alternative == value:
                continue
            candidate = list(values)
            candidate[index] = alternative
            positional = tuple(candidate[: len(arguments)])
            named_values = candidate[len(arguments) :]
            named = tuple((key, item) for (key, _), item in zip(keywords, named_values))
            probes.append((positional, named, tuple(candidate)))
    return tuple(probes)


def _opaque_candidate_matches_probes(
    function: Any,
    probes: tuple[tuple[tuple[Any, ...], tuple[tuple[str, Any], ...], tuple[Any, ...]], ...],
    candidate: Any,
    result_kind: str,
) -> bool:
    if not probes:
        return False
    for arguments, keywords, values in probes:
        try:
            actual = function(
                *copy.deepcopy(arguments),
                **copy.deepcopy(dict(keywords)),
            )
            predicted = candidate(values)
        except Exception:
            return False
        if _SummaryMixin._opaque_kind(actual) != result_kind or predicted != actual:
            return False
    return True


def _opaque_exception_candidate_matches_probes(
    function: Any,
    probes: tuple[tuple[tuple[Any, ...], tuple[tuple[str, Any], ...], tuple[Any, ...]], ...],
    candidate: Any,
) -> bool:
    if not probes:
        return False
    for arguments, keywords, values in probes:
        try:
            function(
                *copy.deepcopy(arguments),
                **copy.deepcopy(dict(keywords)),
            )
            raised = False
        except Exception:
            raised = True
        try:
            predicted = bool(candidate(values))
        except Exception:
            return False
        if predicted != raised:
            return False
    return True
