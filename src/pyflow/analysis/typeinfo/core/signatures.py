# This file is part of PyFlow.
#
# SPDX-FileCopyrightText: 2019–2026 Pynguin Contributors
# SPDX-License-Identifier: MIT
#
"""Usage-trace signature inference and dynamic guessing helpers."""

from __future__ import annotations

import functools
import inspect
import typing
from collections import Counter, defaultdict
from dataclasses import dataclass, field

import pyflow.analysis.typeinfo.config as config
import pyflow.analysis.typeinfo.inference.tracing as tt
from pyflow.analysis.typeinfo.config import SubtypeInferenceStrategy
from pyflow.analysis.typeinfo.inference.string_patterns import infer_regex_from_methods
from pyflow.util import randomness
from pyflow.util.orderedset import OrderedSet
from pyflow.util.randomness import weighted_choice

from .descriptors import ClassDescriptor
from .types import (
    ANY,
    NONE_TYPE,
    AnyType,
    CSVString,
    EmailString,
    HexadecimalString,
    Instance,
    IPv4String,
    IPv6String,
    ISOColorString,
    ISODateString,
    ISOTimeString,
    NumericString,
    PhoneNumberString,
    ProperType,
    SHA256String,
    StringSubtype,
    TupleType,
    TypeGuessingStats,
    UnionType,
    URLString,
    UUIDString,
)
from .visitors import _is_partial_type_match, is_collection_type

if typing.TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from .typesystem import TypeSystem


class NamedDefaultDict(dict[str, tt.UsageTraceNode]):  # noqa: FURB189
    """Default dict creating a :class:`UsageTraceNode` for each missing key."""

    def __missing__(self, key):
        res = self[key] = tt.UsageTraceNode(key)
        return res


_ARGUMENT_ATTRIBUTES = OrderedSet(
    [
        "__eq__",
        "__ne__",
        "__lt__",
        "__le__",
        "__gt__",
        "__ge__",
        "__add__",
        "__radd__",
        "__sub__",
        "__rsub__",
        "__truediv__",
        "__rtruediv__",
        "__floordiv__",
        "__rfloordiv__",
    ]
)

_STRING_SUBTYPE_ATTRIBUTES = OrderedSet(
    [
        "startswith",
        "endswith",
        "split",
        "rsplit",
        "splitlines",
        "partition",
        "rpartition",
        "find",
        "rfind",
        "index",
        "rindex",
        "replace",
        "format",
        "join",
        "strip",
        "lstrip",
        "rstrip",
        "zfill",
        "center",
        "ljust",
        "rjust",
        "removeprefix",
        "removesuffix",
        "translate",
        "count",
    ]
)

STRING_SUBTYPES = OrderedSet(
    [
        NumericString,
        EmailString,
        HexadecimalString,
        ISOColorString,
        UUIDString,
        ISODateString,
        ISOTimeString,
        CSVString,
        URLString,
        IPv4String,
        IPv6String,
        PhoneNumberString,
        SHA256String,
    ]
)

_LIST_ELEMENT_ATTRIBUTES = OrderedSet(("__iter__", "__getitem__"))
_DICT_KEY_ATTRIBUTES = OrderedSet(("__iter__",))
_DICT_VALUE_ATTRIBUTES = OrderedSet(("__getitem__",))
_SET_ELEMENT_ATTRIBUTES = OrderedSet(("__iter__",))
_TUPLE_ELEMENT_ATTRIBUTES = OrderedSet(("__iter__", "__getitem__"))

_LIST_ELEMENT_FROM_ARGUMENT_TYPES = OrderedSet(("__contains__", "__delitem__"))
_SET_ELEMENT_FROM_ARGUMENT_TYPES = OrderedSet(("__contains__", "__delitem__"))
_DICT_KEY_FROM_ARGUMENT_TYPES = OrderedSet(
    (
        "__contains__",
        "__delitem__",
        "__getitem__",
        "__setitem__",
    )
)
_DICT_VALUE_FROM_ARGUMENT_TYPES = OrderedSet(("__setitem__",))
_TUPLE_ELEMENT_FROM_ARGUMENT_TYPES = OrderedSet(("__contains__",))

_LIST_ELEMENT_FROM_ARGUMENT_TYPES_PATH: OrderedSet[tuple[str, ...]] = OrderedSet(
    [
        ("append", "__call__"),
        ("remove", "__call__"),
    ]
)
_SET_ELEMENT_FROM_ARGUMENT_TYPES_PATH: OrderedSet[tuple[str, ...]] = OrderedSet(
    [
        ("add", "__call__"),
        ("remove", "__call__"),
        ("discard", "__call__"),
    ]
)
_EMPTY_SET: OrderedSet[tuple[str, ...]] = OrderedSet()


@dataclass(eq=False, repr=False)
class InferredSignature:
    """Encapsulates the types inferred for a callable from hints and usage traces."""

    signature: inspect.Signature
    original_return_type: ProperType
    original_parameters: dict[str, ProperType]
    usage_trace: dict[str, tt.UsageTraceNode] = field(
        default_factory=NamedDefaultDict,
        init=False,
    )
    type_system: TypeSystem
    return_type: ProperType = field(init=False)
    current_guessed_parameters: dict[str, list[ProperType]] = field(
        init=False, default_factory=dict
    )
    parameters_for_statistics: dict[str, ProperType] = field(default_factory=dict)
    return_type_for_statistics: ProperType = ANY

    def __post_init__(self):
        self.return_type = self.original_return_type

    def __str__(self):
        return str(self.signature)

    def get_parameter_types(
        self, signature_memo: dict[InferredSignature, dict[str, ProperType]]
    ) -> dict[str, ProperType]:
        """Get a possible type signature for the parameters."""
        if (sig := signature_memo.get(self)) is not None:
            return sig
        res: dict[str, ProperType] = {}
        test_conf = config.settings.test_creation
        for param_name, orig_type in self.original_parameters.items():
            if len(self.usage_trace[param_name]) > 0:
                self._update_guess(
                    param_name,
                    self._guess_parameter_type(
                        self.usage_trace[param_name],
                        self.signature.parameters[param_name].kind,
                    ),
                )

            choices: list[ProperType] = [NONE_TYPE, ANY]
            weights: list[float] = [test_conf.none_weight, test_conf.any_weight]
            if not isinstance(orig_type, AnyType):
                choices.append(orig_type)
                weights.append(test_conf.original_type_weight)

            if (guessed := self.current_guessed_parameters.get(param_name)) is not None:
                choices.append(UnionType(tuple(sorted(guessed))))
                weights.append(test_conf.type_tracing_weight)

            chosen = randomness.choices(choices, weights)[0]

            if (
                randomness.next_float()
                < config.settings.test_creation.wrap_var_param_type_probability
            ):
                chosen = self.type_system.wrap_var_param_type(
                    chosen,
                    self.signature.parameters[param_name].kind,
                )
            res[param_name] = chosen
        signature_memo[self] = res
        return res

    def _update_guess(self, name: str, guessed: ProperType | None):
        if guessed is None:
            return

        if (old := self.current_guessed_parameters.get(name)) is None:
            self.current_guessed_parameters[name] = [guessed]
        else:
            if guessed in old:
                return
            if len(old) >= config.settings.test_creation.type_tracing_kept_guesses:
                old.pop(0)
            old.append(guessed)

    def _guess_parameter_type(self, knowledge: tt.UsageTraceNode, kind) -> ProperType | None:
        match kind:
            case inspect.Parameter.VAR_KEYWORD:
                if (get_item_knowledge := knowledge.children.get("__getitem__")) is not None:
                    return self._guess_parameter_type_from(get_item_knowledge)
            case inspect.Parameter.VAR_POSITIONAL:
                if (iter_knowledge := knowledge.children.get("__iter__")) is not None:
                    return self._guess_parameter_type_from(iter_knowledge)
            case _:
                return self._guess_parameter_type_from(knowledge)
        return None

    def _from_type_check(self, knowledge: tt.UsageTraceNode) -> ProperType | None:
        return self._choose_type_or_negate(
            OrderedSet(
                [self.type_system.to_class_descriptor(randomness.choice(knowledge.type_checks))]
            )
        )

    def _from_attr_table(self, knowledge: tt.UsageTraceNode) -> ProperType | None:
        random_attribute = randomness.choice(list(knowledge.children))
        arg_types = knowledge.children[random_attribute].children["__call__"].arg_types[0]

        def _string_subtype() -> ProperType | None:
            return self._from_str_values(knowledge)

        def _argument_type() -> ProperType | None:
            selected_arg_type = randomness.choice(knowledge.children[random_attribute].arg_types[0])
            return self._choose_type_or_negate(
                OrderedSet([self.type_system.to_class_descriptor(selected_arg_type)])
            )

        def _attribute_table() -> ProperType | None:
            return self._choose_type_or_negate(self.type_system.find_by_attribute(random_attribute))

        weights = {
            _string_subtype: config.settings.type_inference.type_tracing_subtype_weight,
            _argument_type: config.settings.type_inference.type_tracing_argument_type_weight,
            _attribute_table: config.settings.type_inference.type_tracing_attribute_weight,
        }
        available_strategies = {}

        if (
            config.settings.type_inference.subtype_inference == SubtypeInferenceStrategy.STRING
            and len(arg_types) > 0
        ):
            candidate_arg_type = randomness.choice(arg_types)
            if candidate_arg_type is str and random_attribute in _STRING_SUBTYPE_ATTRIBUTES:
                available_strategies[_string_subtype] = weights[_string_subtype]

        if (
            random_attribute in _ARGUMENT_ATTRIBUTES
            and knowledge.children[random_attribute].arg_types[0]
        ):
            available_strategies[_argument_type] = weights[_argument_type]

        available_strategies[_attribute_table] = weights[_attribute_table]
        chosen_strategy = weighted_choice(available_strategies)
        return chosen_strategy()

    @staticmethod
    def _from_str_values(knowledge: tt.UsageTraceNode) -> StringSubtype | None:
        called_str_methods: Mapping[str, OrderedSet[str]] = defaultdict(OrderedSet)
        for child in knowledge.children:
            if child in _STRING_SUBTYPE_ATTRIBUTES:
                for arg_values in knowledge.children[child].children["__call__"].arg_values[0]:
                    if isinstance(arg_values, str):
                        called_str_methods[child].add(arg_values)

        if not called_str_methods:
            return None
        regex = infer_regex_from_methods(called_str_methods)
        return StringSubtype(regex)

    def _guess_parameter_type_from(
        self, knowledge: tt.UsageTraceNode, recursion_depth: int = 0
    ) -> ProperType | None:
        guess_from: list[Callable[[tt.UsageTraceNode], ProperType | None]] = []
        if knowledge.type_checks:
            guess_from.append(self._from_type_check)
        if knowledge.children:
            guess_from.append(self._from_attr_table)

        if not guess_from:
            return None

        guessed_type: ProperType | None = randomness.choice(guess_from)(knowledge)

        if recursion_depth <= 1 and guessed_type and guessed_type.accept(is_collection_type):
            guessed_type = self._guess_generic_type_parameters_for_builtins(
                guessed_type, knowledge, recursion_depth
            )
        return guessed_type

    def _guess_generic_type_parameters_for_builtins(
        self,
        guessed_type: ProperType,
        knowledge: tt.UsageTraceNode,
        recursion_depth: int,
    ):
        if isinstance(guessed_type, Instance):
            args = guessed_type.args
            match guessed_type.type.full_name:
                case "builtins.list":
                    guessed_element_type = self._guess_generic_arguments(
                        knowledge,
                        recursion_depth,
                        _LIST_ELEMENT_ATTRIBUTES,
                        _LIST_ELEMENT_FROM_ARGUMENT_TYPES,
                        _LIST_ELEMENT_FROM_ARGUMENT_TYPES_PATH,
                        argument_idx=0,
                    )
                    args = (guessed_element_type or guessed_type.args[0],)
                case "builtins.set":
                    guessed_element_type = self._guess_generic_arguments(
                        knowledge,
                        recursion_depth,
                        _SET_ELEMENT_ATTRIBUTES,
                        _SET_ELEMENT_FROM_ARGUMENT_TYPES,
                        _SET_ELEMENT_FROM_ARGUMENT_TYPES_PATH,
                        argument_idx=0,
                    )
                    args = (guessed_element_type or guessed_type.args[0],)
                case "builtins.dict":
                    guessed_key_type = self._guess_generic_arguments(
                        knowledge,
                        recursion_depth,
                        _DICT_KEY_ATTRIBUTES,
                        _DICT_KEY_FROM_ARGUMENT_TYPES,
                        _EMPTY_SET,
                        argument_idx=0,
                    )
                    guessed_value_type = self._guess_generic_arguments(
                        knowledge,
                        recursion_depth,
                        _DICT_VALUE_ATTRIBUTES,
                        _DICT_VALUE_FROM_ARGUMENT_TYPES,
                        _EMPTY_SET,
                        argument_idx=1,
                    )
                    args = (
                        guessed_key_type or guessed_type.args[0],
                        guessed_value_type or guessed_type.args[1],
                    )
            guessed_type = Instance(guessed_type.type, args)
        elif isinstance(guessed_type, TupleType):
            num_elements = randomness.next_int(1, config.settings.test_creation.collection_size)
            elements = []
            for _ in range(num_elements):
                guessed_element_type = self._guess_generic_arguments(
                    knowledge,
                    recursion_depth,
                    _TUPLE_ELEMENT_ATTRIBUTES,
                    _TUPLE_ELEMENT_FROM_ARGUMENT_TYPES,
                    _EMPTY_SET,
                    argument_idx=0,
                )
                elements.append(guessed_element_type if guessed_element_type else ANY)
            guessed_type = TupleType(tuple(elements))
        return guessed_type

    def _choose_type_or_negate(
        self, positive_types: OrderedSet[ClassDescriptor]
    ) -> ProperType | None:
        if not positive_types:
            return None

        if randomness.next_float() < config.settings.test_creation.negate_type:
            negated_choices = self.type_system.get_type_outside_of(positive_types)
            if len(negated_choices) > 0:
                return self.type_system.make_instance(randomness.choice(negated_choices))
        return self.type_system.make_instance(randomness.choice(positive_types))

    def _guess_generic_arguments(  # noqa: PLR0917
        self,
        knowledge: tt.UsageTraceNode,
        recursion_depth: int,
        element_attributes: OrderedSet[str],
        argument_attributes: OrderedSet[str],
        argument_attribute_paths: OrderedSet[tuple[str, ...]],
        argument_idx: int,
    ) -> ProperType | None:
        guess_from: list[Callable[[], ProperType | None]] = []

        if elem_attributes := element_attributes.intersection(knowledge.children.keys()):
            guess_from.append(
                functools.partial(
                    self._guess_parameter_type_from,
                    knowledge.children[randomness.choice(elem_attributes)],
                    recursion_depth + 1,
                )
            )
        if arg_attributes := argument_attributes.intersection(knowledge.children.keys()):
            guess_from.append(
                functools.partial(
                    self._guess_from_argument_types,
                    arg_attributes,
                    knowledge,
                    argument_idx,
                )
            )
        if paths := [
            path for path in argument_attribute_paths if knowledge.find_path(path) is not None
        ]:
            guess_from.append(
                functools.partial(self._guess_from_argument_types_from_path, paths, knowledge)
            )
        guess_from.append(lambda: ANY)
        return randomness.choice(guess_from)()

    def _guess_from_argument_types(
        self,
        arg_attrs: OrderedSet[str],
        knowledge: tt.UsageTraceNode,
        arg_idx: int = 0,
    ) -> ProperType | None:
        arg_types = knowledge.children[randomness.choice(arg_attrs)].arg_types[arg_idx]
        if arg_types:
            return self._choose_type_or_negate(
                OrderedSet([self.type_system.to_class_descriptor(randomness.choice(arg_types))])
            )
        return None

    def _guess_from_argument_types_from_path(
        self,
        paths: list[tuple[str, ...]],
        knowledge: tt.UsageTraceNode,
    ) -> ProperType | None:
        path = randomness.choice(paths)
        path_end = knowledge.find_path(path)
        assert path_end is not None
        arg_types = path_end.children[path[-1]].arg_types[0]
        if arg_types:
            return self._choose_type_or_negate(
                OrderedSet([self.type_system.to_class_descriptor(randomness.choice(arg_types))])
            )
        return None

    def log_stats_and_guess_signature(
        self,
        is_constructor: bool,  # noqa: FBT001
        callable_full_name: str,
        stats: TypeGuessingStats,
    ) -> None:
        """Log statistics and create a guessed signature."""
        sig_info = stats.signature_infos[callable_full_name]

        sig_info.annotated_parameter_types = {
            k: str(v) for k, v in self.parameters_for_statistics.items()
        }
        if not is_constructor:
            sig_info.annotated_return_type = str(self.return_type_for_statistics)
        else:
            stats.number_of_constructors += 1

        parameter_types: dict[str, list[str]] = {}
        compute_partial_matches_for: list[tuple[ProperType, ProperType]] = []
        for param_name, param in self.signature.parameters.items():
            if param_name not in self.original_parameters:
                continue

            top_n_guesses: list[ProperType] = []
            if len(self.usage_trace[param_name]) > 0:
                counter: Counter[ProperType] = Counter()
                for _ in range(100):
                    guess = self._guess_parameter_type(
                        self.usage_trace[param_name],
                        param.kind,
                    )
                    if guess is not None:
                        counter[guess] += 1
                for typ, _ in counter.most_common(
                    config.settings.statistics_output.type_guess_top_n
                ):
                    top_n_guesses.append(typ)

            for item in top_n_guesses:
                compute_partial_matches_for.append(  # noqa: PERF401
                    (item, self.parameters_for_statistics[param_name])
                )
            parameter_types[param_name] = [str(t) for t in top_n_guesses]
        compute_partial_matches_for.append(
            (
                self.return_type,
                self.return_type_for_statistics,
            )
        )

        self._compute_partial_matches(compute_partial_matches_for, sig_info)

        return_type = str(self.return_type)
        if not is_constructor and self.return_type != self.original_return_type:
            sig_info.recorded_return_type = str(return_type)
        sig_info.guessed_parameter_types = parameter_types

    @staticmethod
    def _compute_partial_matches(compute_partial_matches_for, sig_info):
        for left, right in compute_partial_matches_for:
            if (match := _is_partial_type_match(left, right)) is not None:
                sig_info.partial_type_matches[f"({left!s}, {right!s})"] = str(match)
