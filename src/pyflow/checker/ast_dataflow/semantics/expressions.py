"""Python expression transfer semantics for the formal taint domain."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Mapping

from pyflow.analysis.taint import TaintPolicy

from ..domain import (
    AccessSelector,
    AnalysisUncertainty,
    PrecisionLevel,
    ProvenanceOperation,
    TaintFact,
    TaintLocation,
    TaintOrigin,
    TaintState,
)
from ..modeling import CallShapeContractRegistry, SanitizerContractRegistry
from ..solver import ProcedureTaintSummary, SummaryPort, SummaryPortKind
from .events import TaintSinkEvent


@dataclass(frozen=True)
class ExpressionResult:
    state: TaintState
    facts: frozenset[TaintFact] = frozenset()
    location: TaintLocation | None = None
    events: frozenset[object] = frozenset()


@dataclass(frozen=True)
class ExpressionContext:
    procedure: str
    filename: str | None
    policy: TaintPolicy
    summaries: Mapping[str, ProcedureTaintSummary]
    contracts: SanitizerContractRegistry
    shape_contracts: CallShapeContractRegistry
    known_functions: frozenset[str] = frozenset()


class PythonExpressionSemantics:
    def __init__(self, context: ExpressionContext) -> None:
        self.context = context

    def evaluate(
        self, expression: ast.AST | None, state: TaintState
    ) -> ExpressionResult:
        if expression is None:
            return ExpressionResult(state)
        if isinstance(expression, ast.Name):
            name_location = TaintLocation((self.context.procedure, expression.id))
            return ExpressionResult(state, state.facts_at(name_location), name_location)
        if isinstance(expression, ast.Constant):
            return ExpressionResult(state)
        if isinstance(expression, ast.Await):
            return self.evaluate(expression.value, state)
        if isinstance(expression, ast.NamedExpr):
            value = self.evaluate(expression.value, state)
            written = self._assign_target(expression.target, value, value.state)
            return ExpressionResult(
                written, value.facts, self.location_of(expression.target), value.events
            )
        if isinstance(expression, ast.Call):
            return self._evaluate_call(expression, state)
        if isinstance(expression, (ast.Attribute, ast.Subscript)):
            location = self.location_of(expression)
            base_result = self.evaluate(expression.value, state)
            if location is None:
                return ExpressionResult(
                    base_result.state,
                    base_result.facts,
                    events=base_result.events,
                )
            current = base_result.state
            if isinstance(expression, ast.Attribute):
                name = self._call_name(expression)
                source_kinds = self.context.policy.source_kinds_for(name)
                for kind in source_kinds:
                    current = current.introduce(
                        location,
                        {kind},
                        TaintOrigin(
                            kind,
                            self.context.filename,
                            getattr(expression, "lineno", None),
                            getattr(expression, "col_offset", None),
                            name,
                        ),
                    )
            return ExpressionResult(
                current,
                current.facts_at(location),
                location,
                base_result.events,
            )
        if isinstance(expression, ast.IfExp):
            tested = self.evaluate(expression.test, state)
            body = self.evaluate(expression.body, tested.state)
            alternate = self.evaluate(expression.orelse, tested.state)
            return ExpressionResult(
                body.state.join(alternate.state),
                body.facts | alternate.facts,
                events=tested.events | body.events | alternate.events,
            )
        if isinstance(expression, ast.BoolOp):
            return self._evaluate_many(expression.values, state)
        if isinstance(expression, ast.BinOp):
            return self._evaluate_many((expression.left, expression.right), state)
        if isinstance(expression, ast.UnaryOp):
            evaluated = self.evaluate(expression.operand, state)
            if isinstance(expression.op, ast.Not):
                return ExpressionResult(evaluated.state, events=evaluated.events)
            return evaluated
        if isinstance(expression, ast.Compare):
            evaluated = self._evaluate_many(
                (expression.left, *expression.comparators), state
            )
            return ExpressionResult(evaluated.state, events=evaluated.events)
        if isinstance(expression, ast.JoinedStr):
            return self._evaluate_many(expression.values, state)
        if isinstance(expression, ast.FormattedValue):
            return self.evaluate(expression.value, state)
        if isinstance(expression, ast.Starred):
            # Expansion changes container shape, not the taint of the value.
            return self.evaluate(expression.value, state)
        if isinstance(expression, (ast.List, ast.Tuple, ast.Set)):
            return self._evaluate_container_literal(expression, state)
        if isinstance(expression, ast.Dict):
            return self._evaluate_container_literal(expression, state)
        if isinstance(expression, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            expressions: list[ast.AST] = [expression.elt]
            for generator in expression.generators:
                expressions.append(generator.iter)
                expressions.extend(generator.ifs)
            return self._evaluate_many(expressions, state)
        if isinstance(expression, ast.DictComp):
            expressions = [expression.key, expression.value]
            for generator in expression.generators:
                expressions.append(generator.iter)
                expressions.extend(generator.ifs)
            return self._evaluate_many(expressions, state)
        if isinstance(expression, (ast.Yield, ast.YieldFrom)):
            return self.evaluate(expression.value, state)
        if isinstance(expression, ast.Lambda):
            return ExpressionResult(state)

        uncertainty = AnalysisUncertainty(
            code="unsupported-expression",
            message=f"No precise taint semantics for {type(expression).__name__}",
            level=PrecisionLevel.UNSUPPORTED,
            function=self.context.procedure,
            filename=self.context.filename,
            line=getattr(expression, "lineno", None),
            operation=type(expression).__name__,
        )
        return ExpressionResult(state.with_uncertainty(uncertainty))

    def location_of(self, expression: ast.AST) -> TaintLocation | None:
        if isinstance(expression, ast.Name):
            return TaintLocation((self.context.procedure, expression.id))
        if isinstance(expression, ast.Attribute):
            base = self.location_of(expression.value)
            return base.attribute(expression.attr) if base is not None else None
        if isinstance(expression, ast.Subscript):
            base = self.location_of(expression.value)
            if base is None:
                return None
            key = self._literal_selector(expression.slice)
            if isinstance(key, int):
                return base.index(key)
            if key is not None:
                return base.key(key)
            return base.wildcard()
        return None

    def _evaluate_call(self, call: ast.Call, state: TaintState) -> ExpressionResult:
        current = state
        events: set[object] = set()
        receiver_result: ExpressionResult | None = None
        if isinstance(call.func, ast.Attribute):
            receiver_result = self.evaluate(call.func.value, current)
            current = receiver_result.state
            events.update(receiver_result.events)
        positional: list[ExpressionResult] = []
        for argument in call.args:
            evaluated = self.evaluate(argument, current)
            current = evaluated.state
            positional.append(evaluated)
            events.update(evaluated.events)
        keywords: list[ExpressionResult] = []
        for keyword in call.keywords:
            evaluated = self.evaluate(keyword.value, current)
            current = evaluated.state
            keywords.append(evaluated)
            events.update(evaluated.events)

        name = self._call_name(call.func)
        call_location = TaintLocation(
            (
                "call",
                self.context.procedure,
                getattr(call, "lineno", None),
                getattr(call, "col_offset", None),
            )
        )
        method_state, method_facts, modeled_method = self._model_builtin_method(
            call, current, positional, keywords
        )
        summary_name, ambiguous_summary = self._resolve_summary_name(name)

        source_kinds = self.context.policy.source_kinds_for(name)
        sink_kinds = self.context.policy.sink_kinds_for(name)
        if source_kinds:
            for kind in source_kinds:
                current = current.introduce(
                    call_location,
                    {kind},
                    TaintOrigin(
                        kind,
                        self.context.filename,
                        getattr(call, "lineno", None),
                        getattr(call, "col_offset", None),
                        name,
                    ),
                )

        all_argument_facts = frozenset(
            fact for result in (*positional, *keywords) for fact in result.facts
        )
        sanitizer_kinds = self.context.policy.sanitizer_kinds_for(name)
        contracts = self.context.contracts.for_call(name)
        shape_contracts = self.context.shape_contracts.for_call(name)
        if contracts:
            original_kinds = {fact.kind for fact in all_argument_facts}
            kinds = set(original_kinds)
            for sanitizer_contract in contracts:
                transformed = set(sanitizer_contract.transform.apply(kinds))
                if sanitizer_contract.guard:
                    kinds.update(transformed)
                    current = current.with_uncertainty(
                        AnalysisUncertainty(
                            code="conditional-sanitizer-guard",
                            message=(
                                f"Sanitizer guard {sanitizer_contract.guard!r} was not "
                                "proven; sanitized and unsanitized outcomes join"
                            ),
                            level=PrecisionLevel.CONSERVATIVE,
                            function=self.context.procedure,
                            filename=self.context.filename,
                            line=getattr(call, "lineno", None),
                            operation=name,
                        )
                    )
                else:
                    kinds = transformed
                for assumption in sanitizer_contract.assumptions:
                    current = current.with_uncertainty(
                        AnalysisUncertainty(
                            code="sanitizer-contract-assumption",
                            message=assumption,
                            level=PrecisionLevel.ASSUMED,
                            function=self.context.procedure,
                            filename=self.context.filename,
                            line=getattr(call, "lineno", None),
                            operation=name,
                        )
                    )
                if sanitizer_contract.mutates_input:
                    current = current.with_uncertainty(
                        AnalysisUncertainty(
                            code="sanitizer-mutation-weak-update",
                            message=(
                                "In-place sanitizer mutation retained its input "
                                "facts until heap refinement proves a strong update"
                            ),
                            level=PrecisionLevel.CONSERVATIVE,
                            function=self.context.procedure,
                            filename=self.context.filename,
                            line=getattr(call, "lineno", None),
                            operation=name,
                        )
                    )
            retained = tuple(fact for fact in all_argument_facts if fact.kind in kinds)
            mapped_origins = {
                kind: next(iter(all_argument_facts)).origin
                for kind in kinds
                if all_argument_facts
            }
            current = current.write(
                call_location,
                retained,
                strong=True,
                operation=ProvenanceOperation.SANITIZE,
                filename=self.context.filename,
                line=getattr(call, "lineno", None),
                detail=name,
            )
            for kind in kinds - {fact.kind for fact in retained}:
                current = current.introduce(call_location, {kind}, mapped_origins[kind])
        elif sanitizer_kinds:
            current = current.write(
                call_location,
                all_argument_facts,
                strong=True,
                operation=ProvenanceOperation.SANITIZE,
                filename=self.context.filename,
                line=getattr(call, "lineno", None),
                detail=name,
            ).kill(call_location, sanitizer_kinds)
        elif source_kinds:
            pass
        elif summary_name is not None:
            current = self._apply_summary(
                call,
                summary_name,
                positional,
                keywords,
                call_location,
                current,
                events,
                receiver_result,
            )
        elif shape_contracts:
            current = current.kill(call_location, record_guarantee=False)
            for shape_contract in shape_contracts:
                if shape_contract.input_index >= len(positional):
                    continue
                source = positional[shape_contract.input_index]
                for partition in shape_contract.index_partitions:
                    for residue in partition.residues:
                        target = call_location.index_class(partition.modulus, residue)
                        if source.location is not None:
                            current = current.copy(
                                source.location,
                                target,
                                strong=True,
                                operation=ProvenanceOperation.CALL,
                                filename=self.context.filename,
                                line=getattr(call, "lineno", None),
                                detail=name,
                            )
                        else:
                            current = current.write(target, source.facts, strong=True)
                for assumption in shape_contract.assumptions:
                    current = current.with_uncertainty(
                        AnalysisUncertainty(
                            code="shape-contract-assumption",
                            message=assumption,
                            level=PrecisionLevel.ASSUMED,
                            function=self.context.procedure,
                            filename=self.context.filename,
                            line=getattr(call, "lineno", None),
                            operation=name,
                        )
                    )
        elif sink_kinds:
            # A configured sink is a modeled boundary.  A separate model may
            # describe a tainted return; absent that model the return is safe.
            current = current.write(call_location, (), strong=True)
        elif modeled_method:
            current = method_state.write(
                call_location,
                method_facts,
                strong=True,
                operation=ProvenanceOperation.CALL,
                filename=self.context.filename,
                line=getattr(call, "lineno", None),
                detail=name,
            )
        else:
            current = current.write(
                call_location,
                all_argument_facts,
                strong=True,
                operation=ProvenanceOperation.CALL,
                filename=self.context.filename,
                line=getattr(call, "lineno", None),
                detail=name or "<dynamic>",
            )
            if name not in self.context.known_functions:
                uncertainty = AnalysisUncertainty(
                    code="unknown-call-effect",
                    message=f"Unknown call effects for {name or '<dynamic>'}",
                    level=PrecisionLevel.CONSERVATIVE,
                    function=self.context.procedure,
                    filename=self.context.filename,
                    line=getattr(call, "lineno", None),
                    operation=name or "<dynamic>",
                )
                havoc_kinds = {
                    kind
                    for values in self.context.policy.source_kinds_by_call.values()
                    for kind in values
                } or {"unknown"}
                locations = {call_location}
                locations.update(
                    result.location
                    for result in (*positional, *keywords)
                    if result.location is not None
                )
                current = current.havoc(
                    locations,
                    havoc_kinds,
                    TaintOrigin(
                        "unknown",
                        self.context.filename,
                        getattr(call, "lineno", None),
                        symbol=name or "<dynamic>",
                    ),
                    uncertainty,
                )
                if ambiguous_summary:
                    current = current.with_uncertainty(
                        AnalysisUncertainty(
                            code="ambiguous-call-target",
                            message=f"Multiple local summaries match call {name!r}",
                            # The unknown-call branch above already havocs the
                            # return and reachable actual arguments with every
                            # configured source kind. Ambiguity loses
                            # precision, but does not under-approximate taint.
                            level=PrecisionLevel.CONSERVATIVE,
                            function=self.context.procedure,
                            filename=self.context.filename,
                            line=getattr(call, "lineno", None),
                            operation=name,
                        )
                    )

        if sink_kinds:
            positions = self.context.policy.sink_positions_for(name) or frozenset(
                range(len(positional))
            )
            for index, positional_result in enumerate(positional):
                if index in positions and positional_result.facts:
                    events.add(
                        TaintSinkEvent(
                            self.context.procedure,
                            self.context.filename,
                            name,
                            sink_kinds,
                            index,
                            getattr(call, "lineno", None),
                            positional_result.facts,
                        )
                    )
            for keyword_result in keywords:
                if keyword_result.facts:
                    events.add(
                        TaintSinkEvent(
                            self.context.procedure,
                            self.context.filename,
                            name,
                            sink_kinds,
                            None,
                            getattr(call, "lineno", None),
                            keyword_result.facts,
                        )
                    )

        return ExpressionResult(
            current,
            current.facts_at(call_location),
            call_location,
            frozenset(events),
        )

    def _evaluate_container_literal(
        self,
        expression: ast.List | ast.Tuple | ast.Set | ast.Dict,
        state: TaintState,
    ) -> ExpressionResult:
        location = TaintLocation(
            (
                "literal",
                self.context.procedure,
                getattr(expression, "lineno", None),
                getattr(expression, "col_offset", None),
            )
        )
        current = state.kill(location, record_guarantee=False)
        events: set[object] = set()

        if isinstance(expression, ast.Dict):
            for key_expression, value_expression in zip(
                expression.keys, expression.values
            ):
                if key_expression is None:
                    value = self.evaluate(value_expression, current)
                    current = value.state.write(
                        location.wildcard(), value.facts, strong=False
                    )
                    events.update(value.events)
                    continue
                key = self.evaluate(key_expression, current)
                current = key.state
                events.update(key.events)
                literal_key = self._literal_selector(key_expression)
                child = (
                    location.key(literal_key)
                    if literal_key is not None
                    else location.wildcard()
                )
                value = self.evaluate(value_expression, current)
                current = value.state
                events.update(value.events)
                if value.location is not None:
                    current = current.copy(
                        value.location, child, strong=True, detail="dict-literal"
                    )
                else:
                    current = current.write(child, value.facts, strong=True)
                if key.facts:
                    key_location = location.select(
                        AccessSelector.mapping_key()
                    ).wildcard()
                    current = current.write(key_location, key.facts, strong=False)
        else:
            for index, element in enumerate(expression.elts):
                value = self.evaluate(element, current)
                current = value.state
                events.update(value.events)
                child = (
                    location.wildcard()
                    if isinstance(expression, ast.Set)
                    else location.index(index)
                )
                if value.location is not None:
                    current = current.copy(
                        value.location, child, strong=True, detail="sequence-literal"
                    )
                else:
                    current = current.write(child, value.facts, strong=True)
        return ExpressionResult(
            current,
            current.facts_at(location),
            location,
            frozenset(events),
        )

    def _model_builtin_method(
        self,
        call: ast.Call,
        state: TaintState,
        positional: list[ExpressionResult],
        keywords: list[ExpressionResult],
    ) -> tuple[TaintState, frozenset[TaintFact], bool]:
        if not isinstance(call.func, ast.Attribute):
            return state, frozenset(), False
        receiver = self.location_of(call.func.value)
        if receiver is None:
            return state, frozenset(), False
        method = call.func.attr
        if method in {"get", "pop"}:
            key = self._literal_selector(call.args[0]) if call.args else None
            target = (
                receiver.index(key)
                if isinstance(key, int)
                else receiver.key(key) if key is not None else receiver.wildcard()
            )
            return state, state.facts_at(target), True
        if method == "values":
            return state, state.facts_at(receiver), True
        if method == "keys":
            key_location = receiver.select(AccessSelector.mapping_key())
            return state, state.facts_at(key_location), True
        if method == "items":
            key_location = receiver.select(AccessSelector.mapping_key())
            return state, state.facts_at(receiver) | state.facts_at(key_location), True
        if method in {"append", "add", "extend", "insert", "update", "setdefault"}:
            facts = frozenset(
                fact for value in (*positional, *keywords) for fact in value.facts
            )
            mutated = state.write(
                receiver.wildcard(),
                facts,
                strong=False,
                operation=ProvenanceOperation.WRITE,
                filename=self.context.filename,
                line=getattr(call, "lineno", None),
                detail=method,
            )
            return mutated, frozenset(), True
        if method == "clear":
            uncertainty = AnalysisUncertainty(
                code="container-clear-alias-unknown",
                message="Container clear requires heap refinement for a strong kill",
                level=PrecisionLevel.CONSERVATIVE,
                function=self.context.procedure,
                filename=self.context.filename,
                line=getattr(call, "lineno", None),
                operation=method,
            )
            return state.with_uncertainty(uncertainty), frozenset(), True
        return state, frozenset(), False

    def _apply_summary(
        self,
        call: ast.Call,
        name: str,
        positional: list[ExpressionResult],
        keywords: list[ExpressionResult],
        call_location: TaintLocation,
        state: TaintState,
        events: set[object],
        receiver_result: ExpressionResult | None,
    ) -> TaintState:
        summary = self.context.summaries[name]
        bound_receiver = (
            receiver_result is not None
            and bool(summary.parameters)
            and summary.parameters[0] in {"self", "cls"}
        )
        offset = 1 if bound_receiver else 0
        inputs = {
            SummaryPort(SummaryPortKind.PARAMETER, index=index + offset): {
                (fact.kind, fact) for fact in result.facts
            }
            for index, result in enumerate(positional)
        }
        if bound_receiver and receiver_result is not None:
            inputs[SummaryPort(SummaryPortKind.PARAMETER, index=0)] = {
                (fact.kind, fact) for fact in receiver_result.facts
            }
        parameter_indices = {
            parameter: index for index, parameter in enumerate(summary.parameters)
        }
        for keyword, result in zip(call.keywords, keywords):
            if keyword.arg is None or keyword.arg not in parameter_indices:
                continue
            port = SummaryPort(
                SummaryPortKind.PARAMETER,
                index=parameter_indices[keyword.arg],
            )
            inputs[port] = inputs.get(port, set()) | {
                (fact.kind, fact) for fact in result.facts
            }
        values = summary.propagate_tokens(inputs)
        returned = values.get(SummaryPort(SummaryPortKind.RETURN), frozenset())
        for kind, token in returned:
            if isinstance(token, TaintFact):
                source = TaintFact(token.location, kind, token.origin)
                state = state.write(
                    call_location,
                    (source,),
                    strong=False,
                    operation=ProvenanceOperation.CALL,
                    filename=self.context.filename,
                    line=getattr(call, "lineno", None),
                    detail=name,
                )
                continue
            origin = TaintOrigin(
                kind,
                self.context.filename,
                getattr(call, "lineno", None),
                symbol=name,
            )
            state = state.introduce(call_location, {kind}, origin)
        for sink in summary.sinks:
            sink_values = values.get(sink.port, frozenset())
            if not sink_values:
                continue
            facts = frozenset(
                TaintFact(
                    token.location if isinstance(token, TaintFact) else call_location,
                    kind,
                    (
                        token.origin
                        if isinstance(token, TaintFact)
                        else TaintOrigin(
                            kind,
                            self.context.filename,
                            getattr(call, "lineno", None),
                            symbol=name,
                        )
                    ),
                )
                for kind, token in sink_values
            )
            if facts:
                events.add(
                    TaintSinkEvent(
                        sink.procedure or self.context.procedure,
                        sink.filename or self.context.filename,
                        sink.sink_name,
                        frozenset({"dangerous"}),
                        sink.argument_index,
                        sink.line,
                        facts,
                    )
                )
        actuals: dict[int, ExpressionResult] = {
            index + offset: result for index, result in enumerate(positional)
        }
        if bound_receiver and receiver_result is not None:
            actuals[0] = receiver_result
        for port in summary.writes:
            actual = actuals.get(port.index if port.index is not None else -1)
            if actual is None or actual.location is None:
                continue
            target = actual.location.descendants(port.path)
            tokens = values.get(port, frozenset())
            write_facts = tuple(
                TaintFact(
                    target,
                    kind,
                    (
                        token.origin
                        if isinstance(token, TaintFact)
                        else TaintOrigin(
                            kind,
                            self.context.filename,
                            getattr(call, "lineno", None),
                            symbol=name,
                        )
                    ),
                )
                for kind, token in tokens
            )
            state = state.write(
                target,
                write_facts,
                strong=False,
                operation=ProvenanceOperation.WRITE,
                filename=self.context.filename,
                line=getattr(call, "lineno", None),
                detail=f"summary:{name}",
            )
        for effect in summary.kills:
            port = effect.port
            actual = actuals.get(port.index if port.index is not None else -1)
            if actual is None or actual.location is None:
                continue
            target = actual.location.descendants(port.path)
            state = state.kill(target, effect.kinds)
        return state

    def _resolve_summary_name(self, name: str) -> tuple[str | None, bool]:
        if name in self.context.summaries:
            return name, False
        short = name.rsplit(".", 1)[-1]
        candidates = [
            candidate
            for candidate in self.context.summaries
            if candidate.rsplit(".", 1)[-1] == short
        ]
        if len(candidates) == 1:
            return candidates[0], False
        return None, len(candidates) > 1

    def _evaluate_many(self, expressions, state: TaintState) -> ExpressionResult:
        current = state
        facts: set[TaintFact] = set()
        events: set[object] = set()
        for expression in expressions:
            evaluated = self.evaluate(expression, current)
            current = evaluated.state
            facts.update(evaluated.facts)
            events.update(evaluated.events)
        return ExpressionResult(current, frozenset(facts), events=frozenset(events))

    def _assign_target(
        self, target: ast.AST, value: ExpressionResult, state: TaintState
    ) -> TaintState:
        location = self.location_of(target)
        if location is None:
            return state
        if value.location is not None:
            return state.copy(
                value.location,
                location,
                strong=not location.selectors,
                filename=self.context.filename,
                line=getattr(target, "lineno", None),
            )
        return state.write(
            location,
            value.facts,
            strong=not location.selectors,
            filename=self.context.filename,
            line=getattr(target, "lineno", None),
        )

    @staticmethod
    def _literal_selector(expression: ast.AST):
        if isinstance(expression, ast.Constant) and isinstance(
            expression.value, (str, int)
        ):
            return expression.value
        return None

    @staticmethod
    def _call_name(function: ast.AST) -> str:
        if isinstance(function, ast.Name):
            return function.id
        if isinstance(function, ast.Attribute):
            parts = [function.attr]
            current = function.value
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return ""
