"""Statement transfer functions and source-AST function analysis."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Iterable, Mapping, cast

from pyflow.analysis.taint import TaintPolicy

from ..domain import (
    AnalysisUncertainty,
    PrecisionLevel,
    ProvenanceOperation,
    TaintLocation,
    TaintOrigin,
    TaintState,
)
from ..frontend import ASTCFGBuilder, ASTCFGNode, ASTNodeKind
from ..modeling import CallShapeContractRegistry, SanitizerContractRegistry
from .events import TaintSinkEvent
from ..solver import (
    CFGEdge,
    CFGSolverResult,
    EdgeKind,
    FlowOutcome,
    MonotoneCFGDataflowSolver,
    ProcedureTaintSummary,
    SolverOptions,
    TransferResult,
)
from .expressions import ExpressionContext, ExpressionResult, PythonExpressionSemantics
from .refinement import RefinementProvider, SyntacticRefinementProvider

_TRY_STAR = getattr(ast, "TryStar", None)


def _is_try_statement(statement: ast.AST | None) -> bool:
    return isinstance(statement, ast.Try) or (
        _TRY_STAR is not None and isinstance(statement, _TRY_STAR)
    )


@dataclass(frozen=True)
class ASTFunctionAnalysisResult:
    procedure: str
    cfg_result: CFGSolverResult[ASTCFGNode]
    diagnostics: tuple[AnalysisUncertainty, ...]
    status: str

    @property
    def events(self) -> frozenset[object]:
        return self.cfg_result.events

    @property
    def returned(self) -> FlowOutcome | None:
        return self.cfg_result.returned


class PythonStatementTransfer:
    def __init__(
        self,
        expressions: PythonExpressionSemantics,
        refinement: RefinementProvider | None = None,
    ) -> None:
        self.expressions = expressions
        self.refinement = refinement or SyntacticRefinementProvider()

    def __call__(
        self,
        node: ASTCFGNode,
        state: TaintState,
        edges: tuple[CFGEdge[ASTCFGNode], ...],
    ) -> TransferResult[ASTCFGNode]:
        if node.kind in {
            ASTNodeKind.ENTRY,
            ASTNodeKind.EXIT,
            ASTNodeKind.BREAK,
            ASTNodeKind.CONTINUE,
        }:
            return TransferResult.identity(edges, state)
        if node.kind is ASTNodeKind.TRY:
            return self._try_entry(node, state, edges)
        if node.kind is ASTNodeKind.HANDLER_DISPATCH:
            return self._handler_dispatch(node, state, edges)
        if node.kind is ASTNodeKind.BRANCH:
            return self._branch(node, state, edges)
        if node.kind is ASTNodeKind.LOOP:
            return self._loop(node, state, edges)
        if node.kind is ASTNodeKind.MATCH:
            return self._match(node, state, edges)
        if node.kind is ASTNodeKind.RETURN:
            return self._return(node, state, edges)
        if node.kind is ASTNodeKind.RAISE:
            return self._raise(node, state, edges)
        return self._statement(node, state, edges)

    def _branch(
        self,
        node: ASTCFGNode,
        state: TaintState,
        edges: tuple[CFGEdge[ASTCFGNode], ...],
    ) -> TransferResult[ASTCFGNode]:
        statement = node.syntax
        assert isinstance(statement, ast.If)
        evaluated = self.expressions.evaluate(statement.test, state)
        decided = self._constant_bool(statement.test)
        outgoing = []
        for edge in edges:
            if decided is True and edge.kind is EdgeKind.FALSE:
                continue
            if decided is False and edge.kind is EdgeKind.TRUE:
                continue
            outgoing.append((edge, evaluated.state))
        return TransferResult(tuple(outgoing), events=evaluated.events)

    def _loop(
        self,
        node: ASTCFGNode,
        state: TaintState,
        edges: tuple[CFGEdge[ASTCFGNode], ...],
    ) -> TransferResult[ASTCFGNode]:
        statement = node.syntax
        if isinstance(statement, ast.While):
            evaluated = self.expressions.evaluate(statement.test, state)
            decided = self._constant_bool(statement.test)
            outgoing = []
            for edge in edges:
                if decided is True and edge.kind is EdgeKind.FALSE:
                    continue
                if decided is False and edge.kind is EdgeKind.TRUE:
                    continue
                outgoing.append((edge, evaluated.state))
            return TransferResult(tuple(outgoing), events=evaluated.events)

        assert isinstance(statement, (ast.For, ast.AsyncFor))
        evaluated = self.expressions.evaluate(statement.iter, state)
        outgoing = []
        for edge in edges:
            edge_state = evaluated.state
            if edge.kind is EdgeKind.TRUE:
                edge_state = self._assign(statement.target, evaluated, edge_state, node)
            outgoing.append((edge, edge_state))
        return TransferResult(tuple(outgoing), events=evaluated.events)

    def _match(
        self,
        node: ASTCFGNode,
        state: TaintState,
        edges: tuple[CFGEdge[ASTCFGNode], ...],
    ) -> TransferResult[ASTCFGNode]:
        statement = node.syntax
        assert isinstance(statement, ast.Match)
        evaluated = self.expressions.evaluate(statement.subject, state)
        outgoing = []
        for case, edge in zip(statement.cases, edges):
            edge_state = evaluated.state
            for name in self._pattern_bindings(case.pattern):
                target = ast.Name(id=name, ctx=ast.Store())
                target.lineno = getattr(case.pattern, "lineno", node.line or 0)
                edge_state = self._assign(target, evaluated, edge_state, node)
            outgoing.append((edge, edge_state))
        uncertainty = AnalysisUncertainty(
            code="pattern-guard-overapproximation",
            message="Match guards and pattern feasibility are joined conservatively",
            level=PrecisionLevel.CONSERVATIVE,
            function=node.procedure,
            filename=self.expressions.context.filename,
            line=node.line,
            operation="match",
        )
        outgoing = [
            (edge, edge_state.with_uncertainty(uncertainty))
            for edge, edge_state in outgoing
        ]
        return TransferResult(tuple(outgoing), events=evaluated.events)

    def _return(
        self,
        node: ASTCFGNode,
        state: TaintState,
        edges: tuple[CFGEdge[ASTCFGNode], ...],
    ) -> TransferResult[ASTCFGNode]:
        statement = node.syntax
        assert isinstance(statement, ast.Return)
        evaluated = self.expressions.evaluate(statement.value, state)
        exceptional = tuple(
            (edge, state.join(evaluated.state))
            for edge in edges
            if edge.kind is EdgeKind.EXCEPTION
        )
        if exceptional:
            return TransferResult(exceptional, events=evaluated.events)
        return TransferResult(
            returned=FlowOutcome(evaluated.state, evaluated.facts),
            events=evaluated.events,
        )

    def _raise(
        self,
        node: ASTCFGNode,
        state: TaintState,
        edges: tuple[CFGEdge[ASTCFGNode], ...],
    ) -> TransferResult[ASTCFGNode]:
        statement = node.syntax
        assert isinstance(statement, ast.Raise)
        evaluated = self.expressions.evaluate(statement.exc, state)
        if edges:
            exception_location = TaintLocation(("exception", node.procedure))
            exceptional_state = evaluated.state.write(
                exception_location,
                evaluated.facts,
                strong=True,
                operation=ProvenanceOperation.RAISE,
                filename=self.expressions.context.filename,
                line=node.line,
            )
            return TransferResult(
                tuple((edge, exceptional_state) for edge in edges),
                events=evaluated.events,
            )
        return TransferResult(
            raised=FlowOutcome(evaluated.state, evaluated.facts),
            events=evaluated.events,
        )

    def _try_entry(
        self,
        node: ASTCFGNode,
        state: TaintState,
        edges: tuple[CFGEdge[ASTCFGNode], ...],
    ) -> TransferResult[ASTCFGNode]:
        statement = node.syntax
        assert _is_try_statement(statement)
        statement = cast(ast.Try, statement)
        current = state
        if statement.finalbody:
            current = current.with_uncertainty(
                AnalysisUncertainty(
                    code="finally-abrupt-outcome-overapproximation",
                    message=(
                        "Finally runs precisely on normal/handled paths; abrupt "
                        "return and exception payload ordering is conservative"
                    ),
                    level=PrecisionLevel.CONSERVATIVE,
                    function=node.procedure,
                    filename=self.expressions.context.filename,
                    line=node.line,
                    operation="try-finally",
                )
            )
        return TransferResult.identity(edges, current)

    def _handler_dispatch(
        self,
        node: ASTCFGNode,
        state: TaintState,
        edges: tuple[CFGEdge[ASTCFGNode], ...],
    ) -> TransferResult[ASTCFGNode]:
        statement = node.syntax
        assert _is_try_statement(statement)
        statement = cast(ast.Try, statement)
        exception_location = TaintLocation(("exception", node.procedure))
        exception_value = ExpressionResult(
            state,
            state.facts_at(exception_location),
            exception_location,
        )
        outgoing = []
        handler_edges = [edge for edge in edges if edge.kind is EdgeKind.EXCEPTION]
        for handler, edge in zip(statement.handlers, handler_edges):
            edge_state = state
            if handler.name:
                target = ast.Name(id=handler.name, ctx=ast.Store())
                target.lineno = getattr(handler, "lineno", node.line or 0)
                edge_state = self._assign(target, exception_value, edge_state, node)
            outgoing.append((edge, edge_state))
        if len(handler_edges) > len(statement.handlers):
            outgoing.extend(
                (edge, state) for edge in handler_edges[len(statement.handlers) :]
            )
        return TransferResult(tuple(outgoing))

    def _statement(
        self,
        node: ASTCFGNode,
        state: TaintState,
        edges: tuple[CFGEdge[ASTCFGNode], ...],
    ) -> TransferResult[ASTCFGNode]:
        statement = node.syntax
        assert isinstance(statement, ast.stmt)
        current = state
        events: frozenset[object] = frozenset()

        if isinstance(statement, ast.Assign):
            value = self.expressions.evaluate(statement.value, current)
            current = value.state
            event_set = set(value.events)
            for target in statement.targets:
                current = self._assign(target, value, current, node)
                response_event = self._response_attribute_event(target, value, node)
                if response_event is not None:
                    event_set.add(response_event)
            events = frozenset(event_set)
        elif isinstance(statement, ast.AnnAssign):
            value = self.expressions.evaluate(statement.value, current)
            current = self._assign(statement.target, value, value.state, node)
            event_set = set(value.events)
            response_event = self._response_attribute_event(
                statement.target, value, node
            )
            if response_event is not None:
                event_set.add(response_event)
            events = frozenset(event_set)
        elif isinstance(statement, ast.AugAssign):
            previous = self.expressions.evaluate(statement.target, current)
            value = self.expressions.evaluate(statement.value, previous.state)
            combined = ExpressionResult(
                value.state,
                previous.facts | value.facts,
                events=previous.events | value.events,
            )
            current = self._assign(statement.target, combined, value.state, node)
            events = combined.events
        elif isinstance(statement, ast.Expr):
            if isinstance(statement.value, (ast.Yield, ast.YieldFrom)):
                value = self.expressions.evaluate(statement.value.value, current)
                current, events = value.state, value.events
                return TransferResult(
                    tuple((edge, current) for edge in edges),
                    yielded=FlowOutcome(current, value.facts),
                    events=events,
                )
            value = self.expressions.evaluate(statement.value, current)
            current, events = value.state, value.events
        elif isinstance(statement, ast.Delete):
            for target in statement.targets:
                location = self.expressions.location_of(target)
                if location is not None:
                    current = current.kill(location)
        elif isinstance(statement, ast.Assert):
            value = self.expressions._evaluate_many(
                (statement.test, statement.msg), current
            )
            current, events = value.state, value.events
        elif isinstance(statement, (ast.With, ast.AsyncWith)):
            event_set: set[object] = set()
            for item in statement.items:
                value = self.expressions.evaluate(item.context_expr, current)
                current = value.state
                event_set.update(value.events)
                if item.optional_vars is not None:
                    current = self._assign(item.optional_vars, value, current, node)
            current = current.with_uncertainty(
                AnalysisUncertainty(
                    code="context-manager-exit-effects",
                    message="Context manager __exit__ effects are conservative",
                    level=PrecisionLevel.CONSERVATIVE,
                    function=node.procedure,
                    filename=self.expressions.context.filename,
                    line=node.line,
                    operation="with",
                )
            )
            events = frozenset(event_set)
        elif isinstance(
            statement, (ast.Import, ast.ImportFrom, ast.Pass, ast.Global, ast.Nonlocal)
        ):
            pass
        elif isinstance(
            statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ):
            # Definitions execute decorators/default expressions, but nested
            # bodies are separate procedures.
            expressions: list[ast.AST] = list(statement.decorator_list)
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                expressions.extend(default for default in statement.args.defaults)
                expressions.extend(
                    default
                    for default in statement.args.kw_defaults
                    if default is not None
                )
            value = self.expressions._evaluate_many(expressions, current)
            current, events = value.state, value.events
        else:
            current = current.with_uncertainty(
                AnalysisUncertainty(
                    code="unsupported-statement",
                    message=f"No precise transfer for {type(statement).__name__}",
                    level=PrecisionLevel.UNSUPPORTED,
                    function=node.procedure,
                    filename=self.expressions.context.filename,
                    line=node.line,
                    operation=type(statement).__name__,
                )
            )

        outgoing = []
        for edge in edges:
            if edge.kind is EdgeKind.EXCEPTION:
                uncertainty = AnalysisUncertainty(
                    code="exception-prefix-overapproximation",
                    message="Exceptional edge joins pre- and post-statement effects",
                    level=PrecisionLevel.CONSERVATIVE,
                    function=node.procedure,
                    filename=self.expressions.context.filename,
                    line=node.line,
                    operation=type(statement).__name__,
                )
                edge_state = state.join(current).with_uncertainty(uncertainty)
            else:
                edge_state = current
            outgoing.append((edge, edge_state))
        return TransferResult(tuple(outgoing), events=events)

    def _response_attribute_event(
        self, target: ast.AST, value: ExpressionResult, node: ASTCFGNode
    ) -> TaintSinkEvent | None:
        """Model direct writes to common framework response body fields."""
        if not isinstance(target, ast.Attribute) or target.attr not in {"text", "body"}:
            return None
        receiver = target.value
        while isinstance(receiver, ast.Attribute):
            receiver = receiver.value
        if not isinstance(receiver, ast.Name) or receiver.id not in {
            "resp",
            "response",
        }:
            return None
        if not value.facts:
            return None
        return TaintSinkEvent(
            node.procedure,
            self.expressions.context.filename,
            f"{receiver.id}.{target.attr}",
            frozenset({"xss"}),
            None,
            node.line,
            value.facts,
        )

    def _assign(
        self,
        target: ast.AST,
        value: ExpressionResult,
        state: TaintState,
        program_point: object,
    ) -> TaintState:
        if isinstance(target, (ast.Tuple, ast.List)):
            current = state
            for element in target.elts:
                if isinstance(element, ast.Starred):
                    element = element.value
                current = self._assign(element, value, current, program_point)
            return current
        location = self.expressions.location_of(target)
        if location is None:
            return state.with_uncertainty(
                AnalysisUncertainty(
                    code="unknown-assignment-target",
                    message=f"Cannot resolve assignment target {type(target).__name__}",
                    level=PrecisionLevel.UNSUPPORTED,
                    function=self.expressions.context.procedure,
                    filename=self.expressions.context.filename,
                    line=getattr(target, "lineno", None),
                    operation=type(target).__name__,
                )
            )
        location = state.abstract_location(location)
        decision = self.refinement.update_decision(location, program_point)
        current = state
        for uncertainty in decision.uncertainties:
            current = current.with_uncertainty(uncertainty)
        detail = ",".join(decision.reasons) or None
        if value.location is not None:
            return current.copy(
                value.location,
                location,
                strong=decision.strong,
                operation=ProvenanceOperation.ASSIGN,
                filename=self.expressions.context.filename,
                line=getattr(target, "lineno", None),
                detail=detail,
            )
        return current.write(
            location,
            value.facts,
            strong=decision.strong,
            operation=ProvenanceOperation.ASSIGN,
            filename=self.expressions.context.filename,
            line=getattr(target, "lineno", None),
            detail=detail,
        )

    @staticmethod
    def _constant_bool(expression: ast.AST) -> bool | None:
        if isinstance(expression, ast.Constant) and isinstance(expression.value, bool):
            return expression.value
        if isinstance(expression, ast.UnaryOp) and isinstance(expression.op, ast.Not):
            inner = PythonStatementTransfer._constant_bool(expression.operand)
            return None if inner is None else not inner
        return None

    @staticmethod
    def _pattern_bindings(pattern: ast.pattern) -> set[str]:
        result: set[str] = set()
        for node in ast.walk(pattern):
            if isinstance(node, ast.MatchAs) and node.name:
                result.add(node.name)
            elif isinstance(node, ast.MatchStar) and node.name:
                result.add(node.name)
            elif isinstance(node, ast.MatchMapping) and node.rest:
                result.add(node.rest)
        return result


def analyze_ast_function(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    procedure: str,
    filename: str | None,
    policy: TaintPolicy,
    entry_taint: Mapping[str, Iterable[str]] | None = None,
    summaries: Mapping[str, ProcedureTaintSummary] | None = None,
    contracts: SanitizerContractRegistry | None = None,
    shape_contracts: CallShapeContractRegistry | None = None,
    refinement: RefinementProvider | None = None,
    solver_options: SolverOptions | None = None,
    known_functions: Iterable[str] = (),
    import_aliases: Mapping[str, str] | None = None,
) -> ASTFunctionAnalysisResult:
    context = ExpressionContext(
        procedure=procedure,
        filename=filename,
        policy=policy,
        summaries=summaries or {},
        contracts=contracts or SanitizerContractRegistry(),
        shape_contracts=shape_contracts or CallShapeContractRegistry(),
        known_functions=frozenset(known_functions),
        import_aliases=import_aliases or {},
    )
    expressions = PythonExpressionSemantics(context)
    transfer = PythonStatementTransfer(expressions, refinement)
    initial = TaintState()
    for name, kinds in (entry_taint or {}).items():
        location = TaintLocation((procedure, name))
        for kind in kinds:
            initial = initial.introduce(
                location,
                {kind},
                TaintOrigin(kind, filename, symbol=f"parameter:{name}"),
            )
    built = ASTCFGBuilder(procedure).build(function)
    cfg_result: CFGSolverResult[ASTCFGNode] = MonotoneCFGDataflowSolver[ASTCFGNode](
        solver_options
    ).solve(built.graph, initial, transfer)
    uncertainties = set(cfg_result.diagnostics)
    for state in cfg_result.in_states.values():
        uncertainties.update(state.uncertainties)
    for outcome in (cfg_result.returned, cfg_result.raised, cfg_result.yielded):
        if outcome is not None:
            uncertainties.update(outcome.state.uncertainties)
    diagnostics = tuple(sorted(uncertainties, key=repr))
    status = (
        "partial"
        if cfg_result.status != "complete"
        or any(item.affects_completeness for item in diagnostics)
        else "complete"
    )
    return ASTFunctionAnalysisResult(procedure, cfg_result, diagnostics, status)
