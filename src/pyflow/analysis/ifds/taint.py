"""Concrete interprocedural taint analysis over CFG-backed supergraphs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import FrozenSet, Iterable, Mapping, Sequence

from pyflow.analysis.cfg import graph as cfg_graph
from pyflow.language.python import ast as py_ast

from .cfg_adapter import CFGNode, CFGSupergraphAdapter, assigned_locals
from .problem import IFDSProblem
from .solver import IFDSSolver
from .transfers import (
    actual_parameters,
    collect_locals,
    formal_parameters,
    identity_unless_killed,
    resolve_call_name,
)


ZERO_TAINT = "ZERO_TAINT"


@dataclass(frozen=True)
class TaintConfiguration:
    """Name-based taint models for direct-call analyses."""

    source_names: FrozenSet[str] = frozenset()
    sink_names: FrozenSet[str] = frozenset()
    sanitizer_names: FrozenSet[str] = frozenset()


@dataclass(frozen=True)
class TaintFinding:
    """A sink reached by tainted data."""

    sink: CFGNode
    sink_name: str
    tainted_arguments: tuple[py_ast.Local, ...]


@dataclass(frozen=True)
class LocalTaintFact:
    """Canonical taint fact for a local name inside one procedure."""

    procedure: cfg_graph.Code
    name: str


class TaintAnalysisResult:
    """Result wrapper with taint queries and sink findings."""

    def __init__(self, ifds_result, findings: Sequence[TaintFinding]) -> None:
        self._ifds_result = ifds_result
        self.findings = tuple(findings)

    def is_tainted(self, node: CFGNode, local: py_ast.Local) -> bool:
        fact = LocalTaintFact(node.procedure, local.name)
        return self._ifds_result.is_reached(node, fact)

    def tainted_locals_at(self, node: CFGNode):
        return frozenset(
            fact.name for fact in self._ifds_result.facts_at(node) if isinstance(fact, LocalTaintFact)
        )


class InterproceduralTaintProblem(
    IFDSProblem[cfg_graph.Code, CFGNode, object]
):
    """IFDS taint problem over CFG nodes."""

    def __init__(
        self,
        adapter: CFGSupergraphAdapter,
        configuration: TaintConfiguration,
        entry_nodes: Sequence[CFGNode] | None = None,
    ) -> None:
        self.adapter = adapter
        self.configuration = configuration
        if entry_nodes is None:
            entry_nodes = [
                adapter.supergraph.entry_of(cfg)
                for cfg in adapter.cfgs
                if cfg in adapter.supergraph.procedures()
            ]
        self.entry_nodes = tuple(entry_nodes)

    @property
    def supergraph(self):
        return self.adapter.supergraph

    @property
    def zero_fact(self):
        return ZERO_TAINT

    def initial_seeds(self) -> Mapping[CFGNode, frozenset[object]]:
        return {node: frozenset({ZERO_TAINT}) for node in self.entry_nodes}

    def normal_flow(self, node: CFGNode, successor: CFGNode, fact: object):
        operation = self.adapter.operation_of(node)
        if operation is None:
            return self._identity_outputs(fact, ())

        if isinstance(operation, py_ast.Assign):
            outputs = set(self._identity_outputs(fact, assigned_locals(operation)))
            if not self.adapter.callees_of(node):
                if self._expr_is_tainted(operation.expr, fact):
                    outputs.update(self._facts_for_locals(node.procedure, assigned_locals(operation)))
                if fact == ZERO_TAINT and self._is_source_call(node):
                    outputs.update(self._facts_for_locals(node.procedure, assigned_locals(operation)))
            return tuple(outputs)

        if isinstance(operation, py_ast.Return):
            outputs = set(self._identity_outputs(fact, ()))
            for ret_param, expr in zip(
                node.procedure.code.codeparameters.returnparams, operation.exprs
            ):
                if self._expr_is_tainted(expr, fact):
                    outputs.add(LocalTaintFact(node.procedure, ret_param.name))
            return tuple(outputs)

        return self._identity_outputs(fact, ())

    def call_flow(self, call_node: CFGNode, callee: cfg_graph.Code, fact: object):
        outputs = set()
        if fact == ZERO_TAINT:
            outputs.add(ZERO_TAINT)

        if self._is_source_call(call_node) or self._is_sanitizer_call(call_node):
            return tuple(outputs)

        call = self.adapter.call_expression_of(call_node)
        if call is None:
            return tuple(outputs)

        params = callee.code.codeparameters
        actuals = self._actual_arguments(call, params)
        formals = self._formal_parameters(params)
        for actual, formal in zip(actuals, formals):
            if self._matches_local_fact(call_node.procedure, fact, actual):
                outputs.add(LocalTaintFact(callee, formal.name))

        return tuple(outputs)

    def return_flow(
        self,
        call_node: CFGNode,
        callee: cfg_graph.Code,
        exit_node: CFGNode,
        return_site: CFGNode,
        call_fact: object,
        exit_fact: object,
    ):
        outputs = set()
        if call_fact == ZERO_TAINT and exit_fact == ZERO_TAINT:
            outputs.add(ZERO_TAINT)

        if self._is_sanitizer_call(call_node):
            return tuple(outputs)

        if self._is_return_fact(callee, exit_fact):
            outputs.update(
                self._facts_for_locals(
                    call_node.procedure, assigned_locals(self.adapter.operation_of(call_node))
                )
            )

        return tuple(outputs)

    def call_to_return_flow(self, call_node: CFGNode, return_site: CFGNode, fact: object):
        operation = self.adapter.operation_of(call_node)
        killed = assigned_locals(operation)
        outputs = set(self._identity_outputs(fact, killed))
        if fact == ZERO_TAINT and self._is_source_call(call_node):
            outputs.update(self._facts_for_locals(call_node.procedure, killed))
        return tuple(outputs)

    def _identity_outputs(self, fact: object, killed: Iterable[py_ast.Local]):
        if fact == ZERO_TAINT:
            return (ZERO_TAINT,)
        if isinstance(fact, LocalTaintFact):
            killed_names = {
                local.name for local in killed if isinstance(local, py_ast.Local) and local.name is not None
            }
            if fact.name in killed_names:
                return ()
        return identity_unless_killed(fact, ())

    def _expr_is_tainted(self, expr, fact: object) -> bool:
        if not isinstance(fact, LocalTaintFact):
            return False
        return any(local.name == fact.name for local in collect_locals(expr))

    def _call_name(self, node: CFGNode) -> str | None:
        call = self.adapter.call_expression_of(node)
        return resolve_call_name(
            call,
            fallback_callee_names=tuple(
                cfg.code.codeName() for cfg in self.adapter.callees_of(node) if cfg.code is not None
            ),
        )

    def _is_source_call(self, node: CFGNode) -> bool:
        name = self._call_name(node)
        return name in self.configuration.source_names

    def _is_sanitizer_call(self, node: CFGNode) -> bool:
        name = self._call_name(node)
        return name in self.configuration.sanitizer_names

    def _is_sink_call(self, node: CFGNode) -> bool:
        name = self._call_name(node)
        return name in self.configuration.sink_names

    def _actual_arguments(self, call, params) -> tuple[py_ast.Local, ...]:
        del params
        return actual_parameters(call)

    def _formal_parameters(self, params) -> tuple[py_ast.Local, ...]:
        return formal_parameters(params)

    def findings(self, result) -> tuple[TaintFinding, ...]:
        findings: list[TaintFinding] = []
        for node in self.adapter.supergraph.nodes():
            if not self._is_sink_call(node):
                continue
            operation = self.adapter.operation_of(node)
            call = self.adapter.call_expression_of(node)
            if operation is None or call is None:
                continue
            tainted_args = tuple(
                arg
                for arg in self._actual_arguments(call, node.procedure.code.codeparameters)
                if result.is_reached(node, LocalTaintFact(node.procedure, arg.name))
            )
            if tainted_args:
                findings.append(
                    TaintFinding(
                        sink=node,
                        sink_name=self._call_name(node) or "<sink>",
                        tainted_arguments=tainted_args,
                    )
                )
        return tuple(findings)

    def _facts_for_locals(self, procedure: cfg_graph.Code, locals_):
        return {
            LocalTaintFact(procedure, local.name)
            for local in locals_
            if isinstance(local, py_ast.Local) and local.name is not None
        }

    def _matches_local_fact(self, procedure: cfg_graph.Code, fact: object, local: py_ast.Local) -> bool:
        return (
            isinstance(fact, LocalTaintFact)
            and fact.procedure is procedure
            and local.name is not None
            and fact.name == local.name
        )

    def _is_return_fact(self, procedure: cfg_graph.Code, fact: object) -> bool:
        if not isinstance(fact, LocalTaintFact) or fact.procedure is not procedure:
            return False
        return any(
            isinstance(local, py_ast.Local) and local.name == fact.name
            for local in procedure.code.codeparameters.returnparams
        )


class InterproceduralTaintAnalysis:
    """Concrete taint analysis backed by the IFDS engine."""

    def __init__(
        self,
        adapter: CFGSupergraphAdapter,
        configuration: TaintConfiguration,
        *,
        entry_nodes: Sequence[CFGNode] | None = None,
    ) -> None:
        self.problem = InterproceduralTaintProblem(
            adapter, configuration, entry_nodes=entry_nodes
        )

    def solve(self) -> TaintAnalysisResult:
        result = IFDSSolver().solve(self.problem)
        return TaintAnalysisResult(result, self.problem.findings(result))


def analyze_taint(
    adapter: CFGSupergraphAdapter,
    configuration: TaintConfiguration,
    *,
    entry_nodes: Sequence[CFGNode] | None = None,
) -> TaintAnalysisResult:
    """Convenience entry point for interprocedural taint analysis."""
    return InterproceduralTaintAnalysis(
        adapter, configuration, entry_nodes=entry_nodes
    ).solve()
