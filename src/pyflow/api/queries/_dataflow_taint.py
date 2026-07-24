"""
Helpers for IFDS-backed taint query reporting.
"""

from typing import Optional, Set

from pyflow.analysis.ifds import TaintConfiguration, analyze_taint
from pyflow.analysis.ifds.modeling.calls import CallModel, CallModelRegistry
from pyflow.analysis.ifds.modeling.taint import TaintRule

from ._models import TaintFlowReport


class TaintAnalyzer:
    """Run the IFDS taint engine and adapt results to the query API."""

    def run(
        self,
        *,
        context,
        graph_engine,
        function,
        source_names: Set[str],
        sink_names: Set[str],
        sanitizer_names: Optional[Set[str]] = None,
    ) -> TaintFlowReport:
        sanitizer_names = sanitizer_names or set()
        code = context.resolve_function(function)
        cfg = graph_engine.get_cfg(code)
        adapter = graph_engine.get_ifds_supergraph()
        result = analyze_taint(
            adapter,
            TaintConfiguration(
                call_models=CallModelRegistry(
                    [
                        *(
                            CallModel(name, source_kinds=frozenset({"query.source"}))
                            for name in source_names
                        ),
                        *(
                            CallModel(name, sink_kinds=frozenset({"query.sink"}))
                            for name in sink_names
                        ),
                        *(
                            CallModel(name, sanitizer_kinds=frozenset({"*"}))
                            for name in sanitizer_names
                        ),
                    ]
                ),
                rules=(
                    TaintRule(
                        "PYFLOW-QUERY-TAINT",
                        "Configured query taint flow",
                        frozenset({"query.source"}),
                        frozenset({"query.sink"}),
                    ),
                ),
            ),
            entry_nodes=[adapter.supergraph.entry_of(cfg)],
            record_traces=True,
        )

        findings = []
        for finding in result.findings:
            tainted_arguments = [local.name for local in finding.tainted_arguments]
            if not tainted_arguments:
                tainted_arguments = list(finding.tainted_argument_labels)
            findings.append(
                {
                    "sink_name": finding.sink_name,
                    "procedure": context.code_name(finding.sink.procedure.code),
                    "block_kind": finding.sink.kind,
                    "tainted_arguments": tainted_arguments,
                    "explanations": (
                        [
                            {
                                "source": getattr(
                                    edge.source_node.procedure.code, "name", None
                                ),
                                "target_kind": edge.node.kind,
                                "trace": [
                                    {"kind": step.kind, "note": step.note}
                                    for step in traces
                                ],
                            }
                            for edge, traces in result.explain_fact(
                                finding.sink,
                                result.fact_for_local(
                                    finding.sink, finding.tainted_arguments[0]
                                ),
                            ).items()
                        ]
                        if finding.tainted_arguments
                        else []
                    ),
                }
            )

        return TaintFlowReport(
            function=context.code_name(code) or "<unknown>",
            findings=findings,
            statistics=result.statistics.__dict__,
        )
