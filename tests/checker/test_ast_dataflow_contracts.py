from pyflow.checker.ast_dataflow.modeling import (
    ContractPort,
    PortKind,
    SanitizerContract,
    SanitizerContractRegistry,
    TaintTransform,
)
import ast

from pyflow.analysis.taint import TaintPolicy
from pyflow.checker.ast_dataflow.semantics import TaintSinkEvent, analyze_ast_function


def test_taint_transform_supports_kind_changes_and_composition():
    escape = TaintTransform(maps={"html.raw": "html.escaped"})
    shell_cleaner = TaintTransform(removes=frozenset({"shell"}))

    result = escape.then(shell_cleaner).apply({"html.raw", "shell"})

    assert result == frozenset({"html.escaped"})


def test_sanitizer_contract_registry_retains_semantic_ports():
    contract = SanitizerContract(
        call_name="escape_html",
        input_port=ContractPort(PortKind.PARAMETER, index=0),
        output_port=ContractPort(PortKind.RETURN),
        transform=TaintTransform(removes=frozenset({"html"})),
    )
    registry = SanitizerContractRegistry([contract])

    assert registry.for_call("escape_html") == (contract,)


def test_guarded_sanitizer_joins_sanitized_and_unsanitized_outcomes():
    registry = SanitizerContractRegistry(
        [
            SanitizerContract(
                call_name="conditionally_clean",
                input_port=ContractPort(PortKind.PARAMETER, index=0),
                output_port=ContractPort(PortKind.RETURN),
                transform=TaintTransform(removes=frozenset({"html"})),
                guard="strict_mode",
            )
        ]
    )
    policy = TaintPolicy(
        source_kinds_by_call={"source": frozenset({"html"})},
        sink_kinds_by_call={"sink": frozenset({"dangerous"})},
        sink_positions_by_call={"sink": frozenset({0})},
    )
    function = ast.parse("""
def f():
    sink(conditionally_clean(source()))
""").body[0]

    result = analyze_ast_function(
        function,
        procedure="f",
        filename="contract.py",
        policy=policy,
        contracts=registry,
    )

    assert any(isinstance(event, TaintSinkEvent) for event in result.events)
    assert any(
        diagnostic.code == "conditional-sanitizer-guard"
        for diagnostic in result.diagnostics
    )


def test_contract_assumptions_make_completeness_explicit():
    registry = SanitizerContractRegistry(
        [
            SanitizerContract(
                call_name="trusted_clean",
                input_port=ContractPort(PortKind.PARAMETER, index=0),
                output_port=ContractPort(PortKind.RETURN),
                transform=TaintTransform(removes=frozenset({"*"})),
                assumptions=frozenset({"library implementation matches contract"}),
            )
        ]
    )
    policy = TaintPolicy(
        source_kinds_by_call={"source": frozenset({"html"})},
    )
    function = ast.parse("def f():\n    return trusted_clean(source())\n").body[0]

    result = analyze_ast_function(
        function,
        procedure="f",
        filename="contract.py",
        policy=policy,
        contracts=registry,
    )

    assert result.status == "partial"
    assert any(
        diagnostic.code == "sanitizer-contract-assumption"
        for diagnostic in result.diagnostics
    )
