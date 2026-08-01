from pyflow.analysis.entrypoints import EntryPointMode, EntryPointOptions
from pyflow.analysis.taint import TaintPolicy
from pyflow.checker.ast_dataflow.solver.interprocedural import (
    ASTInterproceduralAnalyzer,
)


def test_summary_chain_converges_with_bounded_round_count():
    count = 24
    sources = {
        f"f{index}": (
            f"def f{index}(value):\n"
            + (
                f"    return f{index + 1}(value)\n"
                if index + 1 < count
                else "    return value\n"
            )
        )
        for index in range(count)
    }
    policy = TaintPolicy(source_kinds_by_call={"source": frozenset({"test"})})

    result = ASTInterproceduralAnalyzer(policy).analyze(
        sources,
        entry_functions=("f0",),
        entry_point_options=EntryPointOptions(mode=EntryPointMode.DECLARED_ONLY),
    )

    assert result.status == "complete"
    assert result.rounds <= count + 2
    assert len(result.summaries) == count
