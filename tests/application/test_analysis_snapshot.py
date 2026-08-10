from types import SimpleNamespace

from pyflow.application.analysis_snapshot import AnalysisFeatures, AnalysisSnapshot
from pyflow.api.queries import create_query_components


def _program():
    return SimpleNamespace(liveCode=[], analysis_results={}, interface=None, ir=None)


def test_query_components_are_constructed_without_protocol_or_manager():
    program = _program()
    queries = create_query_components(object(), program)

    assert queries.context.program is program
    assert queries.call_graph.context is queries.context
    assert queries.control_flow.context is queries.context


def test_snapshots_are_revision_pinned_and_do_not_share_query_components():
    program = _program()
    first = AnalysisSnapshot.create(
        program=program,
        compiler=object(),
        source_index=object(),
        revision=1,
    )
    second = AnalysisSnapshot.create(
        program=program,
        compiler=object(),
        source_index=object(),
        revision=2,
    )

    assert first.revision == 1
    assert second.revision == 2
    assert first.queries is not second.queries


def test_features_describe_analysis_facts_not_protocol_tools():
    program = _program()
    program.analysis_results = {"ipa": object(), "heap": object()}

    features = AnalysisFeatures.from_program(program, type_info=True)

    assert features.call_graph
    assert features.heap
    assert features.type_info
    assert features.supports("callers")
    assert not features.supports("lifetime")
