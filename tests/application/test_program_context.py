from pyflow.application.context import CompilerContext, Context
from pyflow.application.program import Program


def test_context_is_backward_compatible_compiler_context():
    context = Context()

    assert isinstance(context, CompilerContext)
    assert hasattr(context, "console")
    assert hasattr(context, "slots")
    assert hasattr(context, "stats")


def test_program_analysis_registry_tracks_legacy_slots():
    program = Program()

    program.set_analysis_result("ipa", "ipa-value")
    program.set_analysis_result("cpa", "cpa-value")
    program.set_analysis_result("lifetime", "lifetime-value")

    assert program.ipa_analysis == "ipa-value"
    assert program.cpa_analysis == "cpa-value"
    assert program.lifetime_analysis == "lifetime-value"
    assert program.get_analysis_result("ipa_analysis") == "ipa-value"
    assert program.get_analysis_result("cpa_analysis") == "cpa-value"
    assert program.get_analysis_result("lifetime_analysis") == "lifetime-value"

    program.clear_analysis_results({"ipa", "cpa_path_sensitive", "lifetime_refresh"})

    assert program.ipa_analysis is None
    assert program.cpa_analysis is None
    assert program.lifetime_analysis is None
