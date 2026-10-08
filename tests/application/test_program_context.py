from pyflow.application.context import CompilerContext
from pyflow.application.program import Program


def test_compiler_context_provides_run_services():
    context = CompilerContext()

    assert isinstance(context, CompilerContext)
    assert hasattr(context, "console")
    assert hasattr(context, "slots")
    assert hasattr(context, "stats")


def test_program_analysis_registry_has_one_canonical_entry_per_analysis():
    program = Program()

    program.session.record_result("ipa", "ipa-value")
    program.session.record_result("cpa", "cpa-value")
    program.session.record_result("lifetime", "lifetime-value")

    assert program.session.get_result("ipa") == "ipa-value"
    assert program.session.get_result("cpa") == "cpa-value"
    assert program.session.get_result("lifetime") == "lifetime-value"

    program.session.invalidate_results({"ipa", "cpa_path_sensitive", "lifetime_refresh"})

    assert program.session.results == {}
