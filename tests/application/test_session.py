from dataclasses import FrozenInstanceError
from unittest.mock import patch

import pytest

from pyflow.application.program import Program
from pyflow.application.session import AnalysisOptions
from pyflow.application.passes.base import AnalysisPass, OptimizationPass, PassResult
from pyflow.application.passes.builtin import CPAAnalysisPass
from pyflow.application.passes.manager import PassManager
from pyflow.ir.core import AnalysisFacts, FactResult, IRCatalog, Precision, StaleAnalysisFacts


class CountingAnalysis(AnalysisPass):
    def __init__(self):
        super().__init__("ipa")
        self.calls = 0

    def run(self, compiler, program):
        self.calls += 1
        program.session.record_result("ipa", self.calls)
        return PassResult(data=self.calls)


class Change(OptimizationPass):
    def __init__(self, *, preserves=(), fail=False):
        super().__init__("change")
        self.info.preserves.update(preserves)
        self.fail = fail

    def run(self, compiler, program):
        if self.fail:
            program.liveCode.clear()
            raise RuntimeError("partial rewrite")
        return PassResult(changed=True)


def _publish(program, producer):
    program.ir.facts.publish("contexts", producer, {"code": FactResult.exact({producer}, producer)})
    program.session.record_result(producer, producer)


def test_changed_pass_retires_solver_results_and_published_facts():
    program = Program()
    _publish(program, "ipa")
    view = AnalysisFacts(program.ir)
    before = program.ir.revision
    manager = PassManager(enable_caching=False)
    manager.register_pass(Change())

    manager.run_passes(None, program, ["change"])

    assert program.ir.revision != before
    assert not program.session.results
    assert program.ir.facts.query("contexts", "code").precision is Precision.UNKNOWN
    with pytest.raises(StaleAnalysisFacts):
        view.context_ids(object())


def test_preservation_keeps_only_the_promised_producer():
    program = Program()
    _publish(program, "ipa")
    _publish(program, "cpa")
    manager = PassManager()
    manager.register_pass(CountingAnalysis())
    manager.register_pass(Change(preserves={"ipa"}))
    manager.run_passes(None, program, ["ipa", "change", "ipa"])

    assert manager.passes["ipa"].calls == 1
    assert program.session.get_result("ipa") == 1
    assert program.session.get_result("cpa") is None
    assert program.ir.facts.query("contexts", "code").values == {"ipa"}


@pytest.mark.parametrize("replace_catalog", [False, True])
def test_external_ir_change_retires_caches_in_every_manager(replace_catalog):
    program = Program()
    managers = [PassManager(), PassManager()]
    for manager in managers:
        manager.register_pass(CountingAnalysis())
        manager.run_passes(None, program, ["ipa"])
    if replace_catalog:
        program.ir = IRCatalog()
    else:
        program.ir.commit_revision()

    assert program.session.get_result("ipa") is None
    for manager in managers:
        manager.run_passes(None, program, ["ipa"])
        assert manager.passes["ipa"].calls == 2


def test_partial_failure_retires_previously_cached_results():
    program = Program()
    _publish(program, "ipa")
    manager = PassManager()
    manager.register_pass(CountingAnalysis())
    manager.register_pass(Change(fail=True))
    results = manager.run_passes(None, program, ["ipa", "change"])

    assert not results["change"].success
    assert not program.session.results
    assert not program.ir.facts.capabilities()
    assert not manager.cache.pass_names(program)


def test_configuration_is_immutable_and_independent_between_programs():
    first = Program(options=AnalysisOptions(cpa_path_length=1, enable_caching=False))
    second = Program(options=AnalysisOptions(cpa_path_length=5))
    analysis = CPAAnalysisPass("cpa_path_sensitive", first_pass=False)
    with patch("pyflow.application.passes.builtin.cpa.evaluate", return_value="result") as evaluate:
        analysis.run(None, first)
        analysis.run(None, second)
        analysis.run(None, first)

    assert [call.args[2] for call in evaluate.call_args_list] == [1, 5, 1]
    assert first.session.pass_manager.cache is None
    assert second.session.pass_manager.cache is not None
    assert first.session.pass_manager is not second.session.pass_manager
    with pytest.raises(FrozenInstanceError):
        first.session.options.cpa_path_length = 9


def test_reconfiguration_retires_old_results_and_the_scheduler():
    program = Program()
    _publish(program, "ipa")
    manager = program.session.pass_manager
    program.session.configure(AnalysisOptions(cpa_path_length=7))

    assert program.session.get_result("ipa") is None
    assert not program.ir.facts.capabilities()
    assert program.session.pass_manager is not manager
    assert program.session.options.cpa_path_length == 7


def test_preservation_cannot_resurrect_results_from_an_older_revision():
    program = Program()
    manager = PassManager()
    manager.register_pass(CountingAnalysis())
    manager.register_pass(Change(preserves={"ipa"}))
    manager.run_passes(None, program, ["ipa"])
    program.ir.commit_revision()

    manager.run_passes(None, program, ["change"])
    assert program.session.get_result("ipa") is None
    manager.run_passes(None, program, ["ipa"])
    assert manager.passes["ipa"].calls == 2
