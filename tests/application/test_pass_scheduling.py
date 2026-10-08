"""Runtime prerequisite freshness, independent of result caching."""

import pytest

from pyflow.application.program import Program
from pyflow.application.passes.base import AnalysisPass, OptimizationPass, PassResult, UtilityPass
from pyflow.application.passes.manager import PassManager


class TypeAnalysis(AnalysisPass):
    def __init__(self, events, *, fail_on=None):
        super().__init__("types")
        self.events = events
        self.calls = 0
        self.fail_on = fail_on

    def run(self, compiler, program):
        self.calls += 1
        self.events.append("types")
        if self.calls == self.fail_on:
            raise RuntimeError("type analysis failed")
        program.session.record_result(self.name, program.ir.revision)
        return PassResult(data=program.ir.revision)


class Rewrite(OptimizationPass):
    def __init__(self, events, *, changed=True):
        super().__init__("rewrite")
        self.events = events
        self.changed = changed
        self.info.invalidates.add("types")

    def run(self, compiler, program):
        self.events.append("rewrite")
        return PassResult(changed=self.changed)


class Consumer(UtilityPass):
    def __init__(self, events, *, dependency=False):
        super().__init__("consumer")
        self.events = events
        (self.info.dependencies if dependency else self.info.requirements).add("types")

    def run(self, compiler, program):
        self.events.append("consumer")
        assert program.session.get_result("types") == program.ir.revision
        return PassResult()


@pytest.mark.parametrize("caching", [False, True])
@pytest.mark.parametrize("dependency", [False, True])
def test_consumer_automatically_refreshes_invalidated_analysis(caching, dependency):
    events = []
    manager = PassManager(enable_caching=caching)
    for pass_object in (
        TypeAnalysis(events),
        Rewrite(events),
        Consumer(events, dependency=dependency),
    ):
        manager.register_pass(pass_object)
    program = Program()

    results = manager.run_passes(None, program, ["types", "rewrite", "consumer"])

    assert events == ["types", "rewrite", "types", "consumer"]
    assert results["consumer"].success


def test_refresh_failure_prevents_consumer_execution():
    events = []
    manager = PassManager()
    for pass_object in (TypeAnalysis(events, fail_on=2), Rewrite(events), Consumer(events)):
        manager.register_pass(pass_object)

    results = manager.run_passes(None, Program(), ["types", "rewrite", "consumer"])

    assert events == ["types", "rewrite", "types"]
    assert not results["types"].success
    assert "consumer" not in results


@pytest.mark.parametrize("caching", [False, True])
def test_unchanged_rewrite_does_not_refresh_analysis(caching):
    events = []
    manager = PassManager(enable_caching=caching)
    for pass_object in (TypeAnalysis(events), Rewrite(events, changed=False), Consumer(events)):
        manager.register_pass(pass_object)
    results = manager.run_passes(None, Program(), ["types", "rewrite", "consumer"])
    assert events == ["types", "rewrite", "consumer"]
    assert len(results.records) == 3


@pytest.mark.parametrize("caching", [False, True])
def test_preserved_analysis_remains_available_after_ir_change(caching):
    events = []
    manager = PassManager(enable_caching=caching)
    rewrite = Rewrite(events)
    rewrite.info.invalidates.clear()
    rewrite.info.preserves.add("types")
    analysis = TypeAnalysis(events)

    # Use a payload whose value does not depend on revision equality when preserved.
    def analyze(compiler, program):
        events.append("types")
        program.session.record_result("types", "valid types")
        return PassResult(data="valid types")

    analysis.run = analyze
    consumer = Consumer(events)

    def consume(compiler, program):
        events.append("consumer")
        assert program.session.get_result("types") == "valid types"
        return PassResult()

    consumer.run = consume
    for pass_object in (analysis, rewrite, consumer):
        manager.register_pass(pass_object)
    manager.run_passes(None, Program(), ["types", "rewrite", "consumer"])
    assert events == ["types", "rewrite", "consumer"]


def test_refresh_does_not_replay_ordering_transform():
    events = []
    manager = PassManager(enable_caching=False)
    setup = Rewrite(events)
    setup.name = setup.info.name = "setup"
    setup.run = lambda *_: events.append("setup") or PassResult(changed=True)
    analysis = TypeAnalysis(events)
    analysis.info.dependencies.add("setup")
    for pass_object in (setup, analysis, Rewrite(events), Consumer(events)):
        manager.register_pass(pass_object)
    result = manager.run_passes(None, Program(), ["types", "rewrite", "consumer"])
    assert events == ["setup", "types", "rewrite", "types", "consumer"]
    assert result["consumer"].success


@pytest.mark.parametrize("retire", ["ir", "catalog", "solver", "facts"])
def test_external_invalidation_is_detected_before_consumer(retire):
    from pyflow.ir.core import FactResult, IRCatalog

    events = []
    program = Program()
    manager = PassManager(enable_caching=False)
    analysis, consumer = TypeAnalysis(events), Consumer(events)

    def invalidate(compiler, current):
        events.append("external")
        if retire == "ir":
            current.ir.commit_revision()
        elif retire == "catalog":
            current.ir = IRCatalog()
        elif retire == "solver":
            current.session.invalidate_results({"types"})
        else:
            current.ir.facts.invalidate({"types"})
        return PassResult()

    class External(UtilityPass):
        def run(self, compiler, current):
            return invalidate(compiler, current)

    external = External("external")
    for pass_object in (analysis, external, consumer):
        manager.register_pass(pass_object)
    program.ir.facts.publish("types", "types", {"key": FactResult.exact({1}, "types")})
    result = manager.run_passes(None, program, ["types", "external", "consumer"])
    assert events == ["types", "external", "types", "consumer"]
    assert result["consumer"].success


def test_fact_publication_does_not_retire_other_analysis():
    from pyflow.ir.core import FactResult

    events = []
    manager = PassManager(enable_caching=False)
    publisher = TypeAnalysis(events)
    publisher.name = publisher.info.name = "publisher"

    def publish(compiler, program):
        events.append("publisher")
        program.ir.facts.publish("other", "publisher", {"key": FactResult.exact({1}, "publisher")})
        return PassResult()

    publisher.run = publish
    for pass_object in (TypeAnalysis(events), publisher, Consumer(events)):
        manager.register_pass(pass_object)
    result = manager.run_passes(None, Program(), ["types", "publisher", "consumer"])
    assert events == ["types", "publisher", "consumer"]
    assert result["consumer"].success


def test_unstable_requirements_fail_without_running_consumer():
    events = []
    manager = PassManager(enable_caching=False, max_analysis_refreshes=2)
    first, second = TypeAnalysis(events), TypeAnalysis(events)
    second.name = second.info.name = "other"

    def invalidate_other(name, other):
        def run(compiler, program):
            events.append(name)
            program.session.invalidate_results({other})
            program.session.record_result(name, name)
            return PassResult()

        return run

    first.run = invalidate_other("types", "other")
    second.run = invalidate_other("other", "types")
    consumer = Consumer(events)
    consumer.info.requirements.add("other")
    for pass_object in (first, second, consumer):
        manager.register_pass(pass_object)
    result = manager.run_passes(None, Program(), ["consumer"])
    assert "consumer" not in events
    assert not result["consumer"].success
    assert "did not stabilize" in result["consumer"].error
    assert len(result.records) <= 8


@pytest.mark.parametrize("caching", [False, True])
def test_consecutive_invocations_are_recorded_without_overwriting_history(caching):
    events = []
    manager = PassManager(enable_caching=caching)
    analysis = TypeAnalysis(events)
    manager.register_pass(analysis)
    program = Program()
    result = manager.run_passes(None, program, ["types", "types"])
    assert [record.pass_name for record in result.records] == ["types", "types"]
    assert [record.sequence for record in result.records] == [1, 2]
    assert [record.cached for record in result.records] == [False, caching]
    assert analysis.calls == (1 if caching else 2)
    assert result["types"] is result.records[-1].result
    assert len(result) == 1
    assert result.total_time == sum(record.time for record in result.records)
    if caching:
        assert result.records[1].time == 0
        assert result.total_time == result.records[0].time
    second_run = manager.run_passes(None, program, ["types"])
    assert second_run.records[0].run_id != result.records[0].run_id
    assert second_run.records[0].sequence == 1


def test_automatic_refresh_records_include_provenance_and_revisions():
    events = []
    manager = PassManager(enable_caching=False)
    for pass_object in (TypeAnalysis(events), Rewrite(events), Consumer(events)):
        manager.register_pass(pass_object)
    result = manager.run_passes(None, Program(), ["types", "rewrite", "consumer"])
    first, rewrite, refresh, consumer = result.records
    assert [record.sequence for record in result.records] == [1, 2, 3, 4]
    assert rewrite.revision_before != rewrite.revision_after
    assert first.result.data == rewrite.revision_before
    assert refresh.result.data == rewrite.revision_after
    assert refresh.automatic
    assert refresh.requested_by == "consumer"
    assert not consumer.automatic
    assert result["types"] is refresh.result


def test_pipeline_summary_counts_cached_invocations(monkeypatch):
    from types import SimpleNamespace
    from pyflow.application.pipeline import Pipeline

    events, output = [], []
    program = Program()
    program.session.pass_manager.register_pass(TypeAnalysis(events))
    pipeline = Pipeline()
    monkeypatch.setattr(pipeline, "default_pass_names", lambda **_: ["types", "types"])
    compiler = SimpleNamespace(console=SimpleNamespace(output=output.append))
    result = pipeline.run(program, compiler=compiler)
    assert len(result) == 1
    assert len(result.records) == 2
    assert "2/2 passes successful" in output[-1]
    assert result.total_time == result.records[0].time


@pytest.mark.parametrize("caching", [False, True])
def test_recomputing_an_input_retires_derived_analysis_at_same_ir_revision(caching):
    events = []
    manager = PassManager(enable_caching=caching)
    analysis = TypeAnalysis(events)

    def compute(compiler, program):
        analysis.calls += 1
        events.append("types")
        program.session.record_result("types", analysis.calls)
        return PassResult(data=analysis.calls)

    analysis.run = compute

    class Derived(AnalysisPass):
        def run(self, compiler, program):
            events.append("derived")
            value = program.session.get_result("types")
            program.session.record_result("derived", value)
            return PassResult(data=value)

    derived = Derived("derived")
    derived.info.requirements.add("types")

    class RetireInput(UtilityPass):
        def run(self, compiler, program):
            if manager.cache:
                manager.cache.invalidate(program, "types")
            return PassResult()

    class ReadDerived(UtilityPass):
        def run(self, compiler, program):
            events.append("read")
            assert program.session.get_result("derived") == program.session.get_result("types")
            return PassResult()

    reader = ReadDerived("read")
    reader.info.requirements.add("derived")
    for pass_object in (analysis, derived, RetireInput("retire"), reader):
        manager.register_pass(pass_object)
    program = Program()
    revision = program.ir.revision
    result = manager.run_passes(None, program, ["derived", "retire", "types", "read"])
    assert result["read"].success
    assert events == ["types", "derived", "types", "derived", "read"]
    assert program.ir.revision == revision
