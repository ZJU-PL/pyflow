import pytest

from pyflow.concolic.interpreter.model_registry import (
    ModelPrecision,
    ModelResult,
    OpaqueCallSample,
    OpaqueCallSignature,
    OpaqueRefinementStore,
    SummaryModelRegistry,
)
from pyflow.concolic.interpreter.summaries import DEFAULT_MODEL_REGISTRY


def _handler(executor, module, name, args, keywords):
    return executor, module, name, args, keywords


def test_registry_prefers_exact_models_over_module_families():
    registry = SummaryModelRegistry()
    registry.register_module("sample", lambda *_: "module")
    registry.register_function("sample", "exact", lambda *_: "exact")

    assert registry.resolve("sample", "exact")(None, "sample", "exact", [], {}) == "exact"
    assert registry.resolve("sample", "other")(None, "sample", "other", [], {}) == "module"


def test_registry_rejects_duplicate_models():
    registry = SummaryModelRegistry()
    registry.register_function("sample", "value", _handler)

    with pytest.raises(ValueError, match="already registered"):
        registry.register_function("sample", "value", _handler)


def test_default_registry_catalogs_all_existing_model_families():
    modules = {model.module for model in DEFAULT_MODEL_REGISTRY.models()}

    assert modules >= {
        "asyncio",
        "collections",
        "datetime",
        "itertools",
        "math",
        "os.path",
        "urllib.parse",
    }


def test_model_results_and_opaque_refinements_preserve_provenance():
    result = ModelResult("value", ModelPrecision.REFINED, assumptions=("known",))
    signature = OpaqueCallSignature("math", "isclose", ("int", "int"), ())
    sample = OpaqueCallSample((0, 3), (), "bool", False)
    store = OpaqueRefinementStore()

    assert result.precision is ModelPrecision.REFINED
    assert store.record(signature, sample)
    assert not store.record(signature, sample)
    assert store.samples(signature) == (sample,)
    assert store.observations == 2
    assert store.refinements == 1

    blocked = OpaqueCallSample((1, 3), (), "bool", False)
    assert store.observe(signature, blocked, max_refinements=1) is None
    assert store.samples(signature) == (sample,)
    assert store.observations == 3
    assert store.refinements == 1
