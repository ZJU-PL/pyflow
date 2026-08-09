import pytest

from pyflow.concolic.interpreter.model_registry import SummaryModelRegistry
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
