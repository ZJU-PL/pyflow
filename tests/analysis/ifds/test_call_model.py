from __future__ import annotations

import pytest

from pyflow.analysis.ifds.modeling.calls import (
    STATE_CLOSE,
    STATE_OPEN,
    STATE_USE,
    CallModel,
    CallModelRegistry,
)


def test_call_model_default_values():
    model = CallModel(name="read")
    assert model.name == "read"
    assert model.taint_source is False
    assert model.taint_sink is False
    assert model.taint_sanitizer is False
    assert model.nullness_nullable_return is False
    assert model.typestate_actions == frozenset()
    assert model.resource_arg_positions == frozenset({0})
    assert model.track_method_receiver is True


def test_call_model_custom_values():
    model = CallModel(
        name="open",
        typestate_actions=frozenset({STATE_OPEN}),
        resource_arg_positions=frozenset({0, 1}),
        track_method_receiver=False,
    )
    assert model.typestate_actions == frozenset({STATE_OPEN})
    assert model.resource_arg_positions == frozenset({0, 1})
    assert model.track_method_receiver is False


def test_call_model_merged_taint_source():
    a = CallModel(name="f", taint_source=True)
    b = CallModel(name="f", taint_sink=True)
    merged = a.merged(b)
    assert merged.name == "f"
    assert merged.taint_source is True
    assert merged.taint_sink is True


def test_call_model_merged_nullness():
    a = CallModel(name="g")
    b = CallModel(name="g", nullness_nullable_return=True)
    merged = a.merged(b)
    assert merged.nullness_nullable_return is True


def test_call_model_merged_typestate_actions_union():
    a = CallModel(name="h", typestate_actions=frozenset({STATE_OPEN}))
    b = CallModel(name="h", typestate_actions=frozenset({STATE_CLOSE}))
    merged = a.merged(b)
    assert merged.typestate_actions == frozenset({STATE_OPEN, STATE_CLOSE})


def test_call_model_merged_resource_arg_positions_union():
    a = CallModel(name="m", resource_arg_positions=frozenset({0}))
    b = CallModel(name="m", resource_arg_positions=frozenset({1, 2}))
    merged = a.merged(b)
    assert merged.resource_arg_positions == frozenset({0, 1, 2})


def test_call_model_merged_track_method_receiver():
    a = CallModel(name="n", track_method_receiver=False)
    b = CallModel(name="n", track_method_receiver=True)
    merged = a.merged(b)
    assert merged.track_method_receiver is True


def test_call_model_merged_raises_on_name_mismatch():
    a = CallModel(name="x")
    b = CallModel(name="y")
    with pytest.raises(ValueError, match="Cannot merge call models with different names"):
        a.merged(b)


def test_call_model_merged_is_idempotent():
    model = CallModel(name="idem", taint_source=True)
    merged = model.merged(model)
    assert merged == model


def test_call_model_merged_combined_taint_sanitizer():
    a = CallModel(name="san", taint_sanitizer=True)
    b = CallModel(name="san", nullness_nullable_return=True)
    merged = a.merged(b)
    assert merged.taint_sanitizer is True
    assert merged.nullness_nullable_return is True


def test_registry_empty():
    registry = CallModelRegistry()
    assert registry.model_for_name("anything") is None


def test_registry_single_model_lookup():
    model = CallModel(name="source", taint_source=True)
    registry = CallModelRegistry([model])
    found = registry.model_for_name("source")
    assert found is not None
    assert found.taint_source is True


def test_registry_duplicate_names_merge():
    registry = CallModelRegistry([
        CallModel(name="multi", taint_source=True),
        CallModel(name="multi", taint_sink=True),
    ])
    found = registry.model_for_name("multi")
    assert found is not None
    assert found.taint_source is True
    assert found.taint_sink is True


def test_registry_model_for_name_none():
    registry = CallModelRegistry([CallModel(name="x")])
    assert registry.model_for_name(None) is None


def test_registry_model_for_name_missing():
    registry = CallModelRegistry([CallModel(name="present")])
    assert registry.model_for_name("absent") is None


def test_registry_as_mapping():
    registry = CallModelRegistry([
        CallModel(name="a", taint_source=True),
        CallModel(name="b", taint_sink=True),
    ])
    mapping = registry.as_mapping()
    assert mapping == {"a": CallModel(name="a", taint_source=True), "b": CallModel(name="b", taint_sink=True)}


def test_from_taint_configuration():
    from dataclasses import dataclass

    @dataclass(frozen=True)
    class FakeTaintConfig:
        source_names: frozenset[str] = frozenset({"input", "read"})
        sink_names: frozenset[str] = frozenset({"exec", "eval"})
        sanitizer_names: frozenset[str] = frozenset({"escape"})

    config = FakeTaintConfig()
    registry = CallModelRegistry.from_taint_configuration(config)

    source = registry.model_for_name("input")
    assert source is not None
    assert source.taint_source is True
    assert source.taint_sink is False

    sink = registry.model_for_name("exec")
    assert sink is not None
    assert sink.taint_sink is True
    assert sink.taint_source is False

    sanitizer = registry.model_for_name("escape")
    assert sanitizer is not None
    assert sanitizer.taint_sanitizer is True


def test_from_nullness_configuration():
    from dataclasses import dataclass

    @dataclass(frozen=True)
    class FakeNullnessConfig:
        nullable_return_names: frozenset[str] = frozenset({"get", "pop"})

    config = FakeNullnessConfig()
    registry = CallModelRegistry.from_nullness_configuration(config)

    assert registry.model_for_name("get").nullness_nullable_return is True
    assert registry.model_for_name("pop").nullness_nullable_return is True
    assert registry.model_for_name("unknown") is None


def test_from_typestate_configuration():
    from dataclasses import dataclass

    @dataclass(frozen=True)
    class FakeTypestateConfig:
        open_names: frozenset[str] = frozenset({"fopen"})
        close_names: frozenset[str] = frozenset({"fclose"})
        use_names: frozenset[str] = frozenset({"fread", "fwrite"})
        resource_arg_positions: frozenset[int] = frozenset({0})
        track_method_receiver: bool = True

    config = FakeTypestateConfig()
    registry = CallModelRegistry.from_typestate_configuration(config)

    opened = registry.model_for_name("fopen")
    assert opened is not None
    assert opened.typestate_actions == frozenset({STATE_OPEN})

    closed = registry.model_for_name("fclose")
    assert closed is not None
    assert closed.typestate_actions == frozenset({STATE_CLOSE})

    used = registry.model_for_name("fread")
    assert used is not None
    assert used.typestate_actions == frozenset({STATE_USE})


def test_registry_merged_combines_multiple_registries():
    r1 = CallModelRegistry([CallModel(name="f", taint_source=True)])
    r2 = CallModelRegistry([CallModel(name="f", taint_sink=True)])
    r3 = CallModelRegistry([CallModel(name="g", nullness_nullable_return=True)])

    merged = r1.merged(r2, r3)
    assert merged.model_for_name("f").taint_source is True
    assert merged.model_for_name("f").taint_sink is True
    assert merged.model_for_name("g").nullness_nullable_return is True
    assert merged.model_for_name("absent") is None


def test_registry_merged_preserves_original():
    r1 = CallModelRegistry([CallModel(name="f", taint_source=True)])
    r2 = CallModelRegistry([CallModel(name="g", taint_sink=True)])

    merged = r1.merged(r2)
    assert r1.model_for_name("g") is None
    assert r2.model_for_name("f") is None
    assert merged.model_for_name("f") is not None
    assert merged.model_for_name("g") is not None
