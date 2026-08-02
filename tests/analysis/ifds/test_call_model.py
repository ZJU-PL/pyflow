from __future__ import annotations

import pytest

from pyflow.analysis.ifds.modeling.calls import (
    STATE_CLOSE,
    STATE_OPEN,
    STATE_USE,
    CallModel,
    CallModelRegistry,
    TaintModelPort,
    TaintPropagation,
    TaintSanitizerContract,
)


def test_call_model_default_values():
    model = CallModel(name="read")
    assert model.name == "read"
    assert model.source_kinds == frozenset()
    assert model.sink_kinds == frozenset()
    assert model.sanitizer_kinds == frozenset()
    assert model.taint_propagations == frozenset()
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
    a = CallModel(name="f", source_kinds=frozenset({"user_input"}))
    b = CallModel(name="f", sink_kinds=frozenset({"sql"}))
    merged = a.merged(b)
    assert merged.name == "f"
    assert merged.source_kinds == frozenset({"user_input"})
    assert merged.sink_kinds == frozenset({"sql"})


def test_call_model_merges_taint_propagations():
    argument_to_return = TaintPropagation(
        TaintModelPort("parameter", 0), TaintModelPort("return")
    )
    receiver_to_return = TaintPropagation(
        TaintModelPort("receiver"), TaintModelPort("return")
    )
    a = CallModel(name="f", taint_propagations=frozenset({argument_to_return}))
    b = CallModel(name="f", taint_propagations=frozenset({receiver_to_return}))

    merged = a.merged(b)

    assert merged.taint_propagations == frozenset(
        {argument_to_return, receiver_to_return}
    )


def test_taint_propagation_rejects_invalid_port_directions():
    with pytest.raises(ValueError, match="propagation sources"):
        TaintPropagation(TaintModelPort("return"), TaintModelPort("receiver"))
    with pytest.raises(ValueError, match="propagation targets"):
        TaintPropagation(TaintModelPort("receiver"), TaintModelPort("all"))


def test_taint_propagation_supports_paths_mutation_and_kind_mapping():
    propagation = TaintPropagation(
        TaintModelPort("parameter", 0, ("payload",)),
        TaintModelPort("parameter", 1, ("copy",)),
        mapped_kinds=(("user_input", "validated_input"),),
    )

    assert propagation.transform_kind("user_input") == frozenset(
        {"validated_input"}
    )
    assert propagation.target.path == ("copy",)


def test_conditional_sanitizer_contract_joins_both_kind_outcomes():
    contract = TaintSanitizerContract(
        input=TaintModelPort("parameter", 0),
        output=TaintModelPort("return"),
        mapped_kinds=(("html", "html_safe"),),
        guard="strict_mode",
    )

    assert contract.transform_kind("html") == frozenset({"html", "html_safe"})


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
    with pytest.raises(
        ValueError, match="Cannot merge call models with different names"
    ):
        a.merged(b)


def test_call_model_merged_is_idempotent():
    model = CallModel(name="idem", source_kinds=frozenset({"user_input"}))
    merged = model.merged(model)
    assert merged == model


def test_call_model_merged_combined_taint_sanitizer():
    a = CallModel(name="san", sanitizer_kinds=frozenset({"user_input"}))
    b = CallModel(name="san", nullness_nullable_return=True)
    merged = a.merged(b)
    assert merged.sanitizer_kinds == frozenset({"user_input"})
    assert merged.nullness_nullable_return is True


def test_registry_empty():
    registry = CallModelRegistry()
    assert registry.model_for_name("anything") is None


def test_registry_single_model_lookup():
    model = CallModel(name="source", source_kinds=frozenset({"user_input"}))
    registry = CallModelRegistry([model])
    found = registry.model_for_name("source")
    assert found is not None
    assert found.source_kinds == frozenset({"user_input"})


def test_registry_duplicate_names_merge():
    registry = CallModelRegistry(
        [
            CallModel(name="multi", source_kinds=frozenset({"user_input"})),
            CallModel(name="multi", sink_kinds=frozenset({"sql"})),
        ]
    )
    found = registry.model_for_name("multi")
    assert found is not None
    assert found.source_kinds == frozenset({"user_input"})
    assert found.sink_kinds == frozenset({"sql"})


def test_registry_model_for_name_none():
    registry = CallModelRegistry([CallModel(name="x")])
    assert registry.model_for_name(None) is None


def test_registry_model_for_name_missing():
    registry = CallModelRegistry([CallModel(name="present")])
    assert registry.model_for_name("absent") is None


def test_registry_resolves_unambiguous_import_alias_suffix():
    model = CallModel(
        name="flask.request.args.get",
        source_kinds=frozenset({"user_input"}),
    )
    registry = CallModelRegistry([model])

    assert registry.model_for_name("request.args.get") == model


def test_registry_does_not_guess_ambiguous_leaf_aliases():
    registry = CallModelRegistry(
        [
            CallModel(name="pickle.loads", source_kinds=frozenset({"pickle"})),
            CallModel(name="json.loads", source_kinds=frozenset({"json"})),
        ]
    )

    assert registry.model_for_name("loads") is None


def test_registry_does_not_merge_ambiguous_equivalent_leaf_models():
    registry = CallModelRegistry(
        [
            CallModel(name="module_a.open", sink_kinds=frozenset({"file"})),
            CallModel(name="module_b.open", sink_kinds=frozenset({"file"})),
        ]
    )

    assert registry.model_for_name("open") is None


def test_registry_does_not_reinterpret_known_namespace_attribute_by_leaf():
    registry = CallModelRegistry(
        [
            CallModel(name="os.getenv", source_kinds=frozenset({"env"})),
            CallModel(
                name="framework.Request.path",
                source_kinds=frozenset({"user_input"}),
            ),
        ]
    )

    assert registry.model_for_name("os.path") is None


def test_registry_keeps_leaf_fallback_for_instance_receivers():
    registry = CallModelRegistry(
        [
            CallModel(name="self.write", sink_kinds=frozenset({"xss"})),
            CallModel(
                name="framework.Request.get_argument",
                source_kinds=frozenset({"user_input"}),
            ),
        ]
    )

    model = registry.model_for_name("self.get_argument")

    assert model is not None
    assert model.source_kinds == frozenset({"user_input"})


def test_registry_resolves_ambiguous_suffix_when_models_are_semantically_equal():
    registry = CallModelRegistry(
        [
            CallModel(
                name="driver_a.cursor.execute",
                sink_kinds=frozenset({"sql"}),
                cwe="CWE-89",
            ),
            CallModel(
                name="driver_b.cursor.execute",
                sink_kinds=frozenset({"sql"}),
                sink_arg_positions=frozenset({1}),
                cwe="CWE-89",
            ),
        ]
    )

    model = registry.model_for_name("cursor.execute")

    assert model is not None
    assert model.sink_kinds == frozenset({"sql"})
    assert model.sink_arg_positions == frozenset({0, 1})
    assert model.cwe == "CWE-89"


def test_registry_resolves_local_receiver_when_method_models_are_compatible():
    registry = CallModelRegistry(
        [
            CallModel(
                name="driver_a.Cursor.execute",
                sink_kinds=frozenset({"sql"}),
                cwe="CWE-89",
            ),
            CallModel(
                name="driver_b.Connection.execute",
                sink_kinds=frozenset({"sql"}),
                cwe="CWE-89",
            ),
        ]
    )

    model = registry.model_for_name("c.execute")

    assert model is not None
    assert model.sink_kinds == frozenset({"sql"})
    assert model.cwe == "CWE-89"


def test_registry_rejects_local_receiver_for_incompatible_method_models():
    registry = CallModelRegistry(
        [
            CallModel(name="db.Cursor.run", sink_kinds=frozenset({"sql"})),
            CallModel(name="shell.Process.run", sink_kinds=frozenset({"command"})),
        ]
    )

    assert registry.model_for_name("obj.run") is None


def test_registry_as_mapping():
    registry = CallModelRegistry(
        [
            CallModel(name="a", source_kinds=frozenset({"user_input"})),
            CallModel(name="b", sink_kinds=frozenset({"sql"})),
        ]
    )
    mapping = registry.as_mapping()
    assert mapping == {
        "a": CallModel(name="a", source_kinds=frozenset({"user_input"})),
        "b": CallModel(name="b", sink_kinds=frozenset({"sql"})),
    }


def test_taint_registry_requires_explicit_typed_models():
    registry = CallModelRegistry(
        [
            CallModel("input", source_kinds=frozenset({"user_input"})),
            CallModel("exec", sink_kinds=frozenset({"rce"})),
            CallModel("escape", sanitizer_kinds=frozenset({"user_input"})),
        ]
    )
    assert registry.model_for_name("input").source_kinds == frozenset({"user_input"})
    assert registry.model_for_name("exec").sink_kinds == frozenset({"rce"})
    assert registry.model_for_name("escape").sanitizer_kinds == frozenset(
        {"user_input"}
    )


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
    r1 = CallModelRegistry(
        [CallModel(name="f", source_kinds=frozenset({"user_input"}))]
    )
    r2 = CallModelRegistry([CallModel(name="f", sink_kinds=frozenset({"sql"}))])
    r3 = CallModelRegistry([CallModel(name="g", nullness_nullable_return=True)])

    merged = r1.merged(r2, r3)
    assert merged.model_for_name("f").source_kinds == frozenset({"user_input"})
    assert merged.model_for_name("f").sink_kinds == frozenset({"sql"})
    assert merged.model_for_name("g").nullness_nullable_return is True
    assert merged.model_for_name("absent") is None


def test_registry_merged_preserves_original():
    r1 = CallModelRegistry(
        [CallModel(name="f", source_kinds=frozenset({"user_input"}))]
    )
    r2 = CallModelRegistry([CallModel(name="g", sink_kinds=frozenset({"sql"}))])

    merged = r1.merged(r2)
    assert r1.model_for_name("g") is None
    assert r2.model_for_name("f") is None
    assert merged.model_for_name("f") is not None
    assert merged.model_for_name("g") is not None
