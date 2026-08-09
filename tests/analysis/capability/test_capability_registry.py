import json

import pytest

from pyflow.analysis.capability import (
    CapabilityOperation,
    CapabilityRegistry,
    RuntimeCapabilityPolicy,
    RuntimeCapabilityGuard,
    CapabilityViolation,
    ExternalEffectKind,
    capability_for_audit_event,
    default_capability_registry,
)


def test_default_registry_covers_environment_calls_and_common_network_clients():
    registry = default_capability_registry()
    assert registry.match("os.getenv", CapabilityOperation.CALL)[0].capability == (
        "information.environment"
    )
    assert registry.match("requests.get", CapabilityOperation.CALL)[0].capability == "network.io"


def test_registry_loads_versioned_project_extension(tmp_path):
    model = tmp_path / "capabilities.json"
    model.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "patterns": [
                    {
                        "capability": "database.write",
                        "operation": "call",
                        "access_paths": ["acme.db.execute"],
                    }
                ],
                "effects": [
                    {
                        "kind": "invoke_callback",
                        "arguments": [0],
                        "access_paths": ["acme.hooks.register"],
                    }
                ],
            }
        )
    )
    registry = CapabilityRegistry.from_json(model)
    assert registry.match("acme.db.execute", CapabilityOperation.CALL)[0].category == "database"
    effect = registry.effects_for("acme.hooks.register")[0]
    assert effect.kind is ExternalEffectKind.INVOKE_CALLBACK
    assert effect.arguments == (0,)


def test_runtime_event_classification_distinguishes_open_modes():
    assert capability_for_audit_event("open", ("x", "r", 0)) == "file.read"
    assert capability_for_audit_event("open", ("x", "w", 0)) == "file.write"
    assert capability_for_audit_event("subprocess.Popen", ("id",)) == "process.execute"
    assert capability_for_audit_event("compile", (b"1 + 1", "<string>")) == "code.execute"


def test_runtime_guard_records_and_denies_known_events():
    policy = RuntimeCapabilityPolicy.allowing(["file.read"])
    guard = RuntimeCapabilityGuard(policy)
    guard("open", ("x", "r", 0))
    with pytest.raises(CapabilityViolation):
        guard("subprocess.Popen", ("id",))
    assert [event.capability for event in policy.events] == ["file.read", "process.execute"]
