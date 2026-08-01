"""Tests for the framework-aware rule pack registry."""

from __future__ import annotations

import pytest

from pyflow.analysis.entrypoints import EntryPointMode, EntryPointOptions
from pyflow.analysis.ifds.modeling.registry import (
    Registry,
    load_registry,
    validate_rule_pack_data,
)


class TestRegistryLoading:
    def test_load_registry_returns_registry(self):
        r = load_registry()
        assert isinstance(r, Registry)

    def test_activate_by_name(self):
        r = Registry()
        r.activate("flask")
        assert "flask" in r.detected_frameworks

    def test_activate_unknown_fails_closed(self):
        r = Registry()
        with pytest.raises(ValueError, match="nonexistent_framework_xyz"):
            r.activate("nonexistent_framework_xyz")

    def test_activate_all(self):
        r = Registry()
        r.activate_all()
        assert len(r.detected_frameworks) >= 2

    def test_active_models_after_activate(self):
        r = Registry()
        r.activate("flask")
        models = r.active_models()
        mapping = models.as_mapping()
        assert "flask.request.args" in mapping
        m = mapping["flask.request.args"]
        assert m.source_kinds == frozenset({"user_input"})

    def test_active_models_merges_multiple(self):
        r = Registry()
        r.activate("flask", "stdlib")
        models = r.active_models()
        mapping = models.as_mapping()
        assert "flask.request.args" in mapping
        assert "open" in mapping
        assert "eval" in mapping

    def test_typestate_actions(self):
        r = Registry()
        r.activate("stdlib")
        mapping = r.active_models().as_mapping()
        # Now all typestate configs use namespaced typestate_protocol+typestate_action
        assert mapping["open"].typestate_actions == frozenset({"file.open"})
        assert mapping["close"].typestate_actions == frozenset({"close"})
        assert mapping["read"].typestate_actions == frozenset({"file.use"})

    def test_explicit_typestate_protocol_actions(self):
        r = Registry()
        r.activate("network")
        mapping = r.active_models().as_mapping()
        model = mapping["socket.socket"]
        assert "socket.open" in model.typestate_actions
        assert ("socket.open", "socket") in model.typestate_action_protocols
        assert model.module_prefixes == frozenset({"socket"})
        send_model = mapping["send"]
        assert ("socket.use", "socket") in send_model.typestate_action_protocols
        assert "socket.socket" in send_model.receiver_types

    def test_nullness_models(self):
        r = Registry()
        r.activate("stdlib")
        mapping = r.active_models().as_mapping()
        assert mapping["re.match"].nullness_nullable_return is True
        assert mapping["get"].nullness_nullable_return is True

    def test_rich_rules_compile_to_call_models(self):
        r = Registry()
        r.activate("stdlib")
        mapping = r.active_models().as_mapping()
        model = mapping["subprocess.run"]
        assert model.sink_kinds == frozenset({"rce"})
        assert model.sink_arg_positions == frozenset({0})

    def test_sql_cursor_reads_are_database_sources(self):
        r = Registry()
        r.activate("sql")
        models = r.active_models()

        fetchone = models.model_for_name("cursor.fetchone")
        fetchall = models.model_for_name("c.fetchall")

        assert fetchone is not None
        assert fetchone.source_kinds == frozenset({"database"})
        assert fetchall is not None
        assert fetchall.source_kinds == frozenset({"database"})

    def test_template_rendering_models_all_context_arguments_as_sinks(self):
        r = Registry()
        r.activate("flask")

        model = r.active_models().model_for_name("render_template_string")

        assert model is not None
        assert model.sink_kinds == frozenset({"xss"})
        assert model.sink_all_arguments is True
        assert model.cwe == "CWE-79"

    @pytest.mark.parametrize(
        ("framework", "source", "sink"),
        [
            ("bottle", "bottle.request.forms.get", "template"),
            ("pyramid", "pyramid.request.Request.params.get", "Response"),
            ("sanic", "sanic.request.Request.args.get", "html"),
        ],
    )
    def test_web_framework_packs_expose_input_and_html_models(
        self, framework, source, sink
    ):
        r = Registry()
        r.activate(framework)
        models = r.active_models().as_mapping()

        assert models[source].source_kinds == frozenset({"user_input"})
        assert models[sink].sink_kinds == frozenset({"xss"})
        assert models[sink].cwe == "CWE-79"

    def test_active_rule_metadata(self):
        r = Registry()
        r.activate("fastapi")
        rules = {rule.rule_id: rule for rule in r.active_taint_rules()}
        assert rules["PYFLOW-FASTAPI-SSRF"].sink_kinds == frozenset({"ssrf"})
        assert "user_input" in rules["PYFLOW-FASTAPI-SSRF"].source_kinds

    def test_web_pack_exposes_shared_entrypoint_defaults(self):
        registry = Registry()
        registry.activate("flask", type="taint")

        defaults = registry.as_taint_policy().entry_point_defaults
        resolved = defaults.resolve(
            EntryPointOptions(mode=EntryPointMode.ALL_PROCEDURES)
        )

        assert resolved.mode is EntryPointMode.ALL_PROCEDURES
        assert resolved.taint_parameters is True


class TestStrictV2Validation:
    def test_entrypoint_defaults_are_validated(self):
        valid = validate_rule_pack_data(
            {
                "schema_version": 2,
                "framework": "demo",
                "version": "2.0",
                "type": "taint",
                "entrypoints": {
                    "mode": "declared-plus-roots",
                    "taint_parameters": True,
                },
                "models": [],
                "rules": [],
            }
        )
        invalid = validate_rule_pack_data(
            {
                "schema_version": 2,
                "framework": "demo",
                "version": "2.0",
                "type": "taint",
                "entrypoints": {"mode": "guess", "taint_parameters": "yes"},
                "models": [],
                "rules": [],
            }
        )

        assert valid == ()
        assert any("supported entrypoint mode" in issue.message for issue in invalid)
        assert any("must be a boolean" in issue.message for issue in invalid)

    def test_unsupported_schema_version_is_rejected(self):
        issues = validate_rule_pack_data(
            {
                "schema_version": 3,
                "framework": "invalid-version",
                "version": "1.0",
                "type": "taint",
                "models": [],
                "rules": [],
            }
        )
        assert any("must equal 2" in issue.message for issue in issues)

    def test_unknown_model_fields_are_rejected(self):
        issues = validate_rule_pack_data(
            {
                "schema_version": 2,
                "framework": "invalid-fields",
                "version": "2.0",
                "type": "taint",
                "models": [{"call": "source", "taint_source": True}],
                "rules": [],
            }
        )
        assert any("not valid in schema v2" in issue.message for issue in issues)

    def test_sink_kind_requires_flow_rule(self):
        issues = validate_rule_pack_data(
            {
                "schema_version": 2,
                "framework": "broken",
                "version": "2.0",
                "type": "taint",
                "models": [
                    {
                        "call": "sink",
                        "sinks": [{"kind": "sql", "port": {"parameter": 0}}],
                    }
                ],
                "rules": [],
            }
        )
        assert any("sink kind 'sql' has no" in issue.message for issue in issues)

    def test_unknown_endpoint_field_is_rejected(self):
        issues = validate_rule_pack_data(
            {
                "schema_version": 2,
                "framework": "broken",
                "version": "2.0",
                "type": "taint",
                "models": [
                    {
                        "call": "source",
                        "sources": [
                            {"kind": "user_input", "port": "return", "extra": True}
                        ],
                    }
                ],
                "rules": [],
            }
        )
        assert any("unknown endpoint field" in issue.message for issue in issues)

    def test_analysis_specific_model_fields_are_enforced(self):
        issues = validate_rule_pack_data(
            {
                "schema_version": 2,
                "framework": "broken",
                "version": "2.0",
                "type": "nullness",
                "models": [
                    {
                        "call": "source",
                        "sources": [{"kind": "user_input", "port": "return"}],
                    }
                ],
                "rules": [],
            }
        )
        assert any("unknown schema-v2 model field" in issue.message for issue in issues)

    def test_missing_custom_pack_fails_closed(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            Registry().load_custom(tmp_path / "missing.json")


class TestFrameworkDetection:
    def test_flask_detection(self):
        r = Registry()
        detected = r.detect(["from flask import Flask, request"])
        assert "flask" in detected

    def test_django_detection(self):
        r = Registry()
        detected = r.detect(["from django.http import HttpResponse"])
        assert "django" in detected

    def test_fastapi_detection(self):
        r = Registry()
        detected = r.detect(["from fastapi import FastAPI"])
        assert "fastapi" in detected

    def test_stdlib_detection(self):
        r = Registry()
        detected = r.detect(["open('file.txt')"])
        assert "stdlib" in detected

    def test_no_false_positive(self):
        r = Registry()
        detected = r.detect(["x = 1 + 2"])
        assert len(detected) == 0

    def test_multiple_frameworks(self):
        r = Registry()
        detected = r.detect(
            [
                "from flask import Flask",
                "open('config.json')",
                "import requests",
            ]
        )
        assert "flask" in detected
        assert "stdlib" in detected
        assert "requests" in detected

    def test_detection_is_idempotent(self):
        r = Registry()
        r.detect(["from flask import Flask"])
        r.detect(["from flask import Flask, request"])
        assert r.detected_frameworks == frozenset({"flask"})


class TestTaintConfiguration:
    def test_as_config_basic(self):
        r = Registry()
        r.activate("flask")
        tc = r.as_config()
        mapping = tc.call_models.as_mapping()
        assert mapping["flask.request.args"].source_kinds == frozenset({"user_input"})
        assert "xss" in mapping["flask.render_template_string"].sink_kinds
        assert mapping["flask.escape"].sanitizer_kinds == frozenset({"*"})
        assert tc.rules

    def test_as_config_preserves_typed_sanitizers(self):
        r = Registry()
        r.activate("stdlib")
        tc = r.as_config()
        mapping = tc.call_models.as_mapping()
        assert mapping["html.escape"].sanitizer_kinds == frozenset({"user_input"})
        assert mapping["os.path.basename"].sanitizer_kinds == frozenset(
            {"file", "user_input"}
        )


class TestNullnessPack:
    def test_nullness_pack_from_subdir(self):
        """The nullness pack lives under config/nullness/ and must be discoverable."""
        r = Registry()
        r.activate("stdlib")
        assert "stdlib" in r.detected_frameworks
        mapping = r.active_models().as_mapping()
        assert mapping["re.match"].nullness_nullable_return is True
        assert mapping["json.loads"].nullness_nullable_return is True
        assert mapping["pickle.loads"].nullness_nullable_return is True
        assert mapping["next"].nullness_nullable_return is True
        assert mapping["get"].nullness_nullable_return is True
        assert mapping["fetchone"].nullness_nullable_return is True
        assert mapping["first"].nullness_nullable_return is True

    def test_nullness_pack_auto_activated_with_stdlib(self):
        """Nullness models should be merged when stdlib is active."""
        r = Registry()
        r.activate("stdlib")
        mapping = r.active_models().as_mapping()
        assert mapping["re.match"].nullness_nullable_return is True
        assert mapping["first"].nullness_nullable_return is True
        # stdlib taint models should still be present
        assert mapping["eval"].sink_kinds
        assert mapping["open"].source_kinds


class TestTypeStatePresets:
    def test_file_typestate(self):
        r = Registry()
        r.activate("stdlib")
        mapping = r.active_models().as_mapping()
        # open/read/write use "file" protocol → namespaced actions
        assert mapping["open"].typestate_actions == frozenset({"file.open"})
        assert mapping["read"].typestate_actions == frozenset({"file.use"})
        assert mapping["write"].typestate_actions == frozenset({"file.use"})
        # close uses generic "resource" protocol → bare action
        assert mapping["close"].typestate_actions == frozenset({"close"})

    def test_subprocess_typestate(self):
        r = Registry()
        r.activate("stdlib")
        mapping = r.active_models().as_mapping()
        sp = mapping.get("subprocess.Popen")
        assert sp is not None
        assert sp.sink_kinds
        assert "open" in sp.typestate_actions
