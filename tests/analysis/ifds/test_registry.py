"""Tests for the framework-aware rule pack registry."""

from __future__ import annotations

import json

import pytest

from pyflow.analysis.entrypoints import EntryPointMode, EntryPointOptions
from pyflow.analysis.ifds.modeling.registry import (
    Registry,
    load_registry,
    validate_rule_pack_data,
)
from pyflow.analysis.ifds.modeling.registry.loader import _discover_pack_paths


class TestRegistryLoading:
    def test_discovery_ignores_unrelated_config_json(self, tmp_path):
        for family in ("taint", "typestate", "nullness"):
            directory = tmp_path / family
            directory.mkdir()
            (directory / f"{family}.json").write_text("{}", encoding="utf-8")
        unrelated = tmp_path / "capability"
        unrelated.mkdir()
        (unrelated / "stdlib.json").write_text("{}", encoding="utf-8")

        discovered = _discover_pack_paths(tmp_path)

        assert {path.parent.name for path in discovered} == {
            "taint",
            "typestate",
            "nullness",
        }

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

    def test_stdlib_command_and_archive_models(self):
        registry = Registry()
        registry.activate("stdlib", type="taint")
        models = registry.active_models(type="taint")

        for name in ("subprocess.getoutput", "subprocess.getstatusoutput"):
            model = models.model_for_name(name)
            assert model is not None
            assert model.sink_kinds == frozenset({"rce"})
            assert model.sink_arg_positions == frozenset({0})
            assert model.cwe == "CWE-78"

        for name in ("tarfile.TarFile.getnames", "zipfile.ZipFile.namelist"):
            model = models.model_for_name(name)
            assert model is not None
            assert model.source_kinds == frozenset({"file"})
            assert model.cwe == "CWE-22"

        for name in (
            "tarfile.TarFile.extract",
            "tarfile.TarFile.extractall",
            "zipfile.ZipFile.extract",
            "zipfile.ZipFile.extractall",
        ):
            model = models.model_for_name(name)
            assert model is not None
            assert model.sink_kinds == frozenset({"file"})
            assert model.sink_arg_positions == frozenset({0, 1})
            assert model.cwe == "CWE-22"

        tar_open = models.model_for_name("tarfile.open")
        assert tar_open is not None
        assert tar_open.taint_propagations
        assert models.model_for_name("tarfile.TarFile.extractall").sink_receiver
        assert models.model_for_name("zipfile.ZipFile.extractall").sink_receiver

    def test_django_storage_validation_and_backend_sink_models(self):
        registry = Registry()
        registry.activate("django", type="taint")
        models = registry.active_models(type="taint")

        backend_save = models.model_for_name("self._save")
        validator = models.model_for_name("validate_file_name")

        assert backend_save is not None
        assert backend_save.cwe == "CWE-22"
        assert backend_save.sink_arg_positions == frozenset({0})
        assert validator is not None
        assert any(contract.mutates_input for contract in validator.sanitizer_contracts)

    def test_twisted_request_and_error_page_models(self):
        registry = Registry()
        detected = registry.detect(
            ["from twisted.web import resource", "request.getHeader(b'host')"],
            type="taint",
        )
        models = registry.active_models(type="taint")

        assert "twisted" in detected
        assert models.model_for_name("request.getHeader").source_kinds == frozenset(
            {"user_input"}
        )
        no_resource = models.model_for_name("resource.NoResource")
        assert no_resource is not None
        assert no_resource.cwe == "CWE-79"
        assert no_resource.sink_arg_positions == frozenset({0})

    def test_cloudpickle_deserialization_models(self):
        registry = Registry()
        detected = registry.detect(["import cloudpickle"], type="taint")
        model = registry.active_models(type="taint").model_for_name(
            "cloudpickle.load"
        )

        assert "serialization" in detected
        assert model is not None
        assert model.cwe == "CWE-502"
        assert model.sink_kinds == frozenset({"execdeserializationsink"})

    def test_archery_database_engine_models(self):
        registry = Registry()
        detected = registry.detect(
            ["from sql.engines import get_engine", "get_engine(instance=instance)"],
            type="taint",
        )
        models = registry.active_models(type="taint")

        assert "archery" in detected
        query = models.model_for_name("query_engine.query")
        assert query is not None
        assert query.cwe == "CWE-89"
        assert query.sink_arg_positions == frozenset({0, 1})

        metadata = models.model_for_name("query_engine.get_group_tables_by_db")
        assert metadata is not None
        assert metadata.cwe == "CWE-89"
        assert metadata.sink_arg_positions == frozenset({0})

        sanitizer = models.model_for_name("query_engine.escape_string")
        assert sanitizer is not None
        assert sanitizer.sanitizer_kinds == frozenset({"*"})

    def test_odoo_template_context_shape_models(self):
        registry = Registry()
        detected = registry.detect(
            [
                "from odoo.http import request",
                "values = request.params.copy()",
                "request.render('web.login', values)",
            ],
            type="taint",
        )
        models = registry.active_models(type="taint")

        assert "odoo" in detected
        assert (
            registry.as_taint_policy().entry_point_defaults.taint_parameters
            is False
        )
        source = models.model_for_name("request.params.copy")
        assert source is not None
        assert source.source_kinds == frozenset({"template_context_shape"})

        sink = models.model_for_name("request.render")
        assert sink is not None
        assert sink.cwe == "CWE-79"
        assert sink.sink_kinds == frozenset({"template_context_shape"})
        assert sink.sink_arg_positions == frozenset({1})

    def test_stdlib_value_transforms_preserve_taint(self):
        registry = Registry()
        registry.activate("stdlib", type="taint")
        models = registry.active_models(type="taint")

        for name in (
            "json.dumps",
            "repr",
            "str",
            "str.lower",
            "str.replace",
            "str.rsplit",
            "re.search",
            "re.Match.group",
            "io.BytesIO",
        ):
            model = models.model_for_name(name)
            assert model is not None
            assert model.taint_propagations
            assert not model.sanitizer_kinds
            assert not model.sanitizer_contracts

    def test_taint_model_accepts_declarative_return_sink(self, tmp_path):
        pack = tmp_path / "return-sink.json"
        pack.write_text(
            json.dumps(
                {
                    "schema_version": 2,
                    "framework": "return-sink",
                    "version": "1.0",
                    "type": "taint",
                    "models": [
                        {
                            "call": "render_payload",
                            "cwe": "CWE-79",
                            "sinks": [{"kind": "xss", "port": "return"}],
                        }
                    ],
                    "rules": [
                        {
                            "id": "RETURN-XSS",
                            "title": "Unsafe rendered return",
                            "sources": ["user_input"],
                            "sinks": ["xss"],
                            "severity": "high",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

        registry = Registry()
        registry.load_custom(pack)
        model = registry.active_models(type="taint").model_for_name(
            "render_payload"
        )

        assert model is not None
        assert model.sink_return is True
        assert model.sink_arg_positions == frozenset()

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

        autoescaped = r.active_models().model_for_name("render_template")
        assert autoescaped is None or not autoescaped.sink_kinds

    def test_compatible_qualified_sink_aliases_resolve_short_import_name(self):
        registry = Registry()
        registry.activate("flask")

        model = registry.active_models().model_for_name("send_file")

        assert model is not None
        assert model.sink_kinds == frozenset({"file"})
        assert model.cwe == "CWE-22"

    def test_framework_boundary_sinks_cover_common_import_spellings(self):
        registry = Registry()
        registry.activate("fastapi", "django", type="taint")
        models = registry.active_models(type="taint")

        file_response = models.model_for_name("FileResponse")
        assert file_response is not None
        assert file_response.cwe == "CWE-22"

        mark_safe = models.model_for_name("mark_safe")
        assert mark_safe is not None
        assert mark_safe.cwe == "CWE-79"

        injection_registry = Registry()
        injection_registry.activate("injection", type="taint")
        from_string = injection_registry.active_models(type="taint").model_for_name(
            "jinja2_env.from_string"
        )
        assert from_string is not None
        assert from_string.cwe == "CWE-94"
        assert from_string.sink_arg_positions == frozenset({0})

        dynamic_eval = injection_registry.active_models(type="taint").model_for_name(
            "eval"
        )
        assert dynamic_eval is not None
        assert dynamic_eval.cwe == "CWE-95"

    def test_stdlib_exposes_framework_filename_canonicalizer(self):
        registry = Registry()
        registry.activate("stdlib", type="taint")

        model = registry.active_models(type="taint").model_for_name(
            "secure_filename"
        )

        assert model is not None
        assert model.sanitizer_kinds == frozenset({"*"})

    def test_stdlib_exposes_call_propagation_models(self):
        registry = Registry()
        registry.activate("stdlib", type="taint")
        models = registry.active_models(type="taint")

        format_model = models.model_for_name("value.format")
        join_model = models.model_for_name("os.path.join")

        assert format_model is not None
        assert format_model.sink_receiver is True
        assert format_model.sink_arg_positions == frozenset()
        assert {
            (edge.source.kind, edge.source.parameter, edge.target.kind)
            for edge in format_model.taint_propagations
        } == {
            ("receiver", None, "return"),
            ("all", None, "return"),
        }
        assert join_model is not None
        assert {
            (edge.source.kind, edge.target.kind)
            for edge in join_model.taint_propagations
        } == {("all", "return")}

    def test_tortoise_models_like_criteria_and_wildcard_escaping(self):
        registry = Registry()
        registry.activate("tortoise", type="taint")
        models = registry.active_models(type="taint")

        method_sink = models.model_for_name("field.like")
        constructor_sink = models.model_for_name("Like")
        sanitizer = models.model_for_name("escape_like")

        assert method_sink is not None
        assert method_sink.sink_kinds == frozenset({"sql"})
        assert method_sink.sink_arg_positions == frozenset({0})
        assert method_sink.cwe == "CWE-89"
        assert constructor_sink is not None
        assert constructor_sink.sink_arg_positions == frozenset({1})
        assert constructor_sink.cwe == "CWE-89"
        assert sanitizer is not None
        assert sanitizer.sanitizer_kinds == frozenset({"*"})

        rules = {rule.rule_id: rule for rule in registry.active_taint_rules()}
        assert rules["PYFLOW-TORTOISE-SQL"].sink_kinds == frozenset({"sql"})

    def test_detects_tortoise_pack_from_pypika_import(self):
        registry = Registry()

        detected = registry.detect(
            ["from pypika import functions", "return field.like(value)"],
            type="taint",
        )

        assert "tortoise" in detected

    def test_tornado_models_attribute_user_source(self):
        registry = Registry()
        registry.activate("tornado", type="taint")
        models = registry.active_models(type="taint")

        current_user = models.model_for_name("self.current_user")

        assert current_user is not None
        assert current_user.source_kinds == frozenset({"user_input"})

    def test_flask_application_constructor_returns_clean_framework_state(self):
        registry = Registry()
        registry.activate("flask", type="taint")

        model = registry.active_models(type="taint").model_for_name("Flask")

        assert model is not None
        assert model.sanitizer_kinds == frozenset({"*"})

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
    def test_taint_propagations_are_validated(self):
        base = {
            "schema_version": 2,
            "framework": "propagation",
            "version": "2.0",
            "type": "taint",
            "rules": [],
        }
        valid = validate_rule_pack_data(
            {
                **base,
                "models": [
                    {
                        "call": "wrapper",
                        "propagations": [
                            {"from": {"parameter": 0}, "to": "return"},
                            {"from": "receiver", "to": "receiver"},
                        ],
                    }
                ],
            }
        )
        invalid = validate_rule_pack_data(
            {
                **base,
                "models": [
                    {
                        "call": "broken",
                        "propagations": [
                            {"from": "return", "to": "all"},
                            {"from": {"parameter": -1}, "to": "return"},
                        ],
                    }
                ],
            }
        )

        assert valid == ()
        assert any(
            "propagation sources" in issue.message or "must be 'all'" in issue.message
            for issue in invalid
        )
        assert any("must be 'return'" in issue.message for issue in invalid)

    def test_path_propagation_and_transforming_sanitizer_are_loaded(self, tmp_path):
        pack = tmp_path / "advanced.json"
        pack.write_text(
            """{
              "schema_version": 2,
              "framework": "advanced",
              "version": "1.0",
              "type": "taint",
              "models": [{
                "call": "framework.copy",
                "propagations": [{
                  "from": {"parameter": 0, "path": ["payload"]},
                  "to": {"parameter": 1, "path": ["copy"]},
                  "maps": {"user_input": "validated_input"}
                }],
                "sanitizers": [{
                  "kinds": ["unused"],
                  "from": {"parameter": 0},
                  "to": "return",
                  "maps": {"html": "html_safe"},
                  "guard": "strict_mode",
                  "assumptions": ["strict mode is enabled by deployment policy"]
                }]
              }],
              "rules": []
            }"""
        )
        registry = Registry()

        registry.load_custom(pack)
        model = registry.active_models(type="taint").model_for_name(
            "framework.copy"
        )

        assert model is not None
        propagation = next(iter(model.taint_propagations))
        assert propagation.source.path == ("payload",)
        assert propagation.target.parameter == 1
        contract = next(iter(model.sanitizer_contracts))
        assert contract.transform_kind("html") == frozenset({"html", "html_safe"})

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

    def test_call_model_aliases_are_validated(self):
        issues = validate_rule_pack_data(
            {
                "schema_version": 2,
                "framework": "invalid-aliases",
                "version": "2.0",
                "type": "taint",
                "models": [
                    {
                        "call": "qualified.source",
                        "aliases": ["", 42],
                        "sources": [
                            {"kind": "user_input", "port": "return"}
                        ],
                    }
                ],
                "rules": [],
            }
        )

        assert any("non-empty strings" in issue.message for issue in issues)

    def test_sink_behavior_is_validated_and_requires_a_sink(self):
        base = {
            "schema_version": 2,
            "framework": "invalid-sink-behavior",
            "version": "2.0",
            "type": "taint",
            "rules": [],
        }
        unsupported = validate_rule_pack_data(
            {
                **base,
                "models": [
                    {
                        "call": "render",
                        "sink_behavior": "unknown-behavior",
                        "sinks": [
                            {"kind": "xss", "port": {"parameter": 0}}
                        ],
                    }
                ],
            }
        )
        missing_sink = validate_rule_pack_data(
            {
                **base,
                "models": [
                    {
                        "call": "source",
                        "sink_behavior": "jinja-autoescape",
                        "sources": [
                            {"kind": "user_input", "port": "return"}
                        ],
                    }
                ],
            }
        )

        assert any("must be one of" in issue.message for issue in unsupported)
        assert any(
            "requires at least one sink" in issue.message for issue in missing_sink
        )

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
        assert (
            mapping["flask.render_template_string"].sink_behavior
            == "jinja-autoescape"
        )
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
