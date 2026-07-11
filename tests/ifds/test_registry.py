"""Tests for the framework-aware rule pack registry."""

from __future__ import annotations

from pyflow.analysis.ifds.clients.registry import Registry, load_registry


class TestRegistryLoading:
    def test_load_registry_returns_registry(self):
        r = load_registry()
        assert isinstance(r, Registry)

    def test_activate_by_name(self):
        r = Registry()
        r.activate("flask")
        assert "flask" in r.detected_frameworks

    def test_activate_unknown_is_noop(self):
        r = Registry()
        r.activate("nonexistent_framework_xyz")
        assert len(r.detected_frameworks) == 0

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
        assert m.taint_source is True

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
        assert mapping["open"].typestate_actions == frozenset({"open"})
        assert mapping["close"].typestate_actions == frozenset({"close"})
        assert mapping["read"].typestate_actions == frozenset({"use"})

    def test_nullness_models(self):
        r = Registry()
        r.activate("stdlib")
        mapping = r.active_models().as_mapping()
        assert mapping["re.match"].nullness_nullable_return is True
        assert mapping["get"].nullness_nullable_return is True


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
        detected = r.detect([
            "from flask import Flask",
            "open('config.json')",
            "import requests",
        ])
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
        assert "flask.request.args" in tc.source_names
        assert "flask.render_template_string" in tc.sink_names
        assert "flask.escape" in tc.sanitizer_names

    def test_as_config_with_extras(self):
        r = Registry()
        r.activate("flask")
        tc = r.as_config(
            extra_sources=["custom.source"],
            extra_sinks=["custom.sink"],
            extra_sanitizers=["custom.sanitizer"],
        )
        assert "custom.source" in tc.source_names
        assert "custom.sink" in tc.sink_names
        assert "custom.sanitizer" in tc.sanitizer_names


class TestTypeStatePresets:
    def test_file_typestate(self):
        r = Registry()
        r.activate("stdlib")
        mapping = r.active_models().as_mapping()
        assert mapping["open"].typestate_actions == frozenset({"open"})
        assert mapping["close"].typestate_actions == frozenset({"close"})
        assert mapping["read"].typestate_actions == frozenset({"use"})
        assert mapping["write"].typestate_actions == frozenset({"use"})

    def test_subprocess_typestate(self):
        r = Registry()
        r.activate("stdlib")
        mapping = r.active_models().as_mapping()
        sp = mapping.get("subprocess.Popen")
        assert sp is not None
        assert sp.taint_sink is True
        assert "open" in sp.typestate_actions
