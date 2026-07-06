"""
Test Django template sanitization for XSS false positive reduction.

This tests that Django's render() and render_to_string() functions
are properly recognized as sanitizers that prevent XSS via auto-escaping.
"""

import pytest
from a3_python.z3model.taint_lattice import (
    TaintLabel, SourceType, SinkType, SanitizerType
)
from a3_python.contracts.security_lattice import (
    apply_source_taint, apply_sanitizer, check_sink_taint,
    get_sanitizer_contract, get_sink_contract
)


def test_django_render_to_string_is_sanitizer():
    """Django render_to_string should be recognized as TEMPLATE_AUTOESCAPE sanitizer."""
    contract = get_sanitizer_contract("django.template.loader.render_to_string")
    
    assert contract is not None, "django.template.loader.render_to_string not found in sanitizer contracts"
    assert contract.sanitizer_type == SanitizerType.TEMPLATE_AUTOESCAPE


def test_django_shortcuts_render_is_sanitizer():
    """Django shortcuts.render should be recognized as TEMPLATE_AUTOESCAPE sanitizer."""
    contract = get_sanitizer_contract("django.shortcuts.render")
    
    assert contract is not None, "django.shortcuts.render not found in sanitizer contracts"
    assert contract.sanitizer_type == SanitizerType.TEMPLATE_AUTOESCAPE


def test_template_autoescape_protects_html_output():
    """TEMPLATE_AUTOESCAPE sanitizer should protect HTML_OUTPUT sink."""
    # Create tainted label from HTTP param
    label = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
    assert label.has_untrusted_taint()
    
    # Before sanitization: unsafe for HTML output
    assert not label.is_safe_for_sink(SinkType.HTML_OUTPUT)
    
    # Apply TEMPLATE_AUTOESCAPE sanitizer
    sanitized = label.sanitize(SanitizerType.TEMPLATE_AUTOESCAPE)
    
    # After sanitization: safe for HTML output
    assert sanitized.is_safe_for_sink(SinkType.HTML_OUTPUT)


def test_django_template_xss_false_positive_scenario():
    """
    Scenario from PyGoat false positive:
    
    username = request.GET['username']  # Tainted
    render_to_string('template.html', {'username': username})  # Sanitized
    HttpResponse(rendered)  # Should be safe for HTML output
    """
    # Step 1: Create tainted value from HTTP parameter
    username_label = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
    
    # Step 2: Pass through render_to_string (apply TEMPLATE_AUTOESCAPE)
    rendered_label = username_label.sanitize(SanitizerType.TEMPLATE_AUTOESCAPE)
    
    # Step 3: Check if safe for HTML output (HttpResponse)
    assert rendered_label.is_safe_for_sink(SinkType.HTML_OUTPUT), \
        "render_to_string output should be safe for HTML after auto-escaping"


def test_django_safe_filter_bypasses_sanitization():
    """
    Django |safe filter bypasses auto-escaping - this SHOULD be flagged as XSS.
    
    Note: We don't currently track |safe filter usage, so this test documents
    the limitation. When template parsing is added, this should detect XSS.
    """
    # This is a limitation: we currently can't detect |safe filter
    # In the future, we should parse templates and detect:
    # {{username|safe}} -> bypasses TEMPLATE_AUTOESCAPE
    pass  # TODO: Add when template parsing is implemented


def test_html_escape_sanitizer_also_protects():
    """html.escape and django.utils.html.escape should also prevent XSS."""
    label = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
    
    # Apply HTML_ESCAPE sanitizer
    sanitized = label.sanitize(SanitizerType.HTML_ESCAPE)
    
    # Should be safe for HTML output
    assert sanitized.is_safe_for_sink(SinkType.HTML_OUTPUT)


def test_template_sanitizer_does_not_protect_sql():
    """TEMPLATE_AUTOESCAPE only protects HTML sinks, not SQL."""
    label = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
    
    # Apply TEMPLATE_AUTOESCAPE
    sanitized = label.sanitize(SanitizerType.TEMPLATE_AUTOESCAPE)
    
    # Safe for HTML
    assert sanitized.is_safe_for_sink(SinkType.HTML_OUTPUT)
    
    # Still unsafe for SQL (different sanitizer needed)
    assert not sanitized.is_safe_for_sink(SinkType.SQL_EXECUTE)


def test_multiple_sanitizers_accumulate():
    """Multiple sanitizers should accumulate protection."""
    label = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
    
    # Apply both HTML and SQL sanitizers
    label = label.sanitize(SanitizerType.HTML_ESCAPE)
    label = label.sanitize(SanitizerType.SQL_ESCAPE)
    
    # Should be safe for both sinks
    assert label.is_safe_for_sink(SinkType.HTML_OUTPUT)
    assert label.is_safe_for_sink(SinkType.SQL_EXECUTE)


def test_django_httpresponse_is_html_output_sink():
    """HttpResponse should be recognized as HTML_OUTPUT sink."""
    contract = get_sink_contract("django.http.HttpResponse")
    
    assert contract is not None, "django.http.HttpResponse not found in sink contracts"
    assert contract.sink_type == SinkType.HTML_OUTPUT


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
