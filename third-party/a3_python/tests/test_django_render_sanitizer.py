"""
Test Django template rendering sanitizer (Iteration 523).

Verifies that Django's render() and render_to_string() properly sanitize
tainted data for HTML output due to auto-escaping.
"""

import pytest
from a3_python.z3model.taint_lattice import (
    TaintLabel, SourceType, SinkType, SanitizerType
)
from a3_python.contracts.security_lattice import (
    get_sanitizer_contract, apply_sanitizer,
    init_security_contracts
)


@pytest.fixture(autouse=True)
def setup_contracts():
    """Initialize security contracts before each test."""
    init_security_contracts()


class TestDjangoRenderSanitizer:
    """Test Django template rendering sanitization."""
    
    def test_django_render_registered_as_sanitizer(self):
        """Verify Django render functions are registered as sanitizers."""
        functions = [
            'django.shortcuts.render',
            'django.template.loader.render_to_string',
            'django.template.Template.render'
        ]
        
        for func_name in functions:
            contract = get_sanitizer_contract(func_name)
            assert contract is not None, f"{func_name} should be registered"
            assert contract.sanitizer_type == SanitizerType.TEMPLATE_AUTOESCAPE
            assert SinkType.HTML_OUTPUT in contract.applicable_sinks
    
    def test_render_to_string_sanitizes_tainted_data(self):
        """Test that render_to_string marks output as safe for HTML."""
        # Create tainted label from HTTP parameter
        tainted = TaintLabel.from_untrusted_source(
            SourceType.HTTP_PARAM,
            'request.GET.username'
        )
        
        # Apply Django render_to_string sanitizer
        sanitized = apply_sanitizer('django.template.loader.render_to_string', tainted)
        
        # Result should be safe for HTML_OUTPUT
        assert sanitized.is_safe_for_sink(SinkType.HTML_OUTPUT), \
            "render_to_string should sanitize for HTML_OUTPUT"
        
        # But should still have source taint (it came from HTTP)
        assert sanitized.has_untrusted_taint(), \
            "render_to_string doesn't remove source taint, just sanitizes for HTML"
    
    def test_django_shortcuts_render_sanitizes(self):
        """Test that django.shortcuts.render sanitizes."""
        tainted = TaintLabel.from_untrusted_source(
            SourceType.USER_INPUT,
            'form.data'
        )
        
        sanitized = apply_sanitizer('django.shortcuts.render', tainted)
        
        assert sanitized.is_safe_for_sink(SinkType.HTML_OUTPUT)
        assert sanitized.has_untrusted_taint()
    
    def test_django_template_render_sanitizes(self):
        """Test that django.template.Template.render sanitizes."""
        tainted = TaintLabel.from_untrusted_source(
            SourceType.HTTP_PARAM,
            'request.POST.comment'
        )
        
        sanitized = apply_sanitizer('django.template.Template.render', tainted)
        
        assert sanitized.is_safe_for_sink(SinkType.HTML_OUTPUT)
        assert sanitized.has_untrusted_taint()
    
    def test_render_does_not_sanitize_other_sinks(self):
        """Django render only sanitizes HTML, not SQL/command injection."""
        tainted = TaintLabel.from_untrusted_source(
            SourceType.HTTP_PARAM,
            'request.GET.query'
        )
        
        sanitized = apply_sanitizer('django.template.loader.render_to_string', tainted)
        
        # Should NOT be safe for SQL or command execution
        assert not sanitized.is_safe_for_sink(SinkType.SQL_EXECUTE), \
            "render_to_string doesn't sanitize SQL"
        assert not sanitized.is_safe_for_sink(SinkType.COMMAND_SHELL), \
            "render_to_string doesn't sanitize shell commands"


class TestDjangoRenderIntegration:
    """Integration tests with the security tracker."""
    
    def test_render_to_string_followed_by_httpresponse(self):
        """
        Test the PyGoat false positive pattern:
        rendered = render_to_string('template.html', {'username': tainted})
        response = HttpResponse(rendered)
        
        This should NOT be flagged as XSS because render_to_string sanitizes.
        """
        from a3_python.semantics.security_tracker_lattice import LatticeSecurityTracker
        
        tracker = LatticeSecurityTracker()
        
        # Simulate: username = request.GET.get('username')
        tainted_username = object()
        username_label = TaintLabel.from_untrusted_source(
            SourceType.HTTP_PARAM,
            'request.GET.username'
        )
        tracker.set_label(tainted_username, username_label)
        
        # Simulate: context = {'username': tainted_username}
        context_dict = object()
        # Dict inherits taint from its values
        tracker.set_label(context_dict, username_label)
        
        # Simulate: rendered = render_to_string('template.html', context)
        template_name = object()
        tracker.set_label(template_name, TaintLabel.clean())
        
        rendered = object()
        
        # Call handle_call_post for render_to_string
        # This should merge taint from all args and apply sanitization
        result_label, _ = tracker.handle_call_post(
            func_name='django.template.loader.render_to_string',
            func_ref=None,
            args=[template_name, context_dict],
            result=rendered,
            location='test.py:10'
        )
        
        # Verify: rendered has taint but is sanitized for HTML_OUTPUT
        assert result_label.has_untrusted_taint(), \
            "rendered should have taint from context"
        assert result_label.is_safe_for_sink(SinkType.HTML_OUTPUT), \
            "rendered should be safe for HTML_OUTPUT due to auto-escaping"
        
        # Simulate: HttpResponse(rendered)
        # This should NOT trigger a violation because rendered is sanitized
        violation = tracker.handle_call_pre(
            func_name='django.http.HttpResponse',
            args=[rendered],
            location='test.py:11'
        )
        
        assert violation is None, \
            "HttpResponse(rendered) should NOT trigger XSS violation"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
