"""SSRF pattern checks must inspect only the outbound URL argument."""

import ast
from types import SimpleNamespace

import pytest

from pyflow.checker.ast_rules.checkers import ssrf


def _context(source):
    node = ast.parse(source).body[0].value
    return SimpleNamespace(node=node, call_function_name_qual=ast.unparse(node.func))


@pytest.mark.parametrize(
    "source",
    [
        "requests.post('https://example.com', payload)",
        "requests.request(method, 'https://example.com')",
        "requests.get_extra(url)",
        "requests.get('https://example.com', headers=headers)",
    ],
)
def test_requests_does_not_treat_payload_or_method_as_url(source):
    assert ssrf.requests_user_url(_context(source)) is None
    assert ssrf.no_url_validation(_context(source)) is None


@pytest.mark.parametrize(
    "source",
    [
        "requests.get(url)",
        "requests.get(url=url)",
        "requests.request('GET', url)",
        "requests.request(method='GET', url=url)",
    ],
)
def test_requests_variable_url_is_an_explicit_low_confidence_review(source):
    finding = ssrf.requests_user_url(_context(source))
    assert finding is not None
    assert finding.confidence == "LOW"
    assert "does not establish" in finding.text


def test_urllib_keyword_url_is_checked():
    assert ssrf.urllib_user_url(_context("urllib.request.urlopen(url=url)")) is not None


@pytest.mark.parametrize(
    "source",
    [
        "requests.request('GET', 'file:///tmp/example')",
        "urllib.request.urlopen(url='file:///tmp/example')",
    ],
)
def test_url_scheme_check_uses_correct_url_port(source):
    assert ssrf.dangerous_url_scheme(_context(source)) is not None
