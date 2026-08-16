from pyflow.checker.pattern.core.context import Context


def test_context_exposes_legacy_string_alias():
    context = Context({"str": "/tmp/example.txt"})

    assert context.string_val == "/tmp/example.txt"
    assert context.string == context.string_val
