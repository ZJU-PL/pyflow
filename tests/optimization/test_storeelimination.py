from contextlib import contextmanager
from types import SimpleNamespace

from pyflow.optimization import storeelimination
from pyflow.ir.core import Capabilities, IRCatalog


class _Console:
    def __init__(self):
        self.messages = []

    @contextmanager
    def scope(self, _name):
        yield

    def output(self, msg):
        self.messages.append(str(msg))


def test_store_elimination_skips_when_lifetime_snapshot_is_known_empty():
    compiler = SimpleNamespace(console=_Console())
    catalog = IRCatalog()
    catalog.facts.publish(Capabilities.LIFETIME_OP_READS, "test", {})
    prgm = SimpleNamespace(liveCode=set(), ir=catalog)

    changed = storeelimination.evaluate(compiler, prgm)

    assert changed is False
    assert any("missing lifetime facts" in msg for msg in compiler.console.messages)


def test_store_elimination_requires_lifetime_even_if_annotations_exist():
    compiler = SimpleNamespace(console=_Console())
    code = SimpleNamespace(annotation=SimpleNamespace(codeReads=[set()]))
    store = SimpleNamespace(annotation=SimpleNamespace(reads=[set()], modifies=[[object()]]))
    code.isStandardCode = lambda: True
    code.annotation.descriptive = False

    prgm = SimpleNamespace(liveCode=[code], ir=IRCatalog())

    from unittest.mock import patch

    with patch("pyflow.optimization.storeelimination.codeOps", return_value=[store]):
        try:
            storeelimination.evaluate(compiler, prgm)
        except RuntimeError as exc:
            assert "requires lifetime analysis" in str(exc)
        else:
            raise AssertionError("expected store elimination to require lifetime analysis")
