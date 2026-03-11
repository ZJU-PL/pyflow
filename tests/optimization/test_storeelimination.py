from contextlib import contextmanager
from types import SimpleNamespace

from pyflow.optimization import storeelimination


class _Console:
    def __init__(self):
        self.messages = []

    @contextmanager
    def scope(self, _name):
        yield

    def output(self, msg):
        self.messages.append(str(msg))


def test_store_elimination_skips_without_annotations():
    compiler = SimpleNamespace(console=_Console())
    prgm = SimpleNamespace(liveCode=set())

    changed = storeelimination.evaluate(compiler, prgm)

    assert changed is False
    assert any("missing read/modify annotations" in msg for msg in compiler.console.messages)
