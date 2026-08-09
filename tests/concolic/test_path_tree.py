import z3

from pyflow.concolic.core.runtime import _Branch
from pyflow.concolic.exploration.search import _PathTree


def test_path_tree_tracks_observed_reserved_and_exhausted_alternatives():
    first = _Branch(z3.Int("value") > 0, False)
    tree = _PathTree()

    tree.observe((first,))
    metadata = tree.reserve((), first)

    assert metadata == (1, 1)
    assert tree.reserve((), first) is None

    tree.exhaust((), first)

    assert tree.reserve((), first) is None
