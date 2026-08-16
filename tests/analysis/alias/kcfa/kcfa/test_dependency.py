from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.dependency import (
    DependencyManager,
)


def test_dependency_coalesces_repeated_source_growth():
    manager = DependencyManager()
    calls = []
    manager.subscribe("derived", ("left", "right"), lambda: calls.append("run"))

    manager.notify_growth("left")
    manager.notify_growth("left")
    manager.notify_growth("right")

    assert manager.has_pending()
    manager.run_next()
    assert calls == ["run"]
    assert not manager.has_pending()


def test_dependency_keys_deduplicate_subscriptions():
    manager = DependencyManager()

    assert manager.subscribe("same", ("source",), lambda: None)
    assert not manager.subscribe("same", ("source",), lambda: None)
    assert len(manager) == 1
