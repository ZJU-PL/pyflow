"""Rule identities must remain unambiguous for suppressions and SARIF."""

import pytest

from pyflow.checker.ast_rules.core.config import SecurityConfig
from pyflow.checker.ast_rules.core.test_set import SecurityTestSet
from pyflow.checker.ast_rules.core.blacklist import blacklist_manager


def test_loaded_rule_ids_are_unique_and_do_not_collide_with_blacklists():
    registry = SecurityTestSet(SecurityConfig(), {})
    assert registry.load_errors == []
    functions = {function for functions in registry.tests.values() for function in functions}
    ids = [function._test_id for function in functions]
    assert len(ids) == len(set(ids))
    blacklist_ids = {item.id for items in blacklist_manager.blacklists.values() for item in items}
    assert not blacklist_ids.intersection(ids)


def test_duplicate_rule_registration_is_rejected():
    registry = SecurityTestSet(SecurityConfig(), {})

    def first(context):
        pass

    def second(context):
        pass

    for function in (first, second):
        function._test_id = "B99999"
        function._checks = ("Call",)
    registry.add_test(first)
    with pytest.raises(ValueError, match="Duplicate rule ID B99999"):
        registry.add_test(second)
