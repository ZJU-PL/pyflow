"""Regression cases from ordinary application and framework code."""

from pyflow.checker.ast_rules.core.config import SecurityConfig
from pyflow.checker.ast_rules.core.manager import SecurityManager


def _rules(tmp_path, source):
    path = tmp_path / "app.py"
    path.write_text(source)
    manager = SecurityManager(SecurityConfig())
    manager.discover_files([str(path)])
    manager.run_tests()
    assert manager.get_errors() == []
    return {item.test_id for item in manager.results}


def test_generic_functions_and_collection_operations_are_not_framework_vulnerabilities(tmp_path):
    rules = _rules(
        tmp_path,
        "def helper():\n    kwargs.setdefault('default', value)\n    result.add(template)\n    mapping.add(rule)\n    cursor.execute(**options)\n",
    )
    assert not ({"A105", "B510", "B604"} & rules)


def test_fastapi_rate_limit_hint_requires_endpoint_and_honors_decorators(tmp_path):
    source = (
        "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/')\ndef endpoint():\n    pass\n"
    )
    assert "A105" in _rules(tmp_path, source)
    source = "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/')\n@limiter.limit('10/minute')\ndef endpoint():\n    pass\n"
    assert "A105" not in _rules(tmp_path, source)
    assert "A105" not in _rules(
        tmp_path,
        "from flask import Flask\napp = Flask(__name__)\n@app.get('/')\ndef endpoint():\n    pass\n",
    )


def test_snmp_checks_only_community_name_parameter(tmp_path):
    assert "B510" in _rules(
        tmp_path, "from pysnmp.hlapi import CommunityData\nCommunityData('public')\n"
    )
    assert "B510" not in _rules(
        tmp_path,
        "from pysnmp.hlapi import CommunityData\nCommunityData('public', 'strong-custom-value')\n",
    )


def test_ldap_requires_receiver_evidence(tmp_path):
    assert "B604" in _rules(tmp_path, "import ldap\nconnection.add(user_dn, values)\n")
    assert "B604" not in _rules(tmp_path, "import ldap\nresult.add(item)\n")


def test_dynamic_callee_does_not_crash_user_validation_rule(tmp_path):
    _rules(tmp_path, "def get_current_user():\n    callbacks[0]()\n    get_provider()()\n")


def test_django_csrf_opt_out_uses_a_django_rule_instead_of_generic_rate_limit_hint(tmp_path):
    rules = _rules(
        tmp_path,
        "from django.views.decorators.csrf import csrf_exempt as no_csrf\n@no_csrf\ndef webhook(request):\n    return None\n",
    )
    assert "D111" in rules
    assert "A105" not in rules
