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
    assert not ({"A105", "B9034", "B9037"} & rules)


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
    assert "B9034" in _rules(
        tmp_path, "from pysnmp.hlapi import CommunityData\nCommunityData('public')\n"
    )
    assert "B9034" not in _rules(
        tmp_path,
        "from pysnmp.hlapi import CommunityData\nCommunityData('public', 'strong-custom-value')\n",
    )


def test_ldap_requires_receiver_evidence(tmp_path):
    assert "B9037" in _rules(tmp_path, "import ldap\nconnection.add(user_dn, values)\n")
    assert "B9037" not in _rules(tmp_path, "import ldap\nresult.add(item)\n")


def test_dynamic_callee_does_not_crash_user_validation_rule(tmp_path):
    _rules(tmp_path, "def get_current_user():\n    callbacks[0]()\n    get_provider()()\n")


def test_django_csrf_opt_out_uses_a_django_rule_instead_of_generic_rate_limit_hint(tmp_path):
    rules = _rules(
        tmp_path,
        "from django.views.decorators.csrf import csrf_exempt as no_csrf\n@no_csrf\ndef webhook(request):\n    return None\n",
    )
    assert "D111" in rules
    assert "A105" not in rules


def test_secret_keys_with_no_values_and_password_messages_are_not_secrets(tmp_path):
    rules = _rules(
        tmp_path,
        'import boto3\nconfig = {"SECRET_KEY": None, "password": ""}\nerror = "Password is required."\n',
    )
    assert not ({"W107", "B105", "B507"} & rules)
    assert "W107" in _rules(tmp_path, 'import boto3\nconfig = {"SECRET_KEY": "long-real-secret"}\n')
    assert "W107" in _rules(tmp_path, 'import boto3\nsecret_key: str = "long-real-secret"\n')
    assert "W107" not in _rules(tmp_path, 'password = "long-real-secret"\n')


def test_aws_region_rule_requires_sdk_factory_and_accepts_configured_regions(tmp_path):
    assert "W108" not in _rules(
        tmp_path, 'import boto3\napp.open_resource("schema.sql")\nclient_factory()\n'
    )
    assert "W108" in _rules(tmp_path, 'import boto3 as aws\naws.client("s3")\n')
    assert "W108" in _rules(tmp_path, 'from boto3 import Session\nSession().resource("s3")\n')
    assert "W108" not in _rules(
        tmp_path, 'import boto3\nboto3.client("s3", region_name="us-east-1")\n'
    )
    assert "W108" not in _rules(tmp_path, 'import boto3\nboto3.client("s3", region_name=region)\n')


def test_login_rule_requires_django_request_handler_evidence(tmp_path):
    assert "D109" not in _rules(
        tmp_path,
        "import django\nclass Model:\n def generate(self, max_new_tokens=1): pass\n def print_user_agent(self): pass\ndef user_account(): return None\n",
    )
    source = "from django.http import JsonResponse as Response\ndef user_account(request):\n return Response({})\n"
    assert "D109" in _rules(tmp_path, source)
    protected = "from django.contrib.auth.decorators import login_required\n" + source.replace(
        "def user_account", '@login_required(login_url="/login")\ndef user_account'
    )
    assert "D109" not in _rules(tmp_path, protected)
