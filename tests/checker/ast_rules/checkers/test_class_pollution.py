from __future__ import annotations


def _ids(issues):
    return [i.test_id for i in issues]


def test_setattr_dangerous_dunder_is_flagged(scan):
    res = scan("setattr(obj, '__class__', 1)\n")
    issues = res.issues

    assert _ids(issues) == ["B701"]
    issue = issues[0]
    assert issue.severity == "HIGH"
    assert issue.confidence == "HIGH"
    assert issue.lineno == 1


def test_setattr_safe_attribute_is_not_flagged(scan):
    res = scan("setattr(obj, 'name', 1)\n")
    assert res.issues == []


def test_getattr_dangerous_dunder_is_flagged(scan):
    res = scan("getattr(obj, '__dict__')\n")
    issues = res.issues

    assert _ids(issues) == ["B705"]
    issue = issues[0]
    assert issue.severity == "HIGH"
    assert issue.confidence == "HIGH"
    assert issue.lineno == 1


def test_direct_dunder_dict_assignment_user_input_is_flagged(scan):
    res = scan("""
        user_input = {}
        obj.__dict__ = user_input
        """)
    issues = res.issues

    assert _ids(issues) == ["B704"]
    issue = issues[0]
    assert issue.severity == "HIGH"
    assert issue.confidence == "HIGH"
    assert issue.lineno == 2


def test_vars_call_is_flagged_low_confidence(scan):
    res = scan("vars()\n")
    issues = res.issues

    assert _ids(issues) == ["B706"]
    assert issues[0].confidence == "LOW"


def test_dict_subscript_assignment_with_user_input_is_flagged(scan):
    res = scan("obj.__dict__[input()] = 'val'\n")
    assert _ids(res.issues) == ["B704"]


def test_dict_subscript_assignment_with_formatted_string_is_flagged(scan):
    res = scan("obj.__dict__[f'key_{input()}'] = 123\n")
    assert _ids(res.issues) == ["B704"]

    res_mod = scan("obj.__dict__['key_%s' % input()] = 123\n")
    assert _ids(res_mod.issues) == ["B704"]


def test_dict_subscript_assignment_with_constant_is_not_flagged(scan):
    res = scan("obj.__dict__['safe_key'] = 123\n")
    assert res.issues == []
