from __future__ import annotations

from pyflow.checker import Cwe


def test_exec_use_is_flagged(scan):
    res = scan("exec('1+1')\n")
    issues = res.issues

    assert [i.test_id for i in issues] == ["B102"]
    issue = issues[0]
    assert issue.severity == "MEDIUM"
    assert issue.confidence == "HIGH"
    assert issue.cwe.id == Cwe.OS_COMMAND_INJECTION
    assert issue.lineno == 1


def test_subprocess_popen_shell_true_is_flagged(scan):
    # Importing `subprocess` would also trigger the import blacklist (B404).
    res = scan("subprocess.Popen('ls', shell=True)\n")
    issues = res.issues

    assert [i.test_id for i in issues] == ["B602"]
    issue = issues[0]
    assert issue.severity == "HIGH"
    assert issue.confidence == "HIGH"
    assert issue.cwe.id == Cwe.OS_COMMAND_INJECTION
    assert issue.lineno == 1


def test_os_system_is_flagged(scan):
    res = scan("import os\nos.system('ls')\n")
    issues = res.issues

    assert [i.test_id for i in issues] == ["B604"]
    issue = issues[0]
    assert issue.severity == "HIGH"
    assert issue.confidence == "HIGH"
    assert issue.cwe.id == Cwe.OS_COMMAND_INJECTION
    assert issue.lineno == 2
