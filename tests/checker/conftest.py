from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import textwrap
from typing import Any, Mapping, Optional, Sequence, Union

import pytest

from pyflow.checker import Issue, SecurityConfig, SecurityManager


IssueList = list[Issue]


def _normalize_code(code: str) -> str:
    # Allow indented triple-quoted snippets in tests.
    code = textwrap.dedent(code)
    # Trim leading blank line to keep expected line numbers stable.
    code = code.lstrip("\n")
    if code and not code.endswith("\n"):
        code += "\n"
    return code


def _flatten_issue_list(issue_list: Any) -> IssueList:
    """
    SecurityManager.get_issue_list() normally returns a list[Issue], but if a
    baseline is loaded it returns an OrderedDict mapping -> candidates.
    """
    if isinstance(issue_list, list):
        return issue_list
    if isinstance(issue_list, dict):
        out: IssueList = []
        for _, candidates in issue_list.items():
            out.extend(candidates)
        return out
    return list(issue_list)


@dataclass(frozen=True)
class ScanResult:
    manager: SecurityManager
    issues: IssueList

    def ids(self) -> list[str]:
        return [i.test_id for i in self.issues]

    def by_id(self, test_id: str) -> IssueList:
        return [i for i in self.issues if i.test_id == test_id]

    def one(self, test_id: Optional[str] = None) -> Issue:
        issues = self.by_id(test_id) if test_id is not None else self.issues
        assert len(issues) == 1, issues
        return issues[0]


class Scanner:
    """
    Small harness around SecurityManager that:
    - writes one or many temporary files
    - runs the real AST pipeline (SecurityNodeVisitor/SecurityTester)
    - returns filtered issues plus convenience selectors
    """

    def __init__(self, tmp_path: Path):
        self._tmp_path = tmp_path

    def scan(
        self,
        code: str,
        *,
        filename: str = "sample.py",
        ignore_nosec: bool = False,
        sev_level: str = "LOW",
        conf_level: str = "LOW",
        config_overrides: Optional[Mapping[str, Any]] = None,
    ) -> ScanResult:
        return self.scan_files(
            {filename: code},
            ignore_nosec=ignore_nosec,
            sev_level=sev_level,
            conf_level=conf_level,
            config_overrides=config_overrides,
        )

    def scan_files(
        self,
        files: Mapping[str, str],
        *,
        ignore_nosec: bool = False,
        sev_level: str = "LOW",
        conf_level: str = "LOW",
        config_overrides: Optional[Mapping[str, Any]] = None,
    ) -> ScanResult:
        cfg = SecurityConfig()
        if config_overrides:
            for k, v in config_overrides.items():
                cfg.set_option(k, v)

        paths: list[str] = []
        for rel_name, code in files.items():
            p = self._tmp_path / rel_name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(_normalize_code(code), encoding="utf-8")
            paths.append(str(p))

        manager = SecurityManager(cfg, ignore_nosec=ignore_nosec)
        manager.discover_files(paths, recursive=False)
        manager.run_tests()

        issues = _flatten_issue_list(manager.get_issue_list(sev_level, conf_level))
        return ScanResult(manager=manager, issues=issues)


@pytest.fixture()
def scan(tmp_path: Path):
    scanner = Scanner(tmp_path)

    def _scan(
        code: str,
        *,
        filename: str = "sample.py",
        ignore_nosec: bool = False,
        sev_level: str = "LOW",
        conf_level: str = "LOW",
        config_overrides: Optional[Mapping[str, Any]] = None,
    ) -> ScanResult:
        return scanner.scan(
            code,
            filename=filename,
            ignore_nosec=ignore_nosec,
            sev_level=sev_level,
            conf_level=conf_level,
            config_overrides=config_overrides,
        )

    # expose the richer harness too
    _scan.files = scanner.scan_files  # type: ignore[attr-defined]
    return _scan
