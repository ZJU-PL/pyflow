"""
Configuration file loader for ``.a3.yml``.

Provides sane defaults so the tool works out of the box even without a
config file, while allowing per-repo customisation of analysis flags,
CI behaviour, and scan scope.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class AnalysisConfig:
    interprocedural: bool = True
    kitchensink: bool = True
    dse_verify: bool = True
    min_confidence: float = 0.7
    deduplicate: bool = True
    no_intent_filter: bool = False
    max_dse_steps: int = 100


@dataclass
class CIConfig:
    fail_on_new_bugs: bool = True
    baseline_file: str = ".a3-baseline.json"
    llm_triage: bool = False
    llm_model: str = "claude-sonnet-4-20250514"
    llm_provider: str = "anthropic"
    sarif_upload: bool = True


@dataclass
class ScanConfig:
    exclude: list[str] = field(default_factory=lambda: [
        "tests/**",
        "test/**",
        "**/test_*.py",
        "docs/**",
        "examples/**",
        "setup.py",
        "conftest.py",
    ])
    include: list[str] = field(default_factory=lambda: ["**/*.py"])


@dataclass
class A3Config:
    """Top-level configuration for a3."""
    analysis: AnalysisConfig = field(default_factory=AnalysisConfig)
    ci: CIConfig = field(default_factory=CIConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)

    @classmethod
    def load(cls, repo_root: Path) -> "A3Config":
        """Load config from .a3.yml, falling back to defaults."""
        config_path = repo_root / ".a3.yml"
        if not config_path.exists():
            config_path = repo_root / ".a3.yaml"
        if not config_path.exists():
            return cls()

        try:
            import yaml
        except ImportError:
            # If PyYAML isn't installed, use defaults
            return cls()

        with open(config_path) as f:
            raw = yaml.safe_load(f) or {}

        return cls._from_dict(raw)

    @classmethod
    def _from_dict(cls, raw: dict[str, Any]) -> "A3Config":
        analysis_raw = raw.get("analysis", {})
        ci_raw = raw.get("ci", {})
        scan_raw = raw.get("scan", {})

        analysis = AnalysisConfig(
            interprocedural=analysis_raw.get("interprocedural", True),
            kitchensink=analysis_raw.get("kitchensink", True),
            dse_verify=analysis_raw.get("dse-verify", analysis_raw.get("dse_verify", True)),
            min_confidence=float(analysis_raw.get("min-confidence", analysis_raw.get("min_confidence", 0.7))),
            deduplicate=analysis_raw.get("deduplicate", True),
            no_intent_filter=analysis_raw.get("no-intent-filter", analysis_raw.get("no_intent_filter", False)),
            max_dse_steps=int(analysis_raw.get("max-dse-steps", analysis_raw.get("max_dse_steps", 100))),
        )

        ci = CIConfig(
            fail_on_new_bugs=ci_raw.get("fail-on-new-bugs", ci_raw.get("fail_on_new_bugs", True)),
            baseline_file=ci_raw.get("baseline-file", ci_raw.get("baseline_file", ".a3-baseline.json")),
            llm_triage=ci_raw.get("llm-triage", ci_raw.get("llm_triage", False)),
            llm_model=ci_raw.get("llm-model", ci_raw.get("llm_model", "claude-sonnet-4-20250514")),
            llm_provider=ci_raw.get("llm-provider", ci_raw.get("llm_provider", "anthropic")),
            sarif_upload=ci_raw.get("sarif-upload", ci_raw.get("sarif_upload", True)),
        )

        scan = ScanConfig()
        if "exclude" in scan_raw:
            scan.exclude = scan_raw["exclude"]
        if "include" in scan_raw:
            scan.include = scan_raw["include"]

        return cls(analysis=analysis, ci=ci, scan=scan)

    def to_yaml(self) -> str:
        """Serialise to YAML string."""
        lines = [
            "# .a3.yml — a3-python configuration",
            "# See: https://github.com/thehalleyyoung/a3-python",
            "",
            "analysis:",
            f"  interprocedural: {str(self.analysis.interprocedural).lower()}",
            f"  kitchensink: {str(self.analysis.kitchensink).lower()}",
            f"  dse-verify: {str(self.analysis.dse_verify).lower()}",
            f"  min-confidence: {self.analysis.min_confidence}",
            f"  deduplicate: {str(self.analysis.deduplicate).lower()}",
            f"  no-intent-filter: {str(self.analysis.no_intent_filter).lower()}",
            f"  max-dse-steps: {self.analysis.max_dse_steps}",
            "",
            "ci:",
            f"  fail-on-new-bugs: {str(self.ci.fail_on_new_bugs).lower()}",
            f"  baseline-file: {self.ci.baseline_file}",
            f"  llm-triage: {str(self.ci.llm_triage).lower()}",
            f"  llm-model: {self.ci.llm_model}",
            f"  llm-provider: {self.ci.llm_provider}",
            f"  sarif-upload: {str(self.ci.sarif_upload).lower()}",
            "",
            "scan:",
            "  exclude:",
        ]
        for pat in self.scan.exclude:
            lines.append(f'    - "{pat}"')
        lines.append("  include:")
        for pat in self.scan.include:
            lines.append(f'    - "{pat}"')
        lines.append("")
        return "\n".join(lines)
