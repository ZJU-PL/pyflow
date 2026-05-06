"""
``a3 init`` — bootstrap any repo with CI workflows.

Copies workflow templates into ``.github/workflows/``, creates a
``.a3.yml`` config, and initialises an empty baseline file.
"""

from __future__ import annotations

import shutil
from importlib import resources
from pathlib import Path

from .config import A3Config


# All template files shipped with the package
_WORKFLOW_TEMPLATES = [
    "a3-pr-scan.yml",
    "a3-scheduled-scan.yml",
]


def init_repo(
    repo_root: Path,
    *,
    overwrite: bool = False,
    enable_llm_triage: bool = False,
    llm_provider: str = "anthropic",
    llm_model: str = "claude-sonnet-4-20250514",
    copilot: bool = False,
) -> list[str]:
    """
    Bootstrap a repository with a3 CI integration.

    Creates:
    - ``.github/workflows/a3-pr-scan.yml``
    - ``.github/workflows/a3-scheduled-scan.yml``
    - ``.a3.yml``
    - ``.a3-baseline.json``

    Parameters
    ----------
    repo_root : Path
        Root of the target git repository.
    overwrite : bool
        If True, overwrite existing files.
    enable_llm_triage : bool
        Whether to enable LLM triage in the config.

    Returns
    -------
    list[str]
        Paths of all files created (relative to repo_root).
    """
    repo_root = Path(repo_root).resolve()
    created: list[str] = []

    # --copilot is a convenience shorthand
    if copilot:
        enable_llm_triage = True
        llm_provider = "github"
        llm_model = "gpt-4o"

    # ── 1. Workflow files ────────────────────────────────────────────────
    workflows_dir = repo_root / ".github" / "workflows"
    workflows_dir.mkdir(parents=True, exist_ok=True)

    templates_dir = Path(__file__).parent / "templates"

    for template_name in _WORKFLOW_TEMPLATES:
        src = templates_dir / template_name
        dst = workflows_dir / template_name

        if dst.exists() and not overwrite:
            print(f"  ⏭  {dst.relative_to(repo_root)} already exists (use --overwrite to replace)")
            continue

        content = src.read_text()
        dst.write_text(content)
        rel = str(dst.relative_to(repo_root))
        created.append(rel)
        print(f"  ✅  Created {rel}")

    # ── 2. Config file ───────────────────────────────────────────────────
    config_path = repo_root / ".a3.yml"
    if config_path.exists() and not overwrite:
        print(f"  ⏭  .a3.yml already exists")
    else:
        config = A3Config()
        config.ci.llm_triage = enable_llm_triage
        config.ci.llm_provider = llm_provider
        config.ci.llm_model = llm_model
        config_path.write_text(config.to_yaml())
        created.append(".a3.yml")
        print(f"  ✅  Created .a3.yml")

    # ── 3. Empty baseline ────────────────────────────────────────────────
    baseline_path = repo_root / ".a3-baseline.json"
    if baseline_path.exists() and not overwrite:
        print(f"  ⏭  .a3-baseline.json already exists")
    else:
        baseline_path.write_text('{\n  "version": 1,\n  "findings": {}\n}\n')
        created.append(".a3-baseline.json")
        print(f"  ✅  Created .a3-baseline.json")

    return created


def cmd_init(
    repo_root: Path,
    *,
    overwrite: bool = False,
    llm_triage: bool = False,
    copilot: bool = False,
) -> int:
    """``a3 init`` CLI entry point."""
    print(f"\n🚀 Initialising a3 CI in {repo_root}\n")

    created = init_repo(
        repo_root,
        overwrite=overwrite,
        enable_llm_triage=llm_triage,
        copilot=copilot,
    )

    print(f"\n{'─' * 50}")
    if created:
        print(f"Created {len(created)} file(s). Next steps:\n")
        print("  git add .github/ .a3.yml .a3-baseline.json")
        print("  git commit -m 'ci: add a3 static analysis'")
        print("  git push")
        print()
        if copilot:
            print("  ✅ GitHub Copilot triage is enabled — no API keys needed!")
            print("     The workflow uses GITHUB_TOKEN which is provided automatically.")
            print()
        elif llm_triage:
            print("  ⚠  LLM triage is enabled. Make sure to add your API key")
            print("     as a repository secret: ANTHROPIC_API_KEY or OPENAI_API_KEY")
            print()
    else:
        print("Nothing to do — all files already exist.")
        print("Use --overwrite to replace existing files.")
    print()
    return 0
