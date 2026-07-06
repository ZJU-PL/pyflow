"""
a3_python.ci — CI/CD integration for A³.

Provides:
- SARIF 2.1.0 output for GitHub Code Scanning
- Baseline ratchet for incremental adoption
- LLM triage for automated FP classification
- `a3 init` to bootstrap any repo with workflows
"""

__all__ = ["sarif", "baseline", "triage", "init_cmd"]
