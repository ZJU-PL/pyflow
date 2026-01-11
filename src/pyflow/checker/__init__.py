"""
Security Checker for PyFlow.

This package provides a security checker that scans Python code for security
vulnerabilities and weaknesses. The checker uses AST analysis to identify
dangerous patterns, insecure function calls, weak cryptography, and other
security issues.

**Architecture:**
- ast: AST-based engine (current implementation)
  - core: AST visitor, test runner, issue representation, context management
  - checkers: Individual security test modules
- Formatters: Output formatters (JSON, SARIF, text)
- LLM: LLM-based advanced analysis (optional)

**Key Features:**
- AST-based static analysis
- Blacklist system for dangerous functions/imports
- CWE (Common Weakness Enumeration) integration
- Severity and confidence scoring
- Nosec comment support (# nosec to suppress warnings)
- Multiple output formats

**Note:** Currently, the security checker does not use the facilities in pyflow
for analysis. It operates as a standalone security scanner similar to Bandit.

**Usage:**
```python
from pyflow.checker import SecurityManager

manager = SecurityManager()
results = manager.check_file("example.py")
```
"""

# Security checker for pyflow
# NOTE: Current, the security checker does not use the facilities in pyflow.
from .ast.core.manager import SecurityManager
from .ast.core.config import SecurityConfig
from .ast.core.issue import Issue, Cwe

__all__ = ["SecurityManager", "SecurityConfig", "Issue", "Cwe"]
