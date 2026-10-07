"""
AST rule checking subsystem.

This package contains a pattern-based security checker engine that uses
AST pattern matching to identify security vulnerabilities and weaknesses
in Python code (similar to Bandit).

**Components:**
- core: AST visitor, rule loading and execution, context management
- checkers: Individual security test modules that use AST pattern matching

Shared issue types, rankings, and metrics live in ``pyflow.checker.common``.
This subsystem keeps its AST execution framework and security rules together.
"""
