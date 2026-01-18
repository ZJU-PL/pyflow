"""
Pattern-based AST matching Security Checker Engine.

This package contains a pattern-based security checker engine that uses
AST pattern matching to identify security vulnerabilities and weaknesses
in Python code (similar to Bandit).

**Components:**
- core: AST visitor, test runner, issue representation, context management
- checkers: Individual security test modules that use AST pattern matching

**Note:** This is a pattern-based, AST-only implementation. The semantic
engine uses the full PyFlow analysis pipeline for deeper analysis.
"""
