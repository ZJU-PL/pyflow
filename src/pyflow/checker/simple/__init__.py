"""
Simple AST-based Security Checker Engine.

This package contains a simple AST-based security checker engine that uses
AST analysis to identify security vulnerabilities and weaknesses in Python code.

**Components:**
- core: AST visitor, test runner, issue representation, context management
- checkers: Individual security test modules that use AST analysis

**Note:** This is a simple, AST-only implementation. More advanced engines
(like BugFindingEngine) use the full PyFlow analysis pipeline.
"""
