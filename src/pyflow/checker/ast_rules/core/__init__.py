"""
Core Security Checker Engine.

This package contains the core components of the security checker:
- node_visitor: AST visitor that traverses code
- tester: Test runner that executes security tests
- context: Context wrapper for security tests
- blacklist: Blacklist system for dangerous functions/imports
- manager: Main SecurityManager class
- config: Configuration management
- utils: Utility functions
- test_loader: Test loading and registration
- test_properties: Test decorators and properties

Finding types, rankings, and scan metrics live in ``pyflow.checker.common``.
"""
