"""
Core Security Checker Engine.

This package contains the core components of the security checker:
- node_visitor: AST visitor that traverses code
- tester: Test runner that executes security tests
- issue: Issue and CWE representation
- context: Context wrapper for security tests
- blacklist: Blacklist system for dangerous functions/imports
- constants: Constants for severity/confidence rankings
- manager: Main SecurityManager class
- config: Configuration management
- utils: Utility functions
- metrics: Metrics collection
- test_loader: Test loading and registration
- test_properties: Test decorators and properties
"""