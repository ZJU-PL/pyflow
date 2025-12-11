Security Analysis and Checking
==============================

PyFlow's security checker identifies potential security vulnerabilities and unsafe coding patterns in Python applications.

Checker Categories
==================

Injection Vulnerabilities
-------------------------

**sql_injection.py**: SQL injection detection
- Identifies string formatting used in SQL queries
- Detects unsafe database query construction
- Flags potential injection points

**shell_injection.py**: Command injection detection
- Identifies shell command construction
- Detects unsafe subprocess calls
- Flags potential command injection vulnerabilities

Authentication and Authorization
--------------------------------

**hardcoded_password.py**: Hardcoded credentials detection
- Identifies hardcoded passwords and secrets
- Detects embedded authentication tokens
- Flags insecure credential storage

**weak_crypto.py**: Weak cryptography detection
- Identifies deprecated cryptographic functions
- Detects weak encryption algorithms
- Flags insecure random number generation

Code Safety
-----------

**exec_use.py**: Dangerous code execution
- Identifies use of exec() and eval()
- Detects dynamic code execution patterns
- Flags potential code injection vulnerabilities

**blacklist_calls.py**: Blacklisted function calls
- Identifies calls to dangerous functions
- Configurable blacklist of unsafe operations
- Flags potentially harmful API usage

**blacklist_imports.py**: Blacklisted module imports
- Identifies imports of unsafe modules
- Detects potentially dangerous library usage
- Configurable import restrictions

Object-Oriented Safety
----------------------

**class_pollution.py**: Class pollution detection
- Identifies unsafe attribute manipulation
- Detects potential prototype pollution
- Flags dangerous class attribute access

Analysis Framework
==================

Core Infrastructure
-------------------

**core/manager.py**: Checker management system
- Orchestrates security analysis
- Manages checker registration and execution
- Handles analysis configuration

**core/context.py**: Analysis context management
- Maintains analysis state during checking
- Tracks file and module information
- Manages issue reporting

**core/issue.py**: Issue representation
- Standardizes security issue reporting
- Provides severity levels and categories
- Supports issue metadata and location tracking

Output Formatters
-----------------

**formatters/text.py**: Human-readable text output

**formatters/json.py**: Structured JSON output

**formatters/sarif.py**: SARIF format output

LLM Integration
---------------

**llm/check.py**: LLM-assisted security checking
- Uses language models for vulnerability detection
- Pattern recognition beyond rule-based checking
- Contextual vulnerability assessment

**llm/exploit.py**: Exploit generation and testing
- Generates potential exploit payloads
- Tests vulnerability hypotheses
- Validates security issue impact

Configuration and Testing
-------------------------

**core/config.py**: Configuration management
- Checker enable/disable settings
- Severity threshold configuration
- Custom rule definitions

**core/test_loader.py**: Test case management
- Loads security test cases
- Manages false positive/negative testing
- Benchmarking and validation

Usage
=====

Command Line
------------

::

  pyflow check input.py --format json --severity high

Configuration File
------------------

Security checkers can be configured via YAML/JSON configuration files to customize:

- Enabled checkers
- Severity thresholds
- Custom rules
- Output preferences