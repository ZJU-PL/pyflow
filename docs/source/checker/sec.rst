Security Analysis and Checking
==============================

PyFlow's security checker identifies potential security vulnerabilities and unsafe coding patterns in Python applications.

PyFlow provides two distinct checker engines:

**Pattern-based checker** (``pyflow.checker.pattern``)
  A lightweight AST pattern matching engine, similar to Bandit, that uses
  simple pattern matching to identify common security vulnerabilities.
  Fast and suitable for quick scans.

**Semantic checker** (``pyflow.checker.semantic``)
  A deep analysis engine that leverages PyFlow's full analysis pipeline
  (IPA/CPA, store graph, lifetime analysis) to perform context-sensitive
  vulnerability detection. More thorough but slower than pattern matching.

Checker Categories
==================

HR|Injection Vulnerabilities
XX|-------------------------
NV|
BH|**sql_injection.py**: SQL injection detection
NB|- Identifies string formatting used in SQL queries
NY|- Detects unsafe database query construction
MW|- Flags potential injection points
HQ|
ZP|**sql_injection_enhanced.py**: Enhanced SQL injection detection
QT|- Advanced SQL injection for ORMs (Django ORM, SQLAlchemy)
QK|- Detects ORM extra() injection, raw SQL, dynamic table names
JX|- NoSQL injection detection (MongoDB-style)
BQ|
MG|**command_injection.py**: Command injection detection
QK|- Detects user input in shell commands via subprocess, os.system, os.popen
QS|- Identifies shell=True usage with user-controlled arguments
QV|- Flags dangerous string formatting in command construction
BR|
YN|**shell_injection.py**: Shell injection detection
JM|- Identifies shell command construction
KP|- Detects unsafe subprocess calls
WV|- Flags potential command injection vulnerabilities
QY|
XW|**ssrf.py**: Server-Side Request Forgery detection
QP|- Detects user-controlled URLs in requests/urllib
QS|- Identifies internal metadata access (AWS, Kubernetes)
JK|- Flags dangerous URL schemes and socket connections
BR|
YW|**xxe_vulnerabilities.py**: XXE vulnerability detection
QT|- Detects unsafe XML parsing with external entity resolution
QP|- Identifies lxml, xml.dom.minidom, xml.sax vulnerabilities
QS|- Flags dangerous parser configurations
BR|
XR|**ldap_injection.py**: LDAP injection detection
QT|- Detects unsanitized user input in LDAP operations
QP|- Identifies unsafe LDAP bind and search operations
QS|- Flags dangerous LDAP connection strings
BR|
YW|**deserialization.py**: Unsafe deserialization detection
QT|- Detects unsafe pickle, yaml, marshal, jsonpickle usage
QP|- Identifies user-controlled deserialization
QS|- Flags shelve with user input
BR|
YM|**template_security.py**: Template security analysis
QT|- Detects Jinja2 autoescape disablement
QP|- Identifies unsafe template loading and mark_safe usage
QS|- Flags SSTI (Server-Side Template Injection) patterns
BQ|
Authentication and Authorization
--------------------------------

HZ|**hardcoded_password.py**: Hardcoded credentials detection
WM|- Identifies hardcoded passwords and secrets
ZV|- Detects embedded authentication tokens
YP|- Flags insecure credential storage
JW|
YX|**hardcoded_secrets.py**: Hardcoded secrets detection
RM|- Detects API tokens (GitHub, Google, Slack)
QN|- Identifies hardcoded AWS access keys
QZ|- Detects private keys and database passwords
QK|- Flags JWT secrets and encryption keys
JQ|
XY|**weak_crypto.py**: Weak cryptography detection
RB|- Identifies deprecated cryptographic functions
SW|- Detects weak encryption algorithms
SH|- Flags insecure random number generation
MX|JQ|

Web Framework Security
------------------------

**django_security.py**: Django security analysis
- Detects debug mode enabled in production
- Identifies insecure ALLOWED_HOSTS configuration
- Detects missing login_required decorators
- Flags unsafe querysets with raw user input
- Identifies password fields not properly hashed
- Detects XSS filter disablement

**fastapi_security.py**: FastAPI security analysis
- Detects JWT without expiration
- Identifies weak OAuth2 password bearer secrets
- Flags missing rate limiting
- Detects CORS origin wildcard
- Identifies sensitive data in URLs
- Checks for password hashing requirements
- Validates transaction safety in dependencies

**flask_security.py**: Flask security analysis
- Detects debug mode in production
- Identifies insecure secret key configurations
- Flags missing session cookie security flags
- Detects render_template_string SSTI vulnerability
- Identifies missing CSRF protection
- Checks for unsafe send_file paths
- Validates permanent session lifetimes

AWS Cloud Security
--------------------

**aws_security.py**: AWS security analysis
- Detects hardcoded AWS credentials
- Identifies S3 public access configurations
- Checks EC2 public IP exposure
- Flags RDS publicly accessible settings
- Validates secrets management usage
- Checks encryption at rest requirements
- Identifies insecure region configurations
- Validates STS assume role with external ID
- Flags security group open ports

YM|Code Safety
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
NS|- Configurable import restrictions
TJ|

**path_traversal.py**: Path traversal detection
- Identifies unsafe file operations with user input
- Detects open(), pathlib, os.path with user-controlled paths
- Flags os.stat and send_file with user input

**exception_handling.py**: Exception handling issues
- Detects bare except clauses
- Identifies try/except with only pass statements
- Flags exception handling that swallows errors
- Checks for improper exception propagation
TJ|
Object-Oriented Safety
----------------------

**class_pollution.py**: Class pollution detection
- Identifies unsafe attribute manipulation
- Detects potential prototype pollution
- Flags dangerous class attribute access

Analysis Framework
==================

Pattern-Based Checker Infrastructure
------------------------------------

**pattern/core/manager.py**: Pattern checker management system
- Orchestrates AST-based security analysis
- Manages checker registration and execution
- Handles analysis configuration

**pattern/core/context.py**: Pattern checker context management
- Maintains analysis state during checking
- Tracks file and module information
- Manages issue reporting

**pattern/core/issue.py**: Issue representation
- Standardizes security issue reporting
- Provides severity levels and categories
- Supports issue metadata and location tracking

**pattern/checkers/**: Individual pattern-based security checkers
- AST pattern matching rules for various vulnerability types
- Configurable blacklists and pattern definitions

Semantic Checker Infrastructure
--------------------------------

**semantic/runner.py**: Semantic checker orchestration
- Runs the full PyFlow analysis pipeline
- Coordinates semantic analysis passes (IPA/CPA/lifetime)
- Feeds analysis results to detectors

**semantic/detectors/**: Semantic-based detectors
- **taint.py** and **taint2.py**: Taint analysis detectors
- **null_dereference.py**: Null dereference detection
- **leak.py**: Leak detection (resource leaks, scope leaks)
- Uses semantic facts from PyFlow analyses rather than AST patterns

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