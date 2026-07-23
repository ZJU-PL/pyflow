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
- **semantic_taint.py**: Public semantic taint detector API
- **_semantic_taint.py**: Taint propagation implementation
- Uses semantic facts from PyFlow analyses rather than AST patterns

Output Formatters
-----------------

**formatters/text.py**: Human-readable text output

**formatters/json.py**: Structured JSON output

**formatters/sarif.py**: SARIF format output

LLM Integration
---------------

**llm/llm_utils.py**: LLM API infrastructure (framework-independent)

- ``LLMClient`` — OpenAI-compatible chat-completion client with automatic retry and exponential backoff
- ``LLMConfig`` — Configuration dataclass (API key, model, temperature, max tokens, base URL)
- ``retry_llm_call`` — Decorator for retrying LLM API calls with configurable attempts
- ``format_bug_report`` / ``format_code_snippet`` — Formatting helpers for LLM input

**llm/judge.py**: LLM-based bug report classification

- ``BugReportJudge`` — Analyzes checker issues to determine whether they are genuine security vulnerabilities, assigning severity, CWE ID, confidence, and remediation guidance
- ``BugJudgment`` — Result dataclass (is_security_issue, severity, CWE ID, confidence, category, explanation, remediation)
- ``is_false_positive`` — Quick false-positive detection using configurable confidence thresholds

**llm/exploit.py**: Exploit generation and testing
- Generates potential exploit payloads
- Tests vulnerability hypotheses
- Validates security issue impact

Finding Quality
---------------

**quality.py**: Post-processing helpers for security findings (framework-independent)

Inline Suppression
~~~~~~~~~~~~~~~~~~

Suppress individual findings with ``# pyflow: ignore`` comments:

.. code-block:: python

   user_input = request.args.get("q")  # pyflow: ignore B608 -- validated above

- ``parse_suppressions(source)`` — Parse ``# pyflow: ignore`` directives by line number. Supports per-rule suppression (``# pyflow: ignore B608``) and bare suppression (``# pyflow: ignore``).
- ``is_suppressed(issue, suppressions)`` — Check whether an issue is covered by parsed suppressions.
- Bare suppressions (no rule ID) emit a ``BareSuppressionWarning`` when ``warn_bare=True``.

Baseline Management
~~~~~~~~~~~~~~~~~~~

Freeze known findings and only report new ones:

- ``BaselineStore`` — Persistent set of issue fingerprints (BLAKE2b-based). ``generate(issues)`` creates a baseline; ``load(path)`` / ``save(path)`` persist to JSON; ``filter_new(issues)`` returns only issues not in the baseline.
- ``issue_fingerprint(issue)`` — Stable BLAKE2b fingerprint from rule ID, file path, line number, and source text.

Confidence Scoring
~~~~~~~~~~~~~~~~~~

- ``score_confidence(issue, has_taint_trace=…)`` — Normalized confidence score (0.0–1.0) combining severity, base confidence, and taint evidence. Injection/auth issues without taint traces are penalized.
- ``confidence_level(score)`` — Map a numeric score to HIGH/MEDIUM/LOW.
- ``apply_taint_aware_demotion(issue, has_taint_trace=…)`` — Demote injection/auth issues when no semantic taint evidence backs them up.

Security Guard Detection
~~~~~~~~~~~~~~~~~~~~~~~~

- ``find_security_guards(source)`` — Extract auth-check and input-validation guards from ``if`` conditions and decorators (e.g., ``@login_required``, ``isinstance()`` checks).
- ``is_guarded(issue, guards)`` — Check whether an issue's line is protected by a recognized guard.
- ``apply_guard_aware_demotion(issue, guards)`` — Demote severity when a finding is structurally guarded.

Local Supply-Chain Analysis
----------------------------

**supply_chain.py**: Local-only supply-chain analysis for Python packages.

SBOM Generation
~~~~~~~~~~~~~~~

- ``scan_targets(targets, recursive, exclude)`` — Scan local paths for
  package metadata and produce ``SupplyChainScan`` containing components and
  findings
- ``build_cyclonedx_document(scan)`` — Build and semantically validate a
  CycloneDX 1.7 JSON document
- ``build_spdx_document(scan)`` — Build and semantically validate SPDX 2.3
- Supports ``METADATA``, requirements/constraints includes, ``pyproject.toml``,
  Poetry/PDM/uv locks, ``Pipfile.lock``, ``pylock.toml``, ``setup.cfg``, and
  statically inspected ``setup.py``
- Records source evidence and whether the discovered inventory is complete
- Resolves PEP 508 markers for a caller-selected runtime and can produce
  content-deterministic SBOM identifiers

Distribution Auditing
~~~~~~~~~~~~~~~~~~~~~

- ``RECORD`` integrity verification: validates file existence, hash
  consistency, and detects unlisted files in ``.dist-info`` directories
- Archive safety: detects absolute paths, parent-directory traversal
  (``../``), links, special files, collisions, compression bombs, nested
  archives, and oversized members in zip, tar, and wheel files
- Remote requirement detection: flags ``requirements.txt`` entries using
  remote URLs
- Offline OSV matching includes disjoint range handling, package indexing,
  snapshot freshness and SHA-256 sidecar enforcement
- SPDX-aware license policy evaluates ``AND``, ``OR``, ``WITH``, parentheses,
  and allowed exceptions
- CycloneDX/OpenVEX, in-toto/SLSA provenance, optional Sigstore verification,
  typosquatting checks, expiring exceptions, baselines, and conservative
  source-import reachability evidence are supported

Output
~~~~~~

- ``format_findings_text(scan)`` — Human-readable text output for findings
- ``build_cyclonedx_document(scan)`` — CycloneDX JSON for SBOM
- ``build_spdx_document(scan)`` — SPDX JSON for SBOM
- ``build_sarif_document(scan)`` — SARIF 2.1.0 audit results
- ``SupplyChainFinding.to_dict()`` — Structured dict for JSON serialization

Scanning and OSV/VEX/provenance ingestion work offline from local files.
Production pipelines should pin official SBOM schemas, refresh OSV snapshots,
require checksum sidecars, and use Sigstore identity verification where signed
artifacts are expected.

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

  pyflow security input.py --format json

Configuration File
------------------

Security checkers can be configured via YAML/JSON configuration files to customize:

- Enabled checkers
- Severity thresholds
- Custom rules
- Output preferences
