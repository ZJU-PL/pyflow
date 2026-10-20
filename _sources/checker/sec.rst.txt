Security Analysis and Checking
==============================

PyFlow's security checker identifies potential security vulnerabilities and unsafe coding patterns in Python applications.

PyFlow provides several checking subsystems:

**Pattern-based checker** (``pyflow.checker.ast_rules``)
  A lightweight AST pattern matching engine, similar to Bandit, that uses
  simple pattern matching to identify common security vulnerabilities.
  Fast and suitable for quick scans.

**AST dataflow checker** (``pyflow.checker.ast_dataflow``)
  A CFG-backed abstract interpreter with typed taint kinds, shape-sensitive
  heap access paths, strong/weak updates, outcome-sensitive relational
  summaries, explicit uncertainty diagnostics, and bounded source-to-sink
  witnesses. More thorough but slower than pattern matching.

**IFDS checker** (``pyflow.checker.ifds``)
  Interprocedural security checking using the general IFDS solver, including
  taint and class-pollution analysis.

**CPG checker** (``pyflow.checker.cpg``)
  Security analysis over Code Property Graphs, with rule loading and
  framework-specific models.

**Class-pollution checker** (``pyflow.checker.ifds.class_pollution``)
  An independent relational IFDS checker for attacker-controlled reflective
  object traversal and writes into class or namespace state.

**Capability checker** (``pyflow.checker.capability``)
  A context-sensitive pointer-based checker for security-sensitive authority,
  potential capability transfer, external effects, and optional runtime audit
  observation or denial of classified events.

**Supply-chain checker** (``pyflow.checker.supply_chain``)
  Package inventory, integrity, vulnerability, and policy analysis.

Package Layout
--------------

``ast_rules/`` and ``ast_dataflow/`` keep their execution frameworks and
detection rules together. ``ifds/`` contains the complete IFDS taint analysis,
file-analysis entry point, reporting adapter, shadow scanning, and class
pollution checking. ``cpg/`` contains the complete CPG taint analysis, rule
loading, and framework profiles. ``capability/`` and ``supply_chain/`` remain
self-contained checking subsystems.

``common/`` contains shared issue/CWE types, rankings, and scan metrics.
``formatters/`` handles report output, and ``llm/`` handles LLM-assisted report
analysis. General IFDS solving, CFG adaptation, session loading, and non-security
analyses remain in ``pyflow.analysis.ifds``. CPG/PDG representation, construction,
queries, and export remain in ``pyflow.ir``.

The former ``pattern`` package, ``checker.detectors`` grouping, IFDS taint
exports under ``analysis.ifds``, and security analysis modules under
``ir.cpg`` have been removed without compatibility modules. Use the checking
subsystems directly and import shared types from ``pyflow.checker.common``.

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

**ast_rules/core/manager.py**: Pattern checker management system
- Orchestrates AST-based security analysis
- Manages checker registration and execution
- Handles analysis configuration

**ast_rules/core/context.py**: Pattern checker context management
- Maintains analysis state during checking
- Tracks file and module information
- Manages issue reporting

**common/issue.py**: Issue representation
- Standardizes security issue reporting
- Provides severity levels and categories
- Supports issue metadata and location tracking

**ast_rules/checkers/**: Individual pattern-based security checkers
- AST pattern matching rules for various vulnerability types
- Configurable blacklists and pattern definitions

AST Dataflow Checker Infrastructure
-----------------------------------

**ast_dataflow/core/runner.py**: AST dataflow checker orchestration
- Runs the full PyFlow analysis pipeline
- Runs its standalone AST dataflow engine without IPA/CPA/lifetime preparation
- Feeds analysis results to detectors

**ast_dataflow/detectors/**: AST dataflow detectors
- **taint.py**: Public taint detector API
- **_taint_detector.py** and supporting ``_taint_*`` modules: Taint propagation implementation
- Uses dataflow facts and function summaries rather than AST patterns

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

Local Supply-Chain Analysis
----------------------------

**supply_chain/**: Local-only supply-chain analysis package for Python packages.

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
- CycloneDX/OpenVEX, authenticated in-toto/SLSA provenance, Sigstore verification,
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

For security gates, prefer externally provisioned ``--osv-trusted-digest``
values over checksum files stored beside the database. Unsigned provenance and
DSSE envelopes without signatures cannot establish trust. Builder IDs remain
claims until the exact attestation has passed Sigstore identity verification.

Configuration and Testing
-------------------------

**ast_rules/core/config.py**: Configuration management
- Checker enable/disable settings
- Severity threshold configuration
- Custom rule definitions

**ast_rules/core/test_loader.py**: Test case management
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

Checker Reference
=================

.. toctree::
   :maxdepth: 2

   class-pollution
   capability


Stable rule identities and precision
-----------------------------------

Security rules now have unique fixed IDs, including separation from the dynamic
blacklist ID ranges. Registry collisions are rejected and reported as incomplete
checker loading. Extension checks with conflicting IDs moved into the B9000
range. Update baselines, ``nosec`` annotations, and CI policies by rule name:
old ambiguous IDs cannot safely remain aliases for every previous meaning.

.. csv-table:: Rule ID migration
   :header: "Old ID", "New ID", "Module", "Rule"
   :widths: 10, 10, 25, 55

   B102,B9001,bad_file_permissions,set_world_writable
   B701,B9048,command_injection,subprocess_run_shell_true_user_input
   B702,B9050,command_injection,subprocess_call_shell_true_user_input
   B703,B9053,command_injection,subprocess_popen_shell_true_user_input
   B704,B9055,command_injection,os_system_user_input
   B705,B9057,command_injection,os_popen_user_input
   B706,B9059,command_injection,popen2_shell_true
   B401,B9021,deserialization,pickle_with_user_input
   B402,B9022,deserialization,yaml_load_with_unsafe_loader
   B403,B9023,deserialization,marshal_deserialization
   B404,B9024,deserialization,jsonpickle_deserialization
   B405,B9025,deserialization,shelve_open_with_user_input
   B108,B9004,exception_handling,try_except_pass
   B113,B9007,exception_handling,try_except_generic
   B501,B9026,hardcoded_secrets,hardcoded_aws_access_key
   B502,B9027,hardcoded_secrets,hardcoded_github_token
   B503,B9028,hardcoded_secrets,hardcoded_google_api_key
   B505,B9029,hardcoded_secrets,hardcoded_private_key
   B507,B9030,hardcoded_secrets,hardcoded_generic_password_assignment
   B508,B9031,hardcoded_secrets,hardcoded_api_token_in_call
   B509,B9032,hardcoded_secrets,hardcoded_jwt_secret
   B612,B9043,huggingface_download,huggingface_unsafe_load
   B105,B9002,injection_wildcard,wildcard_injection
   B602,B9035,ldap_injection,ldap_initialize_and_bind_chain
   B603,B9036,ldap_injection,ldap_search_unsanitized_filter
   B604,B9037,ldap_injection,ldap_add_user_controlled_dn
   B605,B9038,ldap_injection,ldap_modify_user_controlled_dn
   B606,B9039,ldap_injection,dangerous_ldap_connection_string
   B107,B9003,logging_insecure,logging_insecure_listen
   B108,B9005,logging_insecure,logging_no_encryption
   B612,B9044,logging_insecure,logging_config_listen
   B509,B9033,paramiko_injection,paramiko_missing_host_key
   B201,B9008,path_traversal,open_file_with_user_input
   B202,B9009,path_traversal,pathlib_path_with_user_input
   B611,B9042,pytorch_load,pytorch_load_unsafe
   B510,B9034,snmp_security,snmp_weak_community
   B609,B9040,sql_injection,sql_injection_concatenation
   B610,B9041,sql_injection_enhanced,django_orm_extra_injection
   B701,B9049,ssrf,requests_user_url
   B702,B9051,ssrf,urllib_user_url
   B703,B9054,ssrf,internal_metadata_access
   B704,B9056,ssrf,socket_internal_connection
   B705,B9058,ssrf,no_url_validation
   B706,B9060,ssrf,dangerous_url_scheme
   B112,B9006,tarfile_unsafe,tarfile_unsafe_extraction
   B613,B9045,template_security,jinja2_autoescape_off
   B614,B9046,template_security,jinja2_mark_safe
   B615,B9047,template_security,jinja2_template_injection
   B702,B9052,template_security,use_of_mako_templates
   B303,B9012,weak_crypto,weak_cryptographic_key
   B304,B9014,weak_crypto,weak_hash_functions
   B301,B9010,xxe_vulnerabilities,lxml_parser_dtd_enabled
   B302,B9011,xxe_vulnerabilities,lxml_html_parser_entity_sub
   B303,B9013,xxe_vulnerabilities,lxml_fromstring_with_dangerous_parser
   B304,B9015,xxe_vulnerabilities,xml_dom_minidom_parse
   B305,B9016,xxe_vulnerabilities,xml_sax_parse_string
   B306,B9017,xxe_vulnerabilities,expat_parser_create
   B307,B9018,xxe_vulnerabilities,defusedxml_lxml_safe
   B308,B9019,xxe_vulnerabilities,lxml_xmlschema_validation
   B310,B9020,xxe_vulnerabilities,sax_parser_create

SQLAlchemy, Flask CSRF, and FastAPI URL checks require relevant API/framework
and route evidence. A computed filesystem path alone is not proof of user
control. Default JSON parsing models propagate input taint without treating the
parser itself as an execution sink; downstream dangerous uses remain checked.

Supply-chain audits recognize uv sdist and wheel hashes and retain every valid
artifact digest. Requirement and lock entries lacking license fields are not
reported as unlicensed distributions. Actual package metadata and root projects
remain subject to license checks, and root SPDX declarations survive lock merges.
