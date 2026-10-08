.. _how-to-security-analysis:

========================================
How to Perform Security Analysis
========================================

This guide explains how to use PyFlow's security analysis to find potential
vulnerabilities in your Python code.

When to Use Security Analysis
==============================

Use security analysis when you need to:

- Find potential security vulnerabilities
- Audit third-party code
- Ensure code follows security best practices
- Detect hardcoded credentials
- Identify unsafe function usage

Running Security Analysis
==========================

Basic security scan
-------------------

.. code-block:: bash

   pyflow security input.py

Full security analysis
----------------------

.. code-block:: bash

   pyflow security input.py --engine ast-dataflow

Specific security engines
-------------------------

Run with a specific analysis engine:

.. code-block:: bash

   pyflow security input.py --engine ast-scanner
   pyflow security input.py --engine ast-dataflow
   pyflow security input.py --engine ifds --sources input --sinks eval
   pyflow security input.py --engine cpg --framework flask

AST dataflow completion status
------------------------------

JSON and SARIF output from ``ast-dataflow`` includes ``status``, diagnostics,
precision reasons, and a bounded source-to-sink ``trace`` for each finding.
``complete`` means the fixed points converged without assumed or unsupported
behavior. ``partial`` means findings remain useful, but one or more dynamic
operations or user contracts crossed the documented soundness boundary.

Machine-readable execution contract
-----------------------------------

For scripts and benchmark runners, keep process execution separate from the
analysis result:

.. code-block:: bash

   pyflow security project/ --recursive --engine cpg \
       --format json --output report.json \
       --exit-code-policy report

With the ``report`` policy, exit code zero means PyFlow successfully emitted
the requested report. The report's ``status`` field communicates
``complete``, ``partial``, ``cancelled``, ``invalid``, or ``failed``; findings
and diagnostics remain available even when the analysis is partial. The
default ``findings`` policy retains the traditional scanner exit codes for
interactive and CI usage.

Available Security Checks
==========================

PyFlow performs the following types of security analysis:

Injection Attacks
-----------------

Detects potential SQL, command, and code injection vulnerabilities:

.. code-block:: python
   :caption: Vulnerable code

   # SQL Injection
   user_input = get_user_input()
   query = "SELECT * FROM users WHERE id = " + user_input

   # Command Injection
   user_file = get_user_input()
   os.system("cat " + user_file)

   # Code Injection
   user_code = get_user_input()
   eval(user_code)

Authentication Issues
---------------------

Detects hardcoded credentials and weak authentication:

.. code-block:: python
   :caption: Vulnerable code

   # Hardcoded password
   API_KEY = "sk-1234567890abcdef"

   # Weak cryptography
   import md5
   hashed = md5(password).hexdigest()

Dangerous Function Usage
-------------------------

Identifies use of potentially dangerous functions:

.. code-block:: python
   :caption: Vulnerable code

   # Pickle can execute arbitrary code
   import pickle
   data = pickle.loads(untrusted_data)

   # Yaml can execute arbitrary code
   import yaml
   data = yaml.load(untrusted_yaml)

Output Formats
==============

Text (default)
--------------

Human-readable format:

.. code-block:: bash

   pyflow security input.py --format text

Output:

.. code-block:: text

   Security Analysis Results:
   ───────────────────────────────────────

   [HIGH] SQL Injection (line 15)
     query = "SELECT * FROM users WHERE id = " + user_input

   [MEDIUM] Hardcoded API Key (line 23)
     API_KEY = "sk-1234567890abcdef"

   [LOW] Use of deprecated md5 (line 31)
     hashed = md5(password).hexdigest()

JSON (programmatic)
-------------------

For integration with other tools:

.. code-block:: bash

   pyflow security input.py --format json --output security_report.json

Output:

.. code-block:: json

   {
     "findings": [
       {
         "severity": "HIGH",
         "type": "sql_injection",
         "line": 15,
         "message": "Potential SQL injection vulnerability",
         "code": "query = \"SELECT * FROM users WHERE id = \" + user_input"
       },
       {
         "severity": "MEDIUM",
         "type": "hardcoded_credentials",
         "line": 23,
         "message": "Hardcoded API key detected",
         "code": "API_KEY = \"sk-1234567890abcdef\""
       }
     ],
     "summary": {
       "high": 1,
       "medium": 1,
       "low": 1
     }
   }

SARIF (CI/CD integration)
--------------------------

For integration with CI/CD systems:

.. code-block:: bash

   pyflow security input.py --format sarif --output security_report.sarif.json

Understanding Findings
======================

Severity Levels
---------------

- **CRITICAL**: Immediate action required
- **HIGH**: Significant risk, fix soon
- **MEDIUM**: Moderate risk, plan fix
- **LOW**: Minor risk, consider fix
- **INFO**: Informational, no action needed

Remediation Examples
====================

SQL Injection
-------------

**Vulnerable:**

.. code-block:: python

   user_id = request.args.get("id")
   query = "SELECT * FROM users WHERE id = " + user_id

**Fixed:**

.. code-block:: python

   import sqlite3

   user_id = request.args.get("id")
   conn = sqlite3.connect("database.db")
   cursor = conn.cursor()
   cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

Hardcoded Credentials
---------------------

**Vulnerable:**

.. code-block:: python

   API_KEY = "sk-1234567890abcdef"

**Fixed:**

.. code-block:: python

   import os

   API_KEY = os.environ.get("API_KEY")
   if not API_KEY:
       raise ValueError("API_KEY not configured")

Deprecated Cryptography
-----------------------

**Vulnerable:**

.. code-block:: python

   import hashlib

   hashed = hashlib.md5(password).hexdigest()

**Fixed:**

.. code-block:: python

   import hashlib

   hashed = hashlib.sha256(password).hexdigest()

Integrating with CI/CD
======================

GitHub Actions
--------------

Create a workflow file:

.. code-block:: yaml
   :caption: .github/workflows/security.yml

   name: Security Analysis

   on: [push, pull_request]

   jobs:
     security:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v3
         - name: Set up Python
           uses: actions/setup-python@v4
           with:
             python-version: '3.10'
         - name: Install PyFlow
           run: pip install pyflow
         - name: Run Security Analysis
           run: pyflow security . --format sarif --output security_report.sarif.json
         - name: Upload SARIF
           uses: github/codeql-action/upload-sarif@v2
           with:
             sarif_file: security_report.sarif.json

GitLab CI
---------

Create a CI configuration:

.. code-block:: yaml
   :caption: .gitlab-ci.yml

   security_scan:
     image: python:3.10
     script:
       - pip install pyflow
       - pyflow security . --format sarif --output security_report.sarif.json
     artifacts:
       reports:
         sarif: security_report.sarif.json

Troubleshooting
===============

Issue: False positives
----------------------

- Use ``--exclude`` to skip known safe patterns
- Add comments to suppress specific warnings
- Configure sources/sinks/sanitizers with ``--sources``, ``--sinks``, ``--sanitizers`` flags

Issue: Missing findings
-----------------------

- Ensure all files are analyzed
- Check for syntax errors that prevent full parsing
- Use ``--analysis all`` for comprehensive analysis

Issue: Performance issues
-------------------------

- Use ``--exclude`` to skip test files
- Analyze specific modules instead of the whole project
- Use incremental analysis for large projects

Shared checker infrastructure
=============================

Engine-independent taint domains and refinement policies live in
``pyflow.checker.common.taint``. AST dataflow and CPG use
``pyflow.checker.common.diagnostics.CheckerDiagnostic`` for precision and
completion diagnostics. Native IFDS findings retain their solver-specific
witnesses and are normalized in ``pyflow.checker.ifds.reporting``.

Formatting is separate from detection. Shared JSON/YAML report collection,
ordering, and SARIF severity/location/document utilities live in
``pyflow.checker.formatters``. These modules can be imported without loading
an engine. Engine-specific fields and code-flow evidence remain available.

For native CPG finding exports, use the formatter functions directly:

.. code-block:: python

   from pyflow.checker.formatters.cpg import findings_to_sarif
   from pyflow.checker.formatters.json import findings_json

   result = engine.analyze()
   document = findings_to_sarif(
       result.findings, artifact_uri="input.py", tool_name="my-analysis"
   )
   serialized_findings = findings_json(result.findings)

These functions replace ``CPGTaintEngine.to_sarif`` and ``to_json``.
``finding_to_sarif`` and ``rule_to_sarif`` in the same CPG formatter module
replace the SARIF methods on native finding and rule objects. Imports of the
former AST-local domain/refinement types should use ``checker.common.taint``
and ``checker.common.taint.refinement``. No compatibility modules are retained.

SARIF severity conversion now agrees across engines: low maps to ``note``,
medium to ``warning``, and high/critical to ``error``. Unknown source lines in
native CPG exports use line 1. CLI exit policy, report completion status,
JSON/YAML Issue fields, and engine-specific evidence are preserved.

IFDS project defaults and multiple entries
-----------------------------------------

Analyze a project without selecting a function:

.. code-block:: bash

   pyflow security project/ --engine ifds --format json
   pyflow security project/ --engine ifds --entry app.py --entry cli.py --format sarif

IFDS entry discovery uses the strongest available evidence tier: packaging
metadata (``project.scripts``, GUI scripts, entry-point groups, Poetry scripts,
``setup.py`` or ``setup.cfg``), then package ``__main__.py`` files, then root
filename conventions such as ``main.py`` and ``app.py``. All distinct files in
that tier are analyzed. It does not import the project to discover entries.
Projects without candidates must provide ``--entry``. A file target is its own
entry; ``--entry`` is reserved for directory targets.

Each entry receives an independent analysis session and solver budget. Analysis
includes its module body and file-local procedures under the existing file
entry policy. Packaging metadata identifies files rather than selecting just
the function named by a console script. Cross-file callees are followed through
the call graph; ``--recursive`` includes nested source files in the input set.

Put reusable defaults in ``project/pyflow.json``:

.. code-block:: json

   {
     "entry": ["app.py", "cli.py"],
     "analysis": "taint",
     "frameworks": ["stdlib"],
     "sources": ["input"],
     "sinks": ["eval"],
     "solver_options": {
       "max_seconds": 30,
       "max_path_edges": 100000,
       "max_call_string_depth": 3
     }
   }

Omit ``entry`` to discover entries automatically. CLI options override the
corresponding configuration values. ``--config other.json`` replaces the
automatically loaded file. File targets load ``pyflow.json`` from their parent;
directory targets load it from the target root. There is no ancestor search.
Entry paths are relative to the project root, while ``registry_path`` entries
are relative to the configuration file. Automatic loading applies to IFDS.

Single-entry reports retain their existing structure. Multi-entry JSON adds
``entries`` and ``entry_results`` with each entry's findings, statistics, and
completion status. Top-level findings are deduplicated, while the aggregate
status retains failures, invalid configurations, and partial analyses. JSON,
text, SARIF and existing exit-code policies use that aggregate result. Budgets
apply per entry, so total project analysis can take longer than ``max_seconds``.

For an executable custom analysis example, see :ref:`ifds-plugin`.
