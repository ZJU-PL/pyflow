.. _how-to-security-analysis:

======================
How to Perform Security Analysis
======================

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

   pyflow security input.py --engine cpa

Specific security engines
-------------------------

Run with a specific analysis engine:

.. code-block:: bash

   pyflow security input.py --engine ast-scanner
   pyflow security input.py --engine cpa
   pyflow security input.py --engine ifds --function main --sources input --sinks eval
   pyflow security input.py --engine cpg --framework flask

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
- Configure custom rules in pyflow.toml

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
