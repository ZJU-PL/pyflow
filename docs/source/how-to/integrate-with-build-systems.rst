Integrate with Build Systems
============================

PyFlow can be integrated into CI/CD pipelines and build systems to run
analysis automatically on every change.

.. note::

   This guide is a work in progress.  For now, refer to the examples below
   and adapt them to your specific build system.

CI/CD Integration
-----------------

GitHub Actions
~~~~~~~~~~~~~~

.. code-block:: yaml

   # .github/workflows/pyflow.yml
   name: PyFlow Analysis
   on: [push, pull_request]
   jobs:
     analysis:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v4
         - uses: actions/setup-python@v5
           with:
             python-version: "3.10"
         - run: pip install -e .
         - run: pyflow security src/ --recursive
         - run: pyflow callgraph src/ --format json --output callgraph.json

GitLab CI
~~~~~~~~~

.. code-block:: yaml

   # .gitlab-ci.yml
   pyflow:
     image: python:3.10
     script:
       - pip install -e .
       - pyflow security src/ --recursive
       - pyflow callgraph src/ --format json --output callgraph.json

Pre-commit Hooks
----------------

Add PyFlow to your `.pre-commit-config.yaml`:

.. code-block:: yaml

   repos:
     - repo: local
       hooks:
         - id: pyflow-security
           name: PyFlow Security Check
           entry: pyflow security
           language: system
           files: \.py$

Makefile Integration
--------------------

Add PyFlow targets to your ``Makefile``:

.. code-block:: makefile

   .PHONY: pyflow-security pyflow-callgraph

   pyflow-security:
   	pyflow security src/ --recursive

   pyflow-callgraph:
   	pyflow callgraph src/ --format json --output callgraph.json

Output Formats for Automation
-----------------------------

For CI/CD pipelines, use machine-readable output formats:

.. code-block:: bash

   # JSON output for custom tooling
   pyflow security src/ --recursive --format json --output results.json
   pyflow callgraph src/ --format json --output callgraph.json

   # SARIF output for GitHub Code Scanning, GitLab SAST, etc.
   pyflow security src/ --recursive --format sarif --output results.sarif

See Also
--------

- :doc:`/cli` — Full CLI command reference
- :doc:`security-analysis` — Security analysis how-to
- :doc:`visualize-results` — Visualizing analysis output
