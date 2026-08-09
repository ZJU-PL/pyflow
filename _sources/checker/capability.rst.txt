Defensive Capability Analysis
=============================

PyFlow's defensive capability analysis identifies the security-relevant
authority exercised or exposed by Python applications and libraries. It is
built on the context-sensitive k-CFA pointer analysis, so capabilities retain
their identity through aliases, imports, calls, heap fields, containers,
closures, returns, yields, and external-library boundaries.

The analysis is intended for library review, dependency auditing, policy
generation, and research on open-world Python programs. It reports authority
flow rather than treating sensitive API names as isolated syntactic matches.

Capability Reports
------------------

Findings use four report kinds:

``direct``
   An analyzed operation calls, reads, or writes a modeled capability.

``indirect``
   A capability-bearing object crosses a boundary through an argument, public
   export, field store, return, yield, exception, closure, callback, spawned
   task or process, or serialization operation.

``runtime_guarded``
   Static analysis found an operation such as dynamic code execution or import
   whose deployment guarantee also depends on the protected CPython runtime.

``unsupported``
   The operation is deliberately rejected rather than silently approximated.

An empty result is authoritative only when its status is ``complete``.
Unresolved callees, translation failures, and exhausted fixpoint budgets make
the result ``partial`` and produce diagnostics.

Analysis Architecture
---------------------

The analysis has four cooperating layers:

#. The k-CFA solver constructs context-qualified points-to and call-graph
   information, including canonical access paths for unanalyzed modules.
#. Capability patterns classify sensitive calls, reads, and writes.
#. Carrier closure follows capabilities transitively through object fields,
   containers, closures, generators, and coroutines.
#. External-effect summaries describe callback invocation, retention,
   serialization, spawning, and argument or receiver return flow.

Argument-to-return and receiver-to-return summaries add pointer-flow edges to
the k-CFA solution. This preserves capability identity through wrappers and
fluent APIs instead of replacing it with an opaque external return object.

Command-Line Usage
------------------

Analyze a file or project:

.. code-block:: bash

   pyflow capabilities app.py
   pyflow capabilities project/ --entry app.py --format json
   pyflow capabilities project/ --entry app.py \
       --format sarif --output capabilities.sarif

Context sensitivity can be selected directly:

.. code-block:: bash

   pyflow capabilities app.py --context-depth 2
   pyflow capabilities app.py --context-policy 1c1o

Use ``--no-public-exports`` when only capability exercise is relevant and
library export exposure should not be reported.

Programmatic API
----------------

.. code-block:: python

   from pyflow.checker.capability import DefensiveCapabilityAnalysis

   result = DefensiveCapabilityAnalysis(
       k=1,
       report_public_exports=True,
   ).analyze_project(
       "src/package/__main__.py",
       project_path=".",
   )

   if result.status != "complete":
       for diagnostic in result.diagnostics:
           print(diagnostic.kind, diagnostic.message)

   for finding in result.findings:
       print(
           finding.capability,
           finding.report_kind.value,
           finding.escape_kind,
           finding.location,
       )

Capability Configuration
------------------------

The packaged model is stored at
``src/pyflow/config/capability/stdlib.json``. The top-level
``schema_version`` is currently ``1``. ``patterns`` classify operations by
access path, while ``effects`` describe open-world library behavior.

.. code-block:: json

   {
     "schema_version": 1,
     "patterns": [
       {
         "capability": "company.secrets.read",
         "category": "information",
         "operation": "call",
         "access_paths": ["company.vault.read_secret"]
       }
     ],
     "effects": [
       {
         "kind": "invoke_callback",
         "arguments": [0],
         "access_paths": ["company.plugins.register"]
       }
     ]
   }

Project-specific models can be appended without replacing the packaged model:

.. code-block:: bash

   pyflow capabilities app.py \
       --capability-model company-capabilities.json

Supported effect kinds are:

* ``return_argument``
* ``return_receiver``
* ``retain_argument``
* ``invoke_callback``
* ``spawn_callback``
* ``serialize_argument``

Each argument selector may be a zero-based positional index, a keyword name,
or ``"*"`` for every argument.

Protected Runtime
-----------------

``capability-run`` executes a script under a fail-closed CPython audit-hook
allow list:

.. code-block:: bash

   pyflow capability-run app.py \
       --allow file.read \
       --allow 'network.*' \
       --audit-log observed-capabilities.json

Known denied operations terminate with exit status ``126``. Audit hooks are
process-global and cannot be removed, so protected code should run in a fresh
process. The runtime guard is not an operating-system sandbox: hostile native
extensions require process isolation, restricted credentials, and an OS-level
sandbox.

Output Contract
---------------

JSON findings include the capability, category, operation, access path, source
location, report kind, context, trace, ``escape_kind``, and ``boundary``.
SARIF output includes the same analysis-specific fields under result
properties. CLI exit status is ``0`` for a complete clean result, ``1`` when
findings exist or analysis is partial, and ``2`` for invalid input or model
configuration.

Soundness Boundary
------------------

The static guarantee assumes that all relevant source modules are reachable
from the configured entry point, every authority-bearing host API is modeled,
and native or generated behavior is either rejected or covered by protected
execution. Unmodeled external calls conservatively expose their arguments;
they are never treated as silently safe.

For the detailed deployment assumptions, see
``src/pyflow/checker/capability/SOUNDNESS.md``.
