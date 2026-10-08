Defensive Capability Analysis
=============================

PyFlow's defensive capability analysis identifies the security-relevant
authority potentially exercised or exposed by Python applications and
libraries. It is built on the context-sensitive k-CFA pointer analysis, so
capabilities retain their identity through aliases, imports, calls, heap
fields, containers, closures, returns, yields, and external-library boundaries.

The analysis is intended for library review, dependency auditing, policy
generation, and research on open-world Python programs. It reports authority
flow rather than treating sensitive API names as isolated syntactic matches.
It is a static security-auditing tool with optional runtime observation. It
does not assign trust to components or verify an authorization policy.

A transfer is security-relevant only under a deployment-specific threat
model: which recipients are less trusted, which resources they cannot already
acquire, and which transfers are permitted. Returning ``os.system`` is not
itself an authority increase when the recipient can import ``os`` directly.

Capability Reports
------------------

Findings use four report kinds:

``direct``
   An analyzed operation may call, read, or write a modeled capability.

``indirect``
   A capability-bearing object potentially crosses a boundary through an
   argument, public export, field store, return, yield, exception, closure,
   callback, spawned task or process, or serialization operation. Callable returns, yields, and
   exceptions require explicit opt-in. These findings do not establish an
   unauthorized transfer or actual capability exercise.

``runtime_guarded``
   A compatibility label for operations such as dynamic code execution or
   import that need further review. It does not certify that a runtime guard
   is installed or provides confinement.

``unsupported``
   The operation is deliberately rejected rather than silently approximated.

``complete`` means no unknown, unsupported, or budget diagnostic was emitted;
it does not certify absence of vulnerabilities or unmodeled authority.
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

Use ``--no-public-exports`` to suppress library export exposure reports.
Use ``--report-callable-boundaries`` to include potential transfers through
returns, yields, and exceptions. These reports are disabled by default because
a callable boundary alone is not a trust boundary. Pointer propagation through
these boundaries remains active, so subsequent calls and external transfers
still retain capability identity.

Programmatic API
----------------

.. code-block:: python

   from pyflow.checker.capability import DefensiveCapabilityAnalysis

   result = DefensiveCapabilityAnalysis(
       k=1,
       report_public_exports=True,
       report_callable_boundaries=False,
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

Runtime Observation
-------------------

``capability-run`` observes classified CPython audit events and, by default,
denies known operations outside its allow list:

.. code-block:: bash

   pyflow capability-run \
       --allow file.read \
       --allow 'network.*' app.py

   pyflow capability-run --observe-only \
       --audit-log observed-capabilities.json app.py

An uncaught denial exits with status ``126``. Unclassified events are ignored
and are not logged. Audit hooks are process-global and cannot be removed
through the public API, so use a fresh process to manage their installation.
Python-level audit hooks are unsuitable for sandboxing malicious code, as the
`Python documentation <https://docs.python.org/3/library/sys.html#sys.addaudithook>`_
explains. A fresh process alone does not restrict hostile code; confinement
requires an independently enforced OS security boundary.

Output Contract
---------------

JSON findings include the capability, category, operation, access path, source
location, report kind, context, trace, ``escape_kind``, and ``boundary``.
SARIF output includes the same analysis-specific fields under result
properties. Indirect SARIF results use level ``note`` because they describe
potential exposure rather than a verified policy violation. CLI exit status
is ``0`` for a complete empty result, ``1`` when findings exist or analysis is
partial, and ``2`` for invalid input or model configuration.

Soundness Boundary
------------------

Static coverage depends on source reachability from the entrypoint, import
depth, solver semantics, and registry coverage. Access-path prefix reachability
is conservative and can overestimate authority obtainable from an object.
It does not prove member accessibility. Unmodeled external calls report relevant
arguments as potential transfers. Runtime observation does not establish
static coverage of native, generated, or reflective behavior.

For the detailed deployment assumptions, see
``src/pyflow/checker/capability/SOUNDNESS.md``.
