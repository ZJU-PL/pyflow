Bug Taxonomy
============

The original ``a3-python`` documentation described a broad, layered bug
taxonomy intended to support both precise reporting and technique selection.
That framing is useful here because ``pyflow.a3_python`` contains more than a
single flat list of detectors.

Core idea
---------

The taxonomy is not just naming. It helps answer three engineering questions:

* what kind of unsafe region is being checked?
* which summary or contract information matters most?
* which refinement or proof techniques are likely to reduce false positives?

Layered view
------------

The original notes grouped bug types into several broad layers.

Exception-based bugs
~~~~~~~~~~~~~~~~~~~~

These bugs are organized around runtime exception behavior and exception
families rather than only around syntax. Examples include:

* value and runtime errors
* file and permission failures
* exception-propagation or unhandled-exception style findings

Relevant code:

* ``unsafe/exception_bugs.py``
* ``semantics/crash_summaries.py``

Contract-based bugs
~~~~~~~~~~~~~~~~~~~

These are failures of expected preconditions, postconditions, representation
invariants, or substitutability constraints.

Examples from the original notes include:

* precondition violations
* postcondition violations
* invariant violations
* representation invariant failures
* Liskov-style contract violations

Relevant code:

* ``contracts/``
* ``barriers/kitchensink_taxonomy.py``

Temporal and ordering bugs
~~~~~~~~~~~~~~~~~~~~~~~~~~

These depend on operation order or lifecycle state:

* use before initialization
* use after close
* double close
* missing cleanup
* ordering violations
* concurrent modification or mutation-during-iteration

Relevant code:

* ``unsafe/iterator_invalid.py``
* ``unsafe/double_free.py``
* ``unsafe/memory_leak.py``
* ``unsafe/send_sync.py``
* ``unsafe/deadlock.py``

Data-flow bugs
~~~~~~~~~~~~~~

These are driven by how values move, whether checks are applied, and whether
derived state stays fresh.

Examples include:

* unvalidated input
* unchecked return values
* ignored exceptions
* partial initialization
* stale-value usage

Relevant code:

* ``semantics/*taint*.py``
* ``semantics/stale_counter_detector.py``
* ``semantics/subprocess_exit_code_detector.py``
* ``semantics/collection_desync_detector.py``

Protocol bugs
~~~~~~~~~~~~~

These track Python protocol expectations rather than simple local expressions.

Examples include:

* iterator protocol violations
* context-manager protocol violations
* descriptor protocol issues
* callable protocol misuse

These are particularly Python-specific because they often arise from implicit
language protocols rather than explicit API calls.

Resource bugs
~~~~~~~~~~~~~

These capture exhaustion or lifecycle failures involving memory, handles,
computation, or storage.

Examples include:

* memory exhaustion and unbounded growth
* CPU exhaustion and non-termination
* disk or handle exhaustion
* stack overflow

Relevant code:

* ``unsafe/non_termination.py``
* ``unsafe/stack_overflow.py``
* ``unsafe/memory_leak.py``
* ``barriers/ranking*.py``

Security bug families
---------------------

Alongside the taxonomy above, the package also contains a large dedicated
security detector set under ``unsafe/security/``.

Representative categories include:

* SQL and command injection
* SSRF, XSS, and template-related sinks
* deserialization and code execution risks
* filesystem and path-injection issues
* XML/XXE and regex-based denial of service
* crypto, config, and web application misuse

The security side is especially dependent on the contract and taint lattice
infrastructure.

Why this taxonomy matters in practice
-------------------------------------

The original project notes tied bug classes to different verification
strategies. That is still the right way to think about this package.

Examples:

* temporal/resource bugs often benefit from lifecycle summaries and state-based
  reasoning
* security bugs rely heavily on source/sink/sanitizer contracts
* crash bugs benefit from symbolic execution and local guard analysis
* termination and resource-exhaustion bugs lean on ranking or invariant
  synthesis

As a result, contributors should avoid treating all bug types as interchangeable
"findings". Their evidence models and proof strategies differ substantially.
