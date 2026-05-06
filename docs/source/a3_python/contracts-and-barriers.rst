Contracts and Barrier Reasoning
===============================

Why contracts matter here
-------------------------

``a3_python`` relies heavily on semantic contracts for library and framework
behavior. These contracts are not just convenience annotations. They provide
facts that later analyses can propagate and use to avoid false positives or to
prove safety conditions.

Examples include:

* return-value intervals
* non-zero or positive-result guarantees
* source, sink, and sanitizer behavior for taint analysis
* shape or relationship facts about structured objects

The implementation lives mainly under ``contracts/`` and is consumed by the
semantic, taint, and verification layers.

Deferred constraint propagation
-------------------------------

One of the central ideas from the original ``a3-python`` docs is that contract
facts can be useful long after the call site where they originate.

For example, a library call may establish that a result lies in a numeric range.
That range may not immediately prove anything, but it can become decisive much
later when the analyzer needs to decide whether an expression can be zero, can
be negative, or can flow into a dangerous sink.

In that sense, contracts act like deferred proof obligations or deferred safety
facts:

* the contract introduces a sound semantic constraint
* the abstract state carries that constraint forward
* later checks consume it to rule out or confirm an unsafe state

Barrier-style view of safety
----------------------------

The barrier-certificate notes in the original project framed Python bug finding
as a reachability problem:

* define an exact or analysis-level transition system for Python execution
* define an unsafe region for a bug class
* ask whether the reachable states intersect that unsafe region

The solver and verification subsystems then try to establish one of two things:

* reachability, by finding a bug witness or counterexample
* unreachability, by synthesizing an invariant, ranking argument, or
  barrier-style separating condition

This perspective explains why the subsystem contains both classic bug detectors
and more proof-oriented modules. They are solving the same problem from
different directions.

Where the theory lands in the code
----------------------------------

The barrier and proof stack is implemented across modules such as:

* ``barriers/invariants.py``
* ``barriers/cegis.py``
* ``barriers/ranking.py``
* ``barriers/ranking_synthesis.py``
* ``barriers/sos_safety.py``
* ``barriers/pdr_spacer.py``
* ``barriers/program_analysis.py``

The contract side of the interface is implemented across:

* ``contracts/schema.py``
* ``contracts/security.py``
* ``contracts/security_lattice.py``
* ``contracts/relations.py``
* ``contracts/stdlib.py``
* ``contracts/stdlib_module_relations.py``

In practice, the most important engineering point is that contract facts and
proof synthesis are coupled: richer contracts improve both bug suppression and
proof search.

Security-specific contract usage
--------------------------------

For security analyses, contracts help model:

* sources of untrusted or sensitive data
* sanitizers and type-based validation patterns
* sinks such as SQL, command execution, path/file operations, XML, SSRF, and
  web-facing output

This is why security support is split between ``contracts/`` and
``unsafe/security/``. The former encodes semantic knowledge; the latter uses
that knowledge to decide whether an unsafe pattern is actually reachable.
