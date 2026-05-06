Overview
========

What ``a3_python`` is
---------------------

``pyflow.a3_python`` is a specialized Python analysis subsystem with a different
focus from the main PyFlow optimization pipeline. Its core goal is to answer
questions like:

* can this Python program reach an unsafe state?
* can the analysis produce a concrete or symbolic counterexample?
* if no bug is found, can it synthesize evidence that the unsafe state is
  unreachable?

The package is designed around a three-way outcome model:

* ``BUG``: an unsafe state is reachable and a witness can often be produced
* ``SAFE``: the unsafe state is proven unreachable, often with an invariant or
  barrier-style proof object
* ``UNKNOWN``: neither a proof nor a bug witness is available

Major capabilities
------------------

The package contains several intertwined analysis families:

* symbolic and concrete execution over Python bytecode
* taint analysis for security bugs and dataflow-style findings
* crash and unsafe-state analysis for bug classes such as division by zero,
  null-like errors, iterator invalidation, panic-style termination, and
  resource misuse
* interprocedural propagation using call graphs and summaries
* dynamic symbolic execution and concolic replay for refinement
* invariant, ranking-function, and barrier-certificate synthesis for proving
  safety or termination

Compared with the rest of PyFlow, this subsystem is more explicitly oriented
toward verification and bug proving than toward compiler-style transformation.

Entry points
------------

The main programmatic and CLI entry points live here:

* ``pyflow.a3_python.analyzer``: high-level analysis orchestration
* ``pyflow.a3_python.cli``: command-line interface for scans, CI bootstrap,
  SARIF handling, and triage
* ``python -m pyflow.a3_python.cli --help``: module-style CLI invocation

The CLI exposes both a legacy direct-scan mode and explicit subcommands such as
``scan``, ``init``, ``triage``, and ``baseline``.

Typical workflow
----------------

At a high level, a run usually looks like this:

1. load Python files, modules, or projects into the package's frontend model
2. derive code objects, control flow, and entry points
3. run symbolic, taint, or interprocedural analyses
4. optionally refine results with DSE, concolic replay, or higher-cost
   verification passes
5. emit findings, proofs, SARIF, or triage-friendly output

Relationship to the original standalone docs
--------------------------------------------

The original ``a3-python`` project carried a large set of standalone Markdown
notes covering architecture, library contracts, barrier-certificate theory, and
true-positive case studies. This section brings the most relevant material into
PyFlow's Sphinx docs while keeping the content aligned with the package's
current location under ``src/pyflow/a3_python``.
