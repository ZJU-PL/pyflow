Case Studies and Precision Notes
================================

The original ``a3-python`` docs included many project-specific true-positive and
false-positive analyses. Those notes are worth preserving because they explain
what the package is trying to optimize for in real repositories.

What these notes are for
------------------------

These case studies are not API documentation. They are evidence about:

* which bug patterns survive strong filtering
* what kinds of false positives dominated earlier runs
* how targeted semantic improvements changed precision

They should be read as engineering guidance for future analysis work.

DeepSpeed-style precision analysis
----------------------------------

The original DeepSpeed notes highlighted a recurring semantic issue:

* method receiver parameters like ``self`` were being treated too much like
  ordinary nullable inputs

That led to obvious false positives such as ``NULL_PTR`` on ``param_0`` in
instance methods. The underlying lesson is broader than that one project:

* Python calling conventions, framework plumbing, and object-model guarantees
  can invalidate naive bytecode-level warnings

This is exactly the kind of gap that the more semantic detectors and contracts
are intended to close.

FLAML
-----

The FLAML case study in the original docs emphasized a useful pattern:

* once high-noise security-style findings are filtered out, the most credible
  remaining issues are often crash or edge-case robustness bugs

Examples called out there included:

* division by zero in normalization or aggregation code
* empty-collection edge cases
* missing required context keys in framework-style APIs

This aligns well with the current package structure, where crash summaries,
guards, and DSE replay are treated as first-class precision tools.

Qlib
----

The Qlib notes are valuable because they show both sides of the system:

* some headline security-looking findings were significantly mitigated once
  surrounding semantics were considered
* a small number of arithmetic crash bugs remained convincing, including
  DSE-validated divide-by-zero paths in backtesting/reporting code

The main lesson is that severity and exploitability depend heavily on context.
The subsystem therefore tries to preserve:

* raw semantic reachability information
* confidence/triage metadata
* optional filtering layers that incorporate contextual knowledge

GraphRAG
--------

The GraphRAG notes documented a large reduction in reported findings after
context-aware filtering. Most dropped reports fell into categories like:

* local CLI-tool misuse rather than remotely exploitable bugs
* template-injection patterns that were actually ``string.Template`` rather than
  Jinja2-style code execution surfaces
* path or archive warnings that were low-risk in a strictly local workflow

This is a good example of why ``fp_context.py`` and intent-aware filtering
exist: the same low-level pattern can mean very different things in a local CLI
tool, a library API, or a network-facing service.

Precision improvements that came directly from the notes
-------------------------------------------------------

Several original docs correspond directly to detector improvements or
documentation-worthy analysis heuristics:

Safe subscript classification
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``SAFE_SUBSCRIPT_DETECTION`` note explains why Python slicing and indexing
must be separated. That work reduces false ``BOUNDS`` alarms by recognizing:

* slices that clamp rather than raise
* safe patterns such as guaranteed-nonempty ``split()`` results
* dictionary lookups that belong to a different exception family

Type-based sanitizer reasoning
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``type_based_sanitizers`` note records another important shift:

* sanitization is not only about escaping strings
* converting into a restricted domain can be a proof obligation in itself

Examples include numeric conversion, path canonicalization, datetime parsing,
and IP-address validation.

Project-specific FP patterns
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The pattern-analysis notes also show the value of manually studying repeated
clusters of findings. Common examples included:

* framework-guaranteed non-``None`` parameters
* intentional guard exceptions that should not be reported as unexpected bugs
* config-validated divisors or dimensions

These analyses are a reminder that improving precision often starts by
identifying recurring semantic invariants in real code, then turning those into
contracts, guard recognizers, or specialized summaries.

How to use these case studies as a contributor
----------------------------------------------

When working on ``a3_python``, use these case-study themes as a checklist:

* is this bug class missing an obvious Python semantic guarantee?
* is there a framework or library contract that should suppress the warning?
* is the current result a real reachability claim, or only a pattern match?
* would DSE or summary refinement separate true bugs from contextual false
  positives here?

The package is at its best when those answers are encoded into reusable
analysis logic rather than left as one-off manual triage rules.
