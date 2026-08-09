Class Pollution Analysis
========================

PyFlow's class-pollution detector is an independent relational analysis.  It
uses the generic IFDS solver and flow-sensitive heap infrastructure, but it
does not use ``TaintFact``, ``TaintConfiguration``, or ``analyze_taint``.
The legacy ``B701``--``B706`` AST rules remain a separate fast prefilter.

The public API is explicit about proof strength:

``pollutable-object``
   A controlled key reaches a reflective write and the target is correlated
   with a dynamic attribute/item traversal or an explicit magic-object path.
   Plain ``setattr(obj, key, value)`` without this target proof is not reported.

``gadget-reachable``
   The proven object path reaches a high-impact reflective namespace such as
   ``__globals__``, ``__builtins__``, ``__code__``, or ``__subclasses__``.
   These findings are ranked above a generic pollutable-object primitive.

Architecture
------------

The implemented analysis combines:

* dedicated ``INPUT``, ``ROOT_OBJECT``, and ``TARGET_OBJECT`` facts;
* origin correlation between a controlled key and the dynamic object path it
  selects;
* flow-sensitive heap locations and attribute/item access paths;
* interprocedural call/return propagation, including recursive helpers;
* bounded self-recursion summaries for recursive dictionary/object merge
  functions even when Python call-graph construction misses the self edge;
* inferred parameter roles, separating controlled structured input from root
  objects used by reflective reads and writes;
* a finite-height key-language domain with unknown, finite-set, and proven-safe
  states;
* branch-sensitive dunder-prefix and literal-allowlist refinement, plus
  configurable sanitizer models;
* ``getattr``, ``operator.getitem``, ``setattr``, item assignment,
  ``vars()``, ``__dict__`` and namespace-update semantics;
* summaries for ``operator.attrgetter``, ``operator.itemgetter``,
  ``inspect.getattr_static``, ``eval``, ``functools.reduce`` getter helpers,
  bound ``__getattribute__``/``__getitem__`` and
  ``__setattr__``/``__setitem__`` protocols, and walrus assignments hidden
  inside comprehensions;
* controlled-value classification for severity ranking.

This separation avoids a common unsound shortcut: scalar taint on a key is a
necessary condition for class pollution, but it does not prove that the target
object can reach class metadata or that the modified field affects behavior.

Programmatic use
----------------

.. code-block:: python

   from pyflow.checker.class_pollution import (
       ClassPollutionConfiguration,
       analyze_class_pollution,
   )

   result = analyze_class_pollution(
       adapter,
       ClassPollutionConfiguration(source_names=frozenset({"input"})),
       entry_nodes=entry_nodes,
   )

   for finding in result.findings:
       print(finding.proof_level, finding.sink_name)

Command line
------------

.. code-block:: bash

   pyflow security app.py --engine ifds --analysis class-pollution \
       --entry app.py --format sarif

Use ``--sources`` to add application-specific input APIs and ``--sanitizers``
to model a key validator that enforces an allowlist.

Evaluation plan
---------------

The implementation is designed to exceed a scalar-taint formulation, but a
state-of-the-art claim remains an empirical result.  Evaluate it against the
Pyrl micro-benchmark and confirmed-vulnerability collection, reporting
end-to-end vulnerability recall, precision on benign merge utilities, time,
peak memory, and ablations for heap refinement, key languages, guard reasoning,
interprocedural propagation, and gadget ranking.
