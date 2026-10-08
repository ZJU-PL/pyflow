.. _ifds-plugin:

Write your first IFDS analysis
==============================

Run ``examples/ifds_plugin.py`` after installing PyFlow:

.. code-block:: bash

   python examples/ifds_plugin.py

It analyzes a bundled program containing ``helper()``, an unused function, and
one call to ``helper``. Expected output:

.. code-block:: text

   Analyzed: ifds_demo.py
   Reachable functions: helper

To analyze your own file, pass its path:

.. code-block:: bash

   python examples/ifds_plugin.py your_program.py

Read the example from top to bottom
----------------------------------

``VisitedFunctions`` defines the analysis. Its domain consists of immutable,
hashable function-name strings and a separate ``ZERO`` sentinel. The domain is
finite because the loaded graph has finitely many function names.

``initial_seeds`` starts ``ZERO`` at the file's declared module entry. The four
flow functions describe what happens to one fact at a time:

* ``normal_flow`` keeps facts across local CFG edges.
* ``call_flow`` generates the callee's name from ``ZERO`` and keeps ``ZERO``
  so later calls can generate more names.
* ``return_flow`` brings the callee's facts back to the matching return site.
* ``call_to_return_flow`` preserves existing facts through the call bypass.

Returning ``()`` would kill a fact. The base class does this by default, so
omitting a flow function can stop propagation. These facts describe path
history; an analysis of local variables needs argument and return-value binding
instead. Helpers are available in ``pyflow.analysis.ifds.core.transfers``.

``analyze_file`` loads the source, prepares the graph, and runs the solver.
``main`` collects function-name facts with ``result.facts_at(node)`` and prints
them, excluding ``ZERO``. This separation lets tests run the analysis without
using its command-line interface.

Add the analysis to a pass pipeline
----------------------------------

Once the standalone analysis is clear, wrap it in an ``AnalysisPass``. With
``VisitedFunctions`` imported from your plugin module:

.. code-block:: python

   from pyflow.analysis.ifds.core.solver import IFDSSolver
   from pyflow.application.passes.base import AnalysisPass, PassResult
   from pyflow.application.passes.manager import PassManager

   class VisitedFunctionsPass(AnalysisPass):
       def __init__(self, session):
           super().__init__("visited_functions")
           self.session = session

       def run(self, compiler, program):
           result = IFDSSolver().solve(VisitedFunctions(self.session))
           return PassResult(
               success=result.is_complete, changed=False, data=result,
               error=result.termination_reason,
           )

   manager = PassManager(enable_caching=False)
   manager.register_pass(VisitedFunctionsPass(session))
   passes = manager.run_passes(session.compiler, session.program, ["visited_functions"])
   result = passes["visited_functions"].data

Here ``session`` is the prepared session returned by ``analyze_file``. This
wrapper uses that session's graph; construct a fresh session and pass after
source or IR changes. Production passes should declare analysis dependencies
and rebuild their adapters when inputs are invalidated.

Interpret and test the result
-----------------------------

A reported name means some modeled path can call the function, not that every
execution will. Unresolved calls cannot reveal their callees; duplicate display
names share one fact in this teaching example. Use stable procedure identities
for a production domain.

Inspect ``result.is_complete``, ``result.termination_reason``, and
``session.diagnostics`` before treating an absent name as meaningful. Solver
completion alone does not certify complete source modeling.

Run the example's regression tests:

.. code-block:: bash

   python -m pytest -q tests/analysis/ifds/test_plugin_tutorial.py

They check reachable and unused functions, facts returned to the module exit,
the default command-line output, and the pass wrapper above. When extending the
analysis, add cases for branches, nested calls, recursion, and killed facts.
