Minimal Intermediate Representation (MIR)
=========================================

``pyflow.ir.mir`` implements the seven-instruction intermediate representation
presented in *MIR: A Formal and Minimal Intermediate Representation for Rigorous
Python Program Analysis*, Hakjoo Oh's IFIP WG 2.4 presentation, March 2026
(``ifip26.pdf``, especially slides 8--10). A native PyCG-style call-graph engine
consumes this representation in ``pyflow.analysis.callgraph.pycg_mir``.

This implementation adds a separate representation to PyFlow. Existing CFG,
GIR, constraint-based call-graph analysis, and the optional upstream PyCG
adapter retain their APIs and defaults. The command-line default is still
``--algorithm simple``; select ``pycg-mir`` explicitly to use the new engine.

Quick Start
-----------

Install the regular PyFlow package; no optional ``pycg`` dependency is needed::

    pip install -e .
    pyflow ir example.py --dump-mir --dump-output out/
    pyflow ir example.py --dump-mir --dump-format json --dump-output out/
    pyflow callgraph example.py --algorithm pycg-mir
    pyflow callgraph project/ --entry src/app.py --algorithm pycg-mir

The IR command writes ``out/example_mir.text`` or
``out/example_mir.json``. A qualified scope can be selected with
``--dump-mir example.worker``. An unqualified name is accepted when it resolves
to exactly one scope; an ambiguous name produces an error listing the matches.
DOT output is available with ``--dump-format dot``. Recursive directory dumps
preserve relative source directories beneath ``--dump-output``.

MIR-only dumps lower source directly. They do not execute target code or invoke
PyFlow's runtime extraction pipeline. Local dependencies are read as source
when the lowering front end resolves imports.

Runnable Example
----------------

``examples/mir/callbacks.py`` combines a higher-order ``apply`` function with
``Callback.__add__`` and a subclass's ``PreferredCallback.__radd__``. Running it
with CPython checks that the computed result is 5. The MIR compiler exposes
the implicit operator dispatch as calls. The operator returns a function value,
which the native solver propagates through ``apply``::

    python examples/mir/callbacks.py
    pyflow callgraph examples/mir/callbacks.py --algorithm pycg-mir
    pyflow ir examples/mir/callbacks.py --dump-mir callbacks.PreferredCallback.__radd__ --dump-output out/

The call graph includes ``callbacks.apply -> callbacks.leaf`` and
relationships from module code to the operator methods. The chosen
flow-, path-, and context-insensitive abstraction can include additional
edges. Selecting one scope for a dump helps inspect user code separately from
the larger set of explicit runtime helper CFGs in a whole-program dump.

Python API
----------

The source-to-MIR and MIR-to-analysis stages can be used independently:

.. code-block:: python

    from pyflow.ir.mir import lower_source, format_program
    from pyflow.analysis.callgraph.pycg_mir import analyze_program

    source = """
    def leaf():
        pass

    def apply(callback):
        return callback()

    apply(leaf)
    """

    program = lower_source(source, module_name="example")
    print(format_program(program))
    data = program.to_dict()  # JSON-serializable MIR, not Python AST nodes

    result = analyze_program(program, raise_on_truncation=True)
    graph = result.call_graph.get()
    assert "example.leaf" in graph["example.apply"]
    print(result.converged, result.iterations)
    print(result.diagnostics)

For file input, use ``lower_file(path, project_root=None)``. The optional project
root supplies the import-resolution boundary. For the existing PyFlow
``CallGraph`` interface, the convenience wrappers are also exported at package
level:

.. code-block:: python

    from pyflow.analysis.callgraph import (
        extract_call_graph_pycg_mir,
        analyze_file_pycg_mir,
    )

    graph = extract_call_graph_pycg_mir(source)
    report = analyze_file_pycg_mir("example.py")

``lower_source`` uses ``__main__`` as its default module name.
``lower_file`` derives a module name from the file and project layout. Calls,
methods, and nested functions are reported using qualified scope names.
``extract_call_graph_pycg_mir`` accepts ``source_path`` for source context;
the supplied ``source_code`` remains the authoritative entry source.

Core Representation
-------------------

A ``Program`` has an entry CFG name and a mapping ``cfgs`` from names to CFGs.
Each CFG has instruction nodes, explicit successor edges, and entry/exit
nodes. Python control flow becomes graph structure; it does not add an eighth
instruction. Source filenames and locations remain attached for diagnostics.

.. list-table:: The seven core instructions
   :header-rows: 1
   :widths: 23 77

   * - Instruction
     - Meaning
   * - ``Skip``
     - Leave the state unchanged; useful for CFG joins and exits.
   * - ``Assume(condition)``
     - Constrain a CFG path using a side-effect-free expression.
   * - ``Alloc(target, value)``
     - Allocate a value in a fresh memory location and bind the target name.
   * - ``Bind(target, source)``
     - Make the target l-value refer to the same location as the source l-value.
   * - ``Env(target)``
     - Expose the current environment as a first-class value.
   * - ``Delete(target)``
     - Delete a variable, object field, or container reference.
   * - ``Call(target, function, args, kwargs)``
     - Invoke a closure with explicit positional and keyword argument containers.

Allocation and binding are distinct. For example, a Python assignment of a new
literal allocates storage, while assigning an existing object aliases that
storage. Lists and dictionaries store references, so copying a reference does
not copy the object. Attribute references use an l-value plus a key expression.

Expressions are side-effect-free and include primitive literals, l-values,
object/list/dictionary construction, lambdas, logical negation, length, and
primitive operations. Operations that can invoke Python user code must be
lowered into explicit ``Call`` instructions. In particular, Python operator
dispatch and ordinary calls are not left as nested Python AST expressions for
the analysis to reinterpret.

A lambda refers to its CFG and names the packed positional arguments, packed
keyword arguments, parent environment, and return binding. The closure captures
the parent environment; a call creates the callee environment. This supports
function values and lexical captures without an AST-specific callback resolver
in the analysis engine.

Class method-resolution order is computed by an emitted C3 merge. The direct
bases and existing base MROs are runtime references, so aliases and dynamically
selected bases participate in the same generated CFG. The merge keeps separate
head indices and does not mutate inherited MRO lists. Duplicate bases, class
cycles, and inconsistent local precedence set the modeled ``TypeError`` state.
No host ``type.mro`` call supplies an MRO to the interpreter or analyzer.

Text, JSON, and DOT dumps are deterministic. JSON dumps expose the core program
model and CFG edges, so the output can be inspected without importing Python
objects from the analyzed project. A scoped dump is an inspection view of that
CFG; references to other CFGs may point outside the selected view.

Reloading and Analyzing MIR JSON
-------------------------------

``program_from_dict`` and ``program_from_json`` reconstruct a program without
access to its Python source. For example, after producing a whole-program JSON
dump with ``--dump-mir --dump-format json``:

.. code-block:: python

    from pathlib import Path
    from pyflow.ir.mir import program_from_json
    from pyflow.analysis.callgraph.pycg_mir import analyze_program

    program = program_from_json(Path("out/example_mir.json").read_text())
    result = analyze_program(program, raise_on_truncation=True)
    print(result.call_graph.get())

The decoder accepts the exact version-1 schema emitted by ``Program.to_dict``.
It checks instruction and expression kinds, field types, primitive operators,
node identifiers, CFG edges, and lambda-body references. Unknown fields,
duplicate JSON object keys, unsupported versions, and malformed graphs raise
``MIRValidationError``. A fixed constructor table decodes the data; no named
class or payload supplied in the JSON is imported or executed. A scoped CFG
dump is an inspection artifact and is not a complete reloadable program.

Concrete Reference Semantics
----------------------------

``MIRInterpreter`` and ``interpret`` execute the core memory semantics. They
maintain explicit addresses, reference containers, environments, and captured
closures. MIR list indices are one-based, as in the presentation; Python
indexing therefore has to be translated by the source front end.

The following directly constructed program illustrates why ``Alloc`` and
``Bind`` are separate instructions:

.. code-block:: python

    from pyflow.ir.mir import (
        Alloc, Bind, CFG, Literal, Node, Program, Skip, Var, interpret,
    )

    cfg = CFG(
        name="example",
        nodes={
            0: Node(0, Skip(), (1,)),
            1: Node(1, Alloc("x", Literal(7)), (2,)),
            2: Node(2, Bind(Var("alias"), Var("x")), (3,)),
            3: Node(3, Alloc("copy", Var("x")), (4,)),
            4: Node(4, Skip()),
        },
        entry=0,
        exit=4,
    )
    program = Program(cfgs={"example": cfg}, entry="example")
    program.validate()
    execution = interpret(program)
    assert execution.address("x") == execution.address("alias")
    assert execution.address("x") != execution.address("copy")
    assert execution.value("copy") == 7

The interpreter checks graph structure before execution. Missing references,
invalid primitive operations, invalid list indices, and infeasible paths have
explicit error types. More than one feasible successor raises
``NondeterministicControlFlow`` instead of selecting an arbitrary branch.
Instruction and call-depth limits bound execution. This is a reference
interpreter for the core MIR language, not a replacement for CPython or an
implicit implementation of all Python builtins.

PyCG Analysis Over MIR
---------------------

The native engine follows the assignment-graph approach described by PyCG:
collect value-flow relationships, repeatedly propagate possible definitions
through assignments and calls, and derive call edges from resolved callable
values. This corresponds to the flow-, path-, and context-insensitive pointer
analysis used for MirCG in slide 14 of the supplied presentation.

The analysis operates on MIR instructions and expressions. It does not delegate
to the legacy Python-AST call-graph engine, import the optional PyCG package, or
read expected ``callgraph.json`` fixture files. Keeping the solver independent
of the Python AST also permits analysis of MIR built directly by clients.

The fixed point accounts for the following relationships:

* ``Alloc`` introduces abstract values for allocation sites, including closures
  and reference containers.
* ``Bind`` propagates references between names and fields. Aliases share the
  abstract objects reached through those references.
* ``Env`` and closure values connect lexical environments and captured names.
* Calls propagate packed actual arguments into callee environments and return
  values back to the caller. Newly discovered callable values can add call
  edges in later iterations.
* Field and container accesses propagate callable values stored in objects,
  lists, and dictionaries.

Flow insensitivity deliberately merges assignments from different program
points. Path insensitivity merges alternative CFG paths. Context insensitivity
shares each function's abstract state across callers. These choices can
produce extra edges; they are algorithm properties, not a promise that all
Python behaviors have been modeled. Deletion cannot generally remove old
points-to facts in a monotone, flow-insensitive analysis.

Generated protocol helpers are subject to the same approximation. For example,
merging callable-object and bound-method dispatch branches can join receiver
arguments into ordinary callback arguments, introducing extra edges or apparent
self-calls. The engine does not use hidden Python-AST refinements to remove
such edges. The returned graph therefore needs to be interpreted together with
the selected abstraction and available library models.

Compiler-generated helper CFGs carry Python protocol dispatch in MIR. The
default call graph reports user-visible relationships across these helpers;
``analyze_program(program, include_synthetic=True)`` can retain them for
inspection. Recursive calls remain present as self-edges in the native result.

As in PyCG, encountered source function definitions are analyzed even if no
caller has yet resolved to them. Set ``analyze_all_functions=False`` to analyze
only the entry CFG and resolved callees. Synthetic helper bodies always
require an actual MIR call.

``analyze_program`` returns a ``PyCGMIRResult`` containing ``call_graph``,
``assignment_graph``, ``call_sites``, ``reachable_cfgs``, ``diagnostics``,
``unresolved_calls``, ``iterations``, and ``converged``. Its ``truncated``
property reports whether
the iteration bound was reached before a fixed point. The default bound is
256 iterations; pass ``max_iterations`` to change it, ``None`` to iterate
without a fixed iteration bound, or
``raise_on_truncation=True`` when a partial result is unacceptable. The source
wrapper attaches the result to ``graph.analysis_result`` for callers that need
these details alongside the usual ``CallGraph`` interface.

A bounded run that does not converge emits ``PyCGMIRConvergenceWarning``.
Strict mode raises ``PyCGMIRConvergenceError`` and exposes the partial analysis
on the exception's ``result`` attribute.

Assignment-graph edges point from a reference to its possible sources or
values: for example, ``scope::name`` may point to an allocation label such as
``@alloc:scope:node``. Binding dependencies point from the assigned target to
the source reference. Field references have their own labels. The graph also
contains saturated points-to and closure-target edges; container containment
does not turn the container itself into an alias of its elements.

Scope and Limitations
---------------------

The current Python front end covers the following areas. Support for a syntax
form does not imply that every builtin, library call, or Python protocol used
inside it has a complete model.

.. list-table:: Source lowering coverage
   :header-rows: 1
   :widths: 24 76

   * - Area
     - Implemented lowering
   * - Values and containers
     - Boolean, integer, and string literals; ``None`` and ``NotImplemented``;
       lists, tuples, sets, dictionaries, references, and sequence/assignment
       unpacking.
   * - Functions
     - Functions, lambdas, closures, decorators, default arguments,
       positional-only and keyword-only parameters, and packed ``*args`` /
       ``**kwargs`` calls.
   * - Control flow
     - Conditional expressions and statements, short-circuit Boolean
       operations, loops, ``break`` / ``continue``, returns, exceptions,
       ``try`` / ``except`` / ``finally``, ``with``, and container comprehensions.
   * - Objects and dispatch
     - Classes, C3 inheritance order, callable objects, ordinary and reflected
       operators, attribute access, method binding, descriptors, and supported
       special-method protocols.
   * - Generators
     - Lazy generator functions and expressions, persistent suspended frames,
       ``yield``, ``yield from``, ``send``, and generator return values carried
       by ``StopIteration.value``.
   * - Modules
     - Statically resolved local Python modules and package imports, including
       cyclic imports, read from source without execution.

Explicitly unsupported source includes float/bytes/complex literals, slices,
dictionary-display unpacking (``{**mapping}``), async syntax, f-strings,
pattern matching, custom metaclasses, and class-definition keyword arguments.
Imports outside the supported local module graph require a model and otherwise
raise ``LoweringError``. These errors include source filenames and locations
where available. Lowering is intentionally separate from core MIR: the core
can represent additional behavior when a client supplies an appropriate
explicit translation.

Some accepted syntax has omitted runtime effects. Type annotation expressions
and ``__annotations__`` storage are not modeled: annotations do not trigger
calls in the lowered program. ``__future__`` directives are accepted but do not
select alternate language semantics.

Builtin models also have deliberate limits:

* Generator ``throw`` and ``close`` methods are not modeled. Ordinary
  iteration, suspension, ``send``, and ``yield from`` delegation are supported.
* ``print`` is a no-output model returning ``None``. Output behavior and
  implicit string-conversion callbacks are not represented by this stub.
* ``range`` materializes its values eagerly. Large ranges can therefore cost
  substantially more memory and interpreter steps than CPython's lazy range
  objects.
* Dictionaries use equality-based key lookup instead of a hash table. This
  does not reproduce hashing callbacks or every hashability rule. Dictionary
  views are materialized eagerly rather than remaining live views.
* Only installed explicit models populate the MIR builtin environment. A
  Python builtin without a model can currently appear as a modeled
  ``NameError`` at runtime; successful lowering alone does not establish that
  all of the program's builtin behavior was modeled.

The interpreter's exception state is part of the MIR program memory. A
modeled Python exception is not necessarily a host Python exception raised by
``interpret``. Clients inspecting concrete runs must check that state in
addition to MIR structural or execution errors.

.. code-block:: python

    from pyflow.ir.mir import interpret, lower_source

    execution = interpret(lower_source("value = 7"))
    builtins = execution.value("$builtins").fields
    state = execution.memory[builtins["$state"]].fields
    assert state["exception"] == builtins["None"]

The instruction model follows the supplied MIR syntax and separation of
memory, references, environments, and closures. The Python lowering front end
and library models are an implementation of selected Python behavior; the
presentation does not supply the authors' full compiler, runtime, or benchmark
suite. This implementation does not claim to reproduce their published
benchmark results or to prove soundness for all Python programs.

The frontend reports explicit lowering diagnostics for syntax it rejects.
Accepted syntax remains subject to the modeling boundaries above. Native
extension behavior, runtime code generation, arbitrary reflection, and external
libraries require additional models. Dynamic keys, merged heap objects, and context-insensitive callbacks
can reduce precision. Review ``result.diagnostics`` and convergence before
using a graph as evidence of completeness.

Explicit runtime expansion can produce large MIR programs even from short
source files. Interactions between operator, attribute, and higher-order call
helpers can substantially increase the assignment graph and analysis time.
This implementation does not claim performance parity with upstream PyCG;
use the convergence and iteration information when evaluating a workload.

The existing ``--context-sensitive``, ``--context-depth``,
``--allocation-site-sensitive-instances``, ``--all-scopes``,
``--as-graph-output``, ``--fixpoint-max-iterations``, and
``--no-fixpoint-warning`` flags remain specific to the constraint algorithm.
They are rejected with ``pycg-mir``. MIR analysis exposes its own result and
iteration options through the direct API. The ``--skip-stdlib`` and
``--no-skip-stdlib`` flags affect only constraint analysis; they do not extend
MIR's supported import graph.

Validation
----------

Focused regression suites cover the MIR model and lowering, native MIR
analysis, and command-line integration::

    pytest tests/ir/mir/ tests/analysis/callgraph/test_pycg_mir*.py
    pytest tests/cli/test_ir.py tests/cli/test_callgraph.py

Tests use source programs and directly constructed MIR as inputs. Expected
graphs are assertions in the tests; they are never inputs to the native solver.

References
----------

* Hakjoo Oh, *MIR: A Formal and Minimal Intermediate Representation for Rigorous
  Python Program Analysis*, IFIP WG 2.4, March 2026. The supplied attachment is
  also available as `the public presentation
  <https://prl.korea.ac.kr/slides/ifip26.pdf>`_. Slides 9--10 specify the core
  grammar and operational semantics; slide 14 identifies the analysis used by
  MirCG.
* Vitalis Salis et al., `PyCG: Practical Call Graph Generation in Python
  <https://arxiv.org/abs/2103.00587>`_, ICSE 2021. The assignment-graph algorithm
  motivates the native MIR analysis.
