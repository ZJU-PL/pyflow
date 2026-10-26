Editor and Agent Integration
============================

PyFlow provides source-oriented editor services through LSP and compiler
analysis through MCP and one-shot queries. All use revision-pinned analysis
snapshots.

Analysis modes
--------------

All three commands accept ``--mode``:

* ``basic`` runs call-graph analysis and exposes lightweight graph/CFG facts.
* ``full`` adds CPA and lifetime analysis and is the default.
* ``advanced`` adds heap analysis for alias and points-to queries.

MCP capabilities and tools are filtered to match the selected mode. LSP always
starts with its source index; ``--mode`` selects the passes for optional compiler
analysis, rather than blocking initialization on those passes. Features
that are not reliable enough for the wire API, such as source-level reaching
definitions, are reported as unavailable instead of returning partial data.

Language Server Protocol
------------------------

Start the LSP server over stdio:

.. code-block:: bash

   pyflow lsp --root /path/to/project --mode full

LSP reserves stdout for ``Content-Length`` framed JSON-RPC 2.0; logs and compiler
output go to stderr. Editors may launch ``pyflow lsp`` without ``--root`` and
supply ``rootUri`` or ``workspaceFolders`` in ``initialize``. An empty workspace
is valid. Opening a standalone document indexes that document without scanning
its parent directory.

Initialization builds the AST source index without extraction, IPA, CPA, or
lifetime analysis. Unsupported compiler constructs therefore do not disable
navigation for an entire workspace. To request compiler facts, execute the
``pyflow.analyzeWorkspace`` command through ``workspace/executeCommand``. Clients
may instead set ``initializationOptions.semanticAnalysis`` to ``true`` to start
one background compiler run after the ``initialized`` notification. Compiler
failures are returned as diagnostics by the command while source services remain
available. The selected ``--mode`` applies to these runs. Source changes mark
compiler facts stale; another explicit command refreshes them. Edits never
schedule repeated whole-project compiler runs.

Both full-document and incremental UTF-16 changes are supported. Navigation,
completion, hover, rename, and diagnostics use unsaved overlays. Unchanged file
shards are reused, and temporary syntax errors retain and rebase unchanged
symbols from the previous valid index, including blocks whose indentation has
changed. Once syntax is valid, ranges come from a fresh AST rather than recovery
coordinates. Rename is unavailable when a file touched
by the edit has incomplete syntax, so stale coordinates cannot be applied as edits. An unrelated invalid file does
not disable refactoring elsewhere.

Definitions, references, and call hierarchy resolve module imports, constructor
instances, aliases, annotations, inherited members, fields, and source-visible
factory returns. Module-level calls also appear in call hierarchy. Dynamic
wrappers and reassignment may leave a receiver partially known: navigation can
offer known targets, but rename rejects a partial receiver when its known
alternatives include the target. Unrelated unresolved uses of a common method
name do not veto the rename. Only statically linked references are changed;
runtime-generated accesses remain unresolved. Unknown receivers never fall back
to an unrelated global namesake. Exported names can be renamed without rewriting
explicit import aliases, and literal ``__all__`` entries are updated as well.
Rename validates declaration-scope collisions and checks the proposed source
against the original reference bindings. It refuses duplicate parameters,
member collisions, and lexical capture/shadowing instead of returning edits
which change symbol identity. ``global`` and ``nonlocal`` declarations are
included in these edits. Runtime-generated bindings remain outside this check.
Keyword argument labels participate in parameter navigation, references, and
rename, including imported functions, aliases, bound methods, constructors, and
callable instances.

The source index recognizes conventional ``src/`` layouts and scoped pytest
fixture declarations in modules and applicable ``conftest.py`` files. Declared
return and attribute types guide receiver resolution. Property reads resolve to
the getter, writes to the setter; property rename includes all accessors. Python
3.12+ function, class, and type-alias type parameters have distinct lexical
bindings when the server runs on a Python version supporting that syntax.
Document outlines contain nested declarations, class fields, and module
variables/constants. Workspace symbol search excludes parameters and function
locals and ranks declarations ahead of variable matches.

Completion suggests members after a dot and lexical bindings elsewhere. It can
use the retained index while a dot leaves the edited document temporarily
unparseable. Trusted builtin and math/os/sys namespaces provide external member
suggestions without importing project code. Hover shows declaration signatures,
annotations, docstrings, and local inferred types, including at interior token
positions. It remains available while compiler results are stale.

Clients advertising LSP pull diagnostic support use ``textDocument/diagnostic``.
Other clients receive debounced ``textDocument/publishDiagnostics`` notifications
on open, change, and save. Closing a document clears published diagnostics.
Per-document generations and versions prevent results for superseded or closed
buffers from being published, including when analysis continues in a worker.

``textDocument/diagnostic`` combines syntax diagnostics, unresolved lexical
names, bounded local type inference, and the AST dataflow security checker.
Analysis runs in a worker, is cached by document contents, and rejects results
for superseded text. Only one diagnostic worker runs at a time; obsolete queued
requests do not start additional analysis. These diagnostics are document-scoped:
they do not establish whole-project taint flow or replace a dedicated project
security scan. Standard collection annotations use their real abstract base
classes and element types. Generator annotations check yielded values separately
from terminal return values, including async generators. Optional values and
``isinstance`` checks narrow local and attribute types along control-flow paths.
Imported types without hierarchy evidence remain explicitly uncertain instead of
being diagnosed as incompatible dummy classes. Unsupported-model and analysis
budget notes remain available in type-analysis status/diagnostics APIs but are
not emitted as editor squiggles. Dynamic imports, runtime-generated attributes,
and unknown external return types remain resolution limits.

Class patterns link the class, keyword attributes, and capture variables
separately. Explicit ``__match_args__`` strings also participate in member
references and rename. Optional-import and fallback-import bindings are retained;
this is not a general proof that every conditional binding is initialized.

Framework navigation has explicit contracts for Flask ``current_app`` and
Starlette/FastAPI connection state. Definitions prefer workspace source, then
installed package source, then bundled editor stubs. Package files are parsed
without importing user/framework code. Observed assignments to known
``request.state`` members provide cross-document definitions, references, hover,
and rename. Request/connection state and application state use separate member
namespaces. Arbitrary ``__getattr__`` implementations and unrelated similarly
named classes do not acquire these contracts. No inferred state members are
created without an observed assignment; namespace schemas are approximate and
are not an instance-sensitive whole-program analysis.

Model Context Protocol
----------------------

Start the MCP server over stdio:

.. code-block:: bash

   pyflow mcp --root /path/to/project --mode advanced

MCP uses newline-delimited JSON-RPC 2.0 messages. Standard method names are
implemented, including ``initialize``, ``resources/list``, ``resources/read``,
``resources/templates/list``, ``tools/list``, and ``tools/call``. Early
``mcp.*`` method aliases remain available for compatibility.

Resources include:

* ``pyflow://capabilities``
* ``pyflow://functions``
* ``pyflow://callgraph`` when call-graph analysis is available
* ``pyflow://function/{name}`` for function locations and profiles

Tool results use JSON text content and include structured content when the
result is an object.

One-shot queries
----------------

The query command is useful for scripts and diagnostics:

.. code-block:: bash

   pyflow query . --get-callgraph --pretty
   pyflow query . --get-callers package.module.function
   pyflow query module.py --get-type module 12 8
   pyflow query . --mode advanced --get-aliases variable_name

The output is JSON and can be written with ``--output``.
