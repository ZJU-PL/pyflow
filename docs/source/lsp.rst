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
symbols from the previous valid index. Rename is unavailable while a shard has
incomplete syntax, so stale coordinates cannot be applied as edits.

Definitions, references, and call hierarchy resolve module imports, constructor
instances, aliases, annotations, inherited members, fields, and source-visible
factory returns. Module-level calls also appear in call hierarchy. Dynamic
wrappers and reassignment may leave a receiver partially known: navigation can
offer known targets, but rename requires complete, unambiguous member evidence.
Unknown receivers never fall back to an unrelated global namesake. Exported
names can be renamed without rewriting explicit import aliases.

Completion suggests members after a dot and lexical bindings elsewhere. It can
use the retained index while a dot leaves the edited document temporarily
unparseable. Trusted builtin and math/os/sys namespaces provide external member
suggestions without importing project code. Hover shows declaration signatures,
annotations, docstrings, and local inferred types, including at interior token
positions. It remains available while compiler results are stale.

``textDocument/diagnostic`` combines syntax diagnostics, unresolved lexical
names, bounded local type inference, and the AST dataflow security checker.
Analysis runs in a worker, is cached by document contents, and rejects results
for superseded text. Only one diagnostic worker runs at a time; obsolete queued
requests do not start additional analysis. These diagnostics are document-scoped:
they do not establish whole-project taint flow or replace a dedicated project
security scan. Dynamic imports, runtime-generated attributes, and unknown
external return types remain resolution limits.

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
