Editor and Agent Integration
============================

PyFlow exposes the same semantic-analysis snapshot through an LSP server, an
MCP server, and a one-shot query command.

Analysis modes
--------------

All three commands accept ``--mode``:

* ``basic`` runs call-graph analysis and exposes lightweight graph/CFG facts.
* ``full`` adds CPA and lifetime analysis and is the default.
* ``advanced`` adds heap analysis for alias and points-to queries.

Capabilities and MCP tools are filtered to match the selected mode. Features
that are not reliable enough for the wire API, such as source-level reaching
definitions, are reported as unavailable instead of returning partial data.

Language Server Protocol
------------------------

Start the LSP server over stdio:

.. code-block:: bash

   pyflow lsp --root /path/to/project --mode full

LSP uses ``Content-Length`` framed JSON-RPC 2.0. PyFlow supports full-document
synchronization: open and changed buffers are analyzed from their in-memory
text, so clients do not need to save before requesting navigation or hover
results. Analysis runs in a worker thread and completed snapshots are swapped
atomically.

Supported standard features include definitions, references, document and
workspace symbols, completion, hover, and call hierarchy. Source locations are
derived from an AST index of the analyzed document snapshot, including UTF-16
position conversion required by LSP.

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
