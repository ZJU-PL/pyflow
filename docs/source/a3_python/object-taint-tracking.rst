Object Taint Tracking
=====================

The original theory notes included dedicated writeups for file-object taint and
network-socket taint. Those notes are worth preserving because they show that
``a3_python`` is designed for object-aware taint propagation, not only plain
string-flow analysis.

Shared mechanism
----------------

Both file-object and socket taint tracking rely on the same key idea:

* a call result inherits taint from its arguments
* for method-like operations, the result can also inherit taint from the
  receiver object or callable reference

This is exactly the pattern described in the original notes and implemented in
the current tree around:

* ``semantics/security_tracker_lattice.py``
* ``contracts/security_lattice.py``

File-object taint
-----------------

The file-object note used the following canonical flow:

* tainted path
* file object created from that path
* content read from the file object
* content used in a sink

That pattern matters because the danger may not be at the initial ``open()``
call alone. The follow-on read result can become the real source of:

* code injection
* unsafe configuration loading
* path-based trust mistakes

The implementation intent is:

* ``open(tainted_path)`` can create a tainted file object
* ``f.read()`` can produce data inheriting taint from ``f``
* later sink checks can combine both path and content reasoning

This theory is backed by tests in the repository, including dedicated file
object taint tests under ``tests/a3-python``.

Socket taint
------------

The socket-taint note extends the same mechanism to network objects:

* a socket or connection created from attacker-controlled data becomes tainted
* data received through that socket inherits both a generic network-source label
  and the socket object's existing taint

This is especially important for second-order SSRF-like patterns:

* attacker controls where the program connects
* the returned data is then trusted too much
* that data is reused in another security-sensitive network operation

The original note framed the core transfer rule as:

* socket creation propagates host or address taint into the socket object
* ``recv``-like operations merge a network-read source label with the socket's
  taint

That gives the analyzer a way to represent:

* ordinary network-derived untrusted input
* transitive attacker control over the connection origin itself

Security impact
---------------

These object-aware taint flows improve detection for patterns such as:

* SSRF through tainted URLs, sockets, or connection pools
* command or code execution on content read from tainted files
* path or deserialization hazards that arise after object-mediated reads

More broadly, they show why the subsystem uses a richer taint lattice and
object-sensitive propagation instead of only line-based string sources and
sinks.

Why receiver-aware propagation matters
--------------------------------------

The original notes emphasized that object taint is compositional:

* file handles, sockets, cursors, and similar handles can carry semantic state
* later operations on those objects should see that state

This is a particularly good fit for Python, where many security-relevant flows
are protocol-driven:

* ``open(...).read()``
* ``socket.recv()``
* ``cursor.fetchall()``
* framework object methods that wrap external state

By propagating taint through object receivers and not just explicit arguments,
the analysis can model these idioms much more naturally.

Related code and tests
----------------------

Relevant implementation areas:

* ``semantics/security_tracker_lattice.py``
* ``contracts/security_lattice.py``
* ``unsafe/security/``

Relevant tests in the current repository include dedicated coverage for:

* file object taint
* socket taint
* connection or cursor-like propagation patterns

These are some of the clearest examples where theory notes from the original
project map directly onto the current codebase.
