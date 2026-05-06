Type-Based Sanitizers
=====================

The original ``type_based_sanitizers`` theory note described one of the most
useful precision improvements in the security stack: some operations sanitize by
constraining the value domain, not by escaping characters.

Core idea
---------

If a conversion or validator maps an attacker-controlled value into a domain
that cannot express a given exploit string family, then that operation can act
as a sanitizer for the relevant sink.

Examples from the original note include:

* ``int()`` for SQL or shell-sensitive contexts
* ``bool()`` for strongly constrained two-value domains
* ``datetime.fromisoformat()`` for format-validated temporal values
* ``pathlib.Path.resolve()`` for canonicalized path usage
* ``ipaddress.ip_address()`` for validated network identifiers

This is a more semantic view of sanitization than plain string escaping.

Why it improves precision
-------------------------

Without this reasoning, the analyzer may keep a value marked as dangerous even
after it has been converted into a domain that no longer supports the relevant
attack surface.

For example:

* a tainted string converted with ``int()`` no longer carries arbitrary SQL
  syntax as such
* a validated IP address is not the same thing as an arbitrary attacker-chosen
  URL string

The original notes used this to justify lower false-positive rates for:

* SQL-related sinks
* command or shell sinks
* filesystem path sinks
* HTTP/network request sinks

Implementation mapping
----------------------

The current implementation is centered in:

* ``contracts/security_lattice.py``
* ``semantics/security_tracker_lattice.py``

The original note described several sanitizer families that still make sense as
categories for contributors:

Numeric conversions
~~~~~~~~~~~~~~~~~~~

Examples:

* ``int``
* ``float``
* ``bool``

These reduce the output domain from arbitrary attacker-controlled strings to
structured numeric or boolean values.

Validation-style string predicates
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Examples:

* ``str.isdigit()``
* ``str.isalpha()``
* ``str.isalnum()``

These can justify sink-specific safety claims when the validated property rules
out the exploit class being modeled.

Structured parsers
~~~~~~~~~~~~~~~~~~

Examples:

* ``datetime.fromisoformat()``
* ``datetime.strptime()``
* ``ipaddress.ip_address()``

These are useful because they turn free-form strings into constrained semantic
objects.

Path and enum constraints
~~~~~~~~~~~~~~~~~~~~~~~~~

Examples:

* ``pathlib.Path.resolve()``
* enum or allowlist conversions

These capture two common real-world precision wins:

* canonicalizing a path before use
* reducing attacker choice to an enumerated set

Why the original note matters
-----------------------------

The most valuable point in the original writeup was not just the contract list.
It was the reminder that sanitization must be sink-specific.

The same transformation should not automatically sanitize every sink:

* an operation that helps with SQL may be irrelevant for HTML or code execution
* a path canonicalizer does not automatically make a value safe for shell use

That is why the current code organizes sanitization through explicit
contract-to-sink relationships rather than a single global "safe now" bit.

Testing and future work
-----------------------

The original note also tied this area to dedicated test coverage, and that is
the right way to maintain it. Type-based sanitizer behavior is subtle enough
that every new sanitizer class should come with:

* positive cases showing reduced false positives
* negative cases proving it does not over-sanitize unrelated sinks

Future extensions suggested in the original note remain relevant:

* stronger type and range tracking after conversion
* user-defined validators
* regex-backed validation contracts
* framework-aware model and ORM validation contracts

For contributors, this is one of the highest-leverage precision areas in the
whole security stack.
