Incremental Analysis Cache
==========================

The ``pyflow.analysis.cache.incremental`` module provides file-level
incremental caching for static analysis runs.  It tracks file content
hashes, caches findings per file, and tracks import dependencies so
that changing a dependency invalidates all of its importers.

.. contents::
   :local:
   :depth: 2

Overview
--------

Re-running a full analysis on a large project can be expensive.  The
incremental cache lets you skip files that haven't changed since the
last run, only re-analyzing files whose content hashes differ from
the stored baseline.

Storage is backed by SQLite (WAL mode) in a single file (e.g.,
``.pyflow/cache.db``).  Content identity is tracked with BLAKE2b hashes.

Key Features
------------

- **Content-addressable identity**: BLAKE2b hashing detects any file change
- **Finding cache**: Store and retrieve analysis results per file
- **Dependency-aware invalidation**: Changing a dependency marks all its
  importers as affected
- **Context manager**: ``with IncrementalCache(db) as cache:`` handles open/close
- **WAL + NORMAL sync**: Optimized for mixed read/write workloads

API Reference
-------------

.. py:class:: IncrementalCache(db_path: str)

   File-level incremental cache backed by SQLite.

   .. py:method:: open() -> None

      Open the database connection and create tables if they don't exist.

   .. py:method:: close() -> None

      Close the database connection.

   .. py:method:: file_changed(path: str) -> bool

      Return ``True`` if the file content hash differs from the stored hash.

   .. py:method:: update_hash(path: str) -> None

      Store the current file content hash.

   .. py:method:: invalidate(path: str) -> None

      Remove the stored hash and cached findings for *path*.

   .. py:method:: store_findings(path: str, findings: list) -> None

      Cache analysis findings for *path* as JSON.

   .. py:method:: get_cached_findings(path: str) -> list[dict] | None

      Retrieve cached findings for *path*, or ``None``.

   .. py:method:: record_import(importer: str, imported: str) -> None

      Record that *importer* imports *imported*.

   .. py:method:: affected_files(changed: list[str], candidate_paths: list[str] | None = None) -> set[str]

      Returns the set of files affected by *changed*, computed by
      transitively following import dependencies.  If *candidate_paths*
      is provided, only those files are considered as potential importers.

Usage
-----

.. code-block:: python

   from pyflow.analysis.cache.incremental import IncrementalCache

   with IncrementalCache(".pyflow/cache.db") as cache:

       # Record import relationships discovered during analysis
       cache.record_import("app.py", "lib.py")
       cache.record_import("tests/test_app.py", "app.py")

       for file_path in project_files:
           if cache.file_changed(file_path):
               findings = run_analysis(file_path)
               cache.store_findings(file_path, findings)
               cache.update_hash(file_path)
           else:
               findings = cache.get_cached_findings(file_path)

       # If lib.py changed, re-analyze app.py and test_app.py too
       affected = cache.affected_files(changed=["lib.py"])

Schema
------

The SQLite database contains three tables:

``file_hashes``
   Tracks the current BLAKE2b hash for each file.

   - ``path TEXT PRIMARY KEY``
   - ``hash TEXT NOT NULL``
   - ``updated_at TEXT``

``cached_findings``
   Stores analysis results for each file as JSON.

   - ``path TEXT PRIMARY KEY``
   - ``findings_json TEXT NOT NULL``
   - ``updated_at TEXT``

``import_deps``
   Tracks which files import which other files.

   - ``importer TEXT NOT NULL``
   - ``imported TEXT NOT NULL``
   - ``PRIMARY KEY (importer, imported)``

See Also
--------

- :doc:`/how-to/customize-analysis` — Using incremental analysis for repeated runs
- :doc:`/how-to/debug-analysis-issues` — Debugging analysis at scale
