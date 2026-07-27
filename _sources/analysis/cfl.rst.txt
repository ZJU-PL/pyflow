Context-Free-Language Reachability
==================================

The ``pyflow.util.cfl`` package provides experimental context-free-language
(CFL) reachability utilities. It is a low-level library for analyses that need
to query paths constrained by a grammar; it is not exposed by the ``pyflow``
command-line interface.

The package contains graph, grammar, matrix, and solver implementations, plus
demonstration inputs under ``pyflow.util.cfl.demo``. Its API is still evolving,
so consumers should import the specific implementation they need and pin their
PyFlow revision rather than treating it as a stable public interface.

For usage examples, see ``src/pyflow/util/cfl/README.md`` and the accompanying
``demo/`` directory in the source tree.
