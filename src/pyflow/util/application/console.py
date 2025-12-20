"""
Console output and timing utilities for compilation phases.

This module provides a hierarchical console output system with timing
capabilities, allowing structured logging of compilation phases with
nested scopes and elapsed time tracking.
"""

import sys
import time
from pyflow.util.io import formatting


class Scope(object):
    """Represents a hierarchical scope for timing and logging.

    Scopes form a tree structure where each scope can have children,
    allowing nested timing and logging of compilation phases.

    Attributes:
        parent: Parent scope, or None for root scope.
        name: Name of this scope.
        children: List of child scopes.
    """

    def __init__(self, parent, name):
        """Initialize a new scope.

        Args:
            parent: Parent scope (None for root).
            name: Name identifier for this scope.
        """
        self.parent = parent
        self.name = name
        self.children = []

    def begin(self):
        """Start timing this scope."""
        self._start = time.perf_counter()

    def end(self):
        """Stop timing this scope."""
        self._end = time.perf_counter()

    @property
    def elapsed(self):
        """Get elapsed time in seconds.

        Returns:
            Time elapsed between begin() and end() calls.
        """
        return self._end - self._start

    def path(self):
        """Get the full path from root to this scope.

        Returns:
            Tuple of scope names from root to this scope.
        """
        if self.parent is None:
            return ()
        else:
            return self.parent.path() + (self.name,)

    def child(self, name):
        """Create a child scope.

        Args:
            name: Name for the child scope.

        Returns:
            New Scope instance with this scope as parent.
        """
        return Scope(self, name)


class ConsoleScopeManager(object):
    """Context manager for console scopes.

    Allows using Console scopes with the 'with' statement for automatic
    scope management.

    Example:
        with console.scope("parsing"):
            # ... parsing code ...
            pass  # Scope automatically ends here
    """

    __slots__ = "console", "name"

    def __init__(self, console, name):
        """Initialize scope manager.

        Args:
            console: Console instance to manage.
            name: Name of the scope.
        """
        self.console = console
        self.name = name

    def __enter__(self):
        """Enter the scope (called by 'with' statement)."""
        self.console.begin(self.name)

    def __exit__(self, type, value, tb):
        """Exit the scope (called by 'with' statement)."""
        self.console.end()


class Console(object):
    """Hierarchical console output with timing and scoping.

    Provides structured console output with nested scopes, timing information,
    and optional verbose mode. Useful for tracking compilation phases and
    their durations.

    Attributes:
        out: Output stream (default: sys.stdout).
        root: Root scope of the hierarchy.
        current: Currently active scope.
        blameOutput: If True, include source location in output.
        verbose: If True, enable verbose output mode.
    """

    def __init__(self, out=None, verbose=False):
        """Initialize console.

        Args:
            out: Output stream (default: sys.stdout).
            verbose: Enable verbose output mode.
        """
        if out is None:
            out = sys.stdout
        self.out = out

        self.root = Scope(None, "root")
        self.current = self.root

        self.blameOutput = False
        self.verbose = verbose

    def path(self):
        """Get formatted path string for current scope.

        Returns:
            String representation of current scope path, e.g., "[ root | parsing | ast ]".
        """
        return "[ %s ]" % " | ".join(self.current.path())

    def begin(self, name):
        """Begin a new nested scope.

        Creates a child scope, starts timing, and outputs a begin message.

        Args:
            name: Name of the new scope.
        """
        scope = self.current.child(name)
        scope.begin()
        self.current = scope

        self.output("begin %s" % self.path(), 0)

    def end(self):
        """End the current scope.

        Stops timing, outputs an end message with elapsed time, and returns
        to the parent scope.
        """
        self.current.end()
        self.output(
            "end   %s %s" % (self.path(), formatting.elapsedTime(self.current.elapsed)),
            0,
        )
        self.current = self.current.parent

    def scope(self, name):
        """Create a context manager for a scope.

        Args:
            name: Name of the scope.

        Returns:
            ConsoleScopeManager instance for use with 'with' statement.

        Example:
            with console.scope("optimization"):
                # ... code ...
        """
        return ConsoleScopeManager(self, name)

    def blame(self):
        """Get source location of the calling code.

        Uses frame inspection to determine the filename and line number
        of the code that called the console method.

        Returns:
            String in format "filename:lineno".
        """
        caller = sys._getframe(2)
        globals = caller.f_globals
        lineno = caller.f_lineno

        filename = caller.f_code.co_filename

        del caller  # Destroy a circular reference

        return "%s:%d" % (filename, lineno)

    def output(self, s, tabs=1):
        """Write output to console.

        Args:
            s: String to output.
            tabs: Number of tab characters to indent (0 for no indentation).
        """
        if tabs:
            self.out.write("\t" * tabs)

        if self.blameOutput and tabs:
            self.out.write(self.blame() + " ")

        self.out.write(s)
        self.out.write("\n")

    def verbose_output(self, s, tabs=1):
        """Output only when verbose mode is enabled.

        Args:
            s: String to output.
            tabs: Number of tab characters to indent.
        """
        if self.verbose:
            self.output(s, tabs)
