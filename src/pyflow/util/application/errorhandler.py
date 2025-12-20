"""
Error handling and reporting for compilation.

This module provides error collection, reporting, and management utilities
for the compiler, including support for error scoping and deferred error
display.
"""

from . import compilerexceptions

from pyflow.util.debug.blame import traceBlame


class ErrorScopeManager(object):
    """Context manager for error scoping.

    Allows isolating error counts within a scope, useful for tracking errors
    in specific compilation phases. Errors are accumulated hierarchically.

    Example:
        with error_handler.scope():
            # Errors in this block are tracked separately
            error_handler.error(...)
    """

    __slots__ = "handler"

    def __init__(self, handler):
        """Initialize scope manager.

        Args:
            handler: ErrorHandler instance to manage.
        """
        self.handler = handler

    def __enter__(self):
        """Enter error scope (called by 'with' statement)."""
        self.handler._push()

    def __exit__(self, type, value, tb):
        """Exit error scope (called by 'with' statement)."""
        self.handler._pop()


class ShowStatusManager(object):
    """Context manager for showing compilation status.

    Automatically displays compilation status (success/failure) and error
    counts when exiting the context. Suppresses CompilerAbort exceptions
    if they occur.

    Example:
        with error_handler.statusManager():
            # ... compilation code ...
            pass  # Status printed automatically on exit
    """

    __slots__ = "handler"

    def __init__(self, handler):
        """Initialize status manager.

        Args:
            handler: ErrorHandler instance to manage.
        """
        self.handler = handler

    def __enter__(self):
        """Enter status context (called by 'with' statement)."""
        pass

    def __exit__(self, type, value, tb):
        """Exit status context and show status (called by 'with' statement).

        Args:
            type: Exception type, if any.
            value: Exception value, if any.
            tb: Traceback, if any.

        Returns:
            True if CompilerAbort was raised (to suppress it), False otherwise.
        """
        self.handler.flush()

        if type is not None:
            print("Compilation Aborted -", self.handler.statusString())
        else:
            print("Compilation Successful -", self.handler.statusString())

        return type is compilerexceptions.CompilerAbort


class ErrorHandler(object):
    """Collects and manages compilation errors and warnings.

    Provides error collection, deferred display, and hierarchical error
    scoping. Supports both immediate and deferred error reporting modes.

    Attributes:
        stack: Stack for nested error scopes.
        errorCount: Total number of errors collected.
        warningCount: Total number of warnings collected.
        defered: If True, buffer errors for later display.
        buffer: List of buffered (classification, message, trace, blame) tuples.
        showBlame: If True, include blame information in error output.
    """

    def __init__(self):
        """Initialize error handler."""
        self.stack = []

        self.errorCount = 0
        self.warningCount = 0

        self.defered = True
        self.buffer = []

        self.showBlame = False

    def blame(self):
        """Get blame information for current call site.

        Returns:
            Blame traceback if showBlame is True, None otherwise.
        """
        if self.showBlame:
            return traceBlame(3, 5)
        else:
            return None

    def error(self, classification, message, trace):
        """Record a compilation error.

        Args:
            classification: Error classification/category.
            message: Error message.
            trace: List of Origin objects representing error trace.
        """
        blame = self.blame()
        if self.defered:
            self.buffer.append((classification, message, trace, blame))
        else:
            self.displayError(classification, message, trace, blame)
        self.errorCount += 1

    def warn(self, classification, message, trace):
        """Record a compilation warning.

        Args:
            classification: Warning classification/category.
            message: Warning message.
            trace: List of Origin objects representing warning trace.
        """
        blame = self.blame()
        if self.defered:
            self.buffer.append((classification, message, trace, blame))
        else:
            self.displayError(classification, message, trace, blame)
        self.warningCount += 1

    def displayError(self, classification, message, trace, blame):
        """Display a single error or warning.

        Args:
            classification: Error/warning classification.
            message: Error/warning message.
            trace: List of Origin objects.
            blame: Blame information (list of strings or None).
        """
        print("%s: %s" % (classification, message))
        for origin in trace:
            if origin is None:
                print("<unknown origin>")
            else:
                print(origin.originString())

        if blame:
            print("BLAME")
            for line in blame:
                print(line)

    def statusString(self):
        """Get formatted status string.

        Returns:
            String describing error and warning counts.
        """
        return "%d errors, %d warnings" % (self.errorCount, self.warningCount)

    def finalize(self):
        """Finalize error handling and raise exception if errors exist.

        Raises:
            CompilerAbort: If any errors were collected.
        """
        if self.errorCount > 0:
            raise compilerexceptions.CompilerAbort

    def flush(self):
        """Flush buffered errors and warnings to output.

        Displays all buffered errors and warnings, then clears the buffer.
        """
        for cls, msg, trace, blame in self.buffer:
            self.displayError(cls, msg, trace, blame)
        self.buffer = []

    def _push(self):
        """Push a new error scope onto the stack.

        Saves current error/warning counts and resets them for the new scope.
        """
        self.stack.append((self.errorCount, self.warningCount))
        self.errorCount = 0
        self.warningCount = 0

    def _pop(self):
        """Pop an error scope from the stack.

        Restores error/warning counts from the previous scope and adds
        current counts to them.
        """
        errorCount, warningCount = self.stack.pop()
        self.errorCount += errorCount
        self.warningCount += warningCount

    def scope(self):
        """Create an error scope context manager.

        Returns:
            ErrorScopeManager instance for use with 'with' statement.
        """
        return ErrorScopeManager(self)

    def statusManager(self):
        """Create a status display context manager.

        Returns:
            ShowStatusManager instance for use with 'with' statement.
        """
        return ShowStatusManager(self)
