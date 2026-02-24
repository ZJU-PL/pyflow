"""
Entry point representation for PyFlow analysis.

An EntryPoint represents a callable entry point with argument information,
used to define the starting points for static analysis.
"""

from .wrappers import ArgumentWrapper, nullWrapper


class EntryPoint:
    """
    Represents a callable entry point with argument information.

    EntryPoints are created during interface translation and represent
    functions or methods that should be analyzed.

    Attributes:
        code: The code object for this entry point
        selfarg: ArgumentWrapper for 'self' (for methods) or nullWrapper
        args: Tuple of ArgumentWrappers for positional arguments
        kwds: List of keyword arguments (currently unused)
        varg: ArgumentWrapper for *args or nullWrapper
        karg: ArgumentWrapper for **kwargs or nullWrapper
        group: EntryPoint group for related entry points
        contexts: List of analysis contexts for this entry point
    """

    __slots__ = "code", "selfarg", "args", "kwds", "varg", "karg", "group", "contexts"

    def __init__(self, code, selfarg, args, kwds, varg, karg):
        assert isinstance(selfarg, ArgumentWrapper), selfarg

        for arg in args:
            assert isinstance(arg, ArgumentWrapper), arg

        assert not kwds

        assert isinstance(varg, ArgumentWrapper), varg
        assert isinstance(karg, ArgumentWrapper), karg

        self.code = code
        self.selfarg = selfarg
        self.args = args
        self.kwds = kwds
        self.varg = varg
        self.karg = karg
        self.group = None
        self.contexts = []

    def name(self):
        return self.code.codeName()

    def __repr__(self):
        return "EntryPoint(%r, %d)" % (self.code, len(self.args))
