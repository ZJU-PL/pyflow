"""
Interface declarations for PyFlow analysis.

This module provides data structures for declaring and representing
program entry points and class interfaces in the PyFlow analysis framework.
"""

from .entry_point import EntryPoint
from .wrappers import ExistingWrapper, InstanceWrapper, nullWrapper


class ClassDeclaration:
    """
    Declares a class with its initialization, attributes, and methods.

    Used to define how a class should be analyzed, including which
    constructor signatures, attributes, and method signatures to include.

    Attributes:
        typeobj: The class type object
        _init: List of constructor argument tuples
        _attr: List of attribute names
        _method: Dict mapping method names to argument tuples
    """

    def __init__(self, cls):
        self.typeobj = cls
        self._init = []
        self._attr = []
        self._method = {}

    def init(self, *args):
        self._init.append(args)

    def attr(self, *args):
        self._attr.extend(args)

    def method(self, name, *args):
        if name not in self._method:
            self._method[name] = []
        self._method[name].append(args)


class InterfaceDeclaration:
    """
    Aggregates function and class declarations into analyzable interfaces.

    This is the main entry point for declaring what should be analyzed.
    Function and class declarations are added, then translated into
    EntryPoints for the analysis pipeline.

    Attributes:
        func: List of (function, args) tuples for function entry points
        cls: List of ClassDeclaration objects for class entry points
        entryPoint: List of EntryPoint objects after translation
        translated: Whether translate() has been called
    """

    __slots__ = "func", "cls", "entryPoint", "translated"

    def __init__(self):
        self.func = []
        self.cls = []
        self.entryPoint = []
        self.translated = False

    def translate(self, extractor):
        assert not self.translated
        self.entryPoint = []
        self._extractFunc(extractor)
        self._extractCls(extractor)
        self.translated = True

    def createEntryPoint(
        self, code, selfarg, args, kwds=None, varg=None, karg=None, group=None
    ):
        if selfarg is None:
            selfarg = nullWrapper
        if args is None:
            args = []
        if kwds is None:
            kwds = []
        if varg is None:
            varg = nullWrapper
        if karg is None:
            karg = nullWrapper

        kwds = self._normalize_kwds(kwds)
        args, unresolved_kwds = self._apply_kwds_to_args(code, args, kwds)
        if unresolved_kwds:
            unresolved_names = ", ".join(name for name, _ in unresolved_kwds)
            raise ValueError(
                f"Unsupported keyword arguments for entry point: {unresolved_names}"
            )

        return self._createEntryPoint(
            code, selfarg, args, unresolved_kwds, varg, karg, group
        )

    def _normalize_kwds(self, kwds):
        if isinstance(kwds, dict):
            items = kwds.items()
        else:
            items = kwds

        normalized = []
        for item in items:
            if not isinstance(item, (tuple, list)) or len(item) != 2:
                raise TypeError(
                    "Keyword arguments must be provided as (name, ArgumentWrapper) pairs."
                )
            name, value = item
            if not isinstance(name, str):
                raise TypeError("Keyword argument names must be strings.")
            normalized.append((name, value))
        return normalized

    def _apply_kwds_to_args(self, code, args, kwds):
        if not kwds:
            return tuple(args), []

        params = None
        try:
            if hasattr(code, "codeParameters"):
                params = list(code.codeParameters().paramnames)
            elif hasattr(code, "codeparameters"):
                params = list(code.codeparameters.paramnames)
        except Exception:
            params = None

        if not params:
            return tuple(args), kwds

        mapped_args = list(args)
        consumed = set()
        unresolved = []
        original_len = len(mapped_args)

        for name, value in kwds:
            if name in consumed:
                raise ValueError(f"Duplicate keyword argument '{name}'.")
            consumed.add(name)
            if name not in params:
                unresolved.append((name, value))
                continue
            index = params.index(name)
            if index < original_len:
                raise ValueError(
                    f"Argument '{name}' passed by both position and keyword."
                )
            while len(mapped_args) <= index:
                mapped_args.append(ExistingWrapper(None))
            mapped_args[index] = value

        return tuple(mapped_args), unresolved

    def _createEntryPoint(self, code, selfarg, args, kwds, varg, karg, group):
        ep = EntryPoint(code, selfarg, args, kwds, varg, karg)
        ep.group = group if group is not None else ep
        self.entryPoint.append(ep)
        return ep

    def _extractFunc(self, extractor):
        for expr, args in self.func:
            fobj, code = extractor.getObjectCall(expr)
            selfarg = nullWrapper
            if not args:
                try:
                    num_params = len(code.codeparameters.params)
                except Exception:
                    num_params = 0
                args = [ExistingWrapper(None) for _ in range(num_params)]

            self.createEntryPoint(
                code, selfarg, tuple(args), [], nullWrapper, nullWrapper, None
            )

    def getMethCode(self, cls, name, extractor):
        meth = getattr(cls.typeobj, name)
        func = getattr(meth, "__func__", getattr(meth, "im_func", meth))
        fobj, code = extractor.getObjectCall(func)
        selfarg = ExistingWrapper(func)
        return selfarg, code

    def _extractCls(self, extractor):
        for cls in self.cls:
            tobj = ExistingWrapper(cls.typeobj)
            inst = InstanceWrapper(cls.typeobj)

            call = extractor.stubs.exports["interpreter_call"]
            getter = extractor.stubs.exports["interpreter_getattribute"]

            group = None
            for args in cls._init:
                ep = self.createEntryPoint(
                    call, tobj, args, [], nullWrapper, nullWrapper, group
                )
                if group is None:
                    group = ep

            for attr in cls._attr:
                name = ExistingWrapper(attr)
                self.createEntryPoint(
                    getter,
                    nullWrapper,
                    (inst, name),
                    [],
                    nullWrapper,
                    nullWrapper,
                    None,
                )

            for name, arglist in cls._method.items():
                selfarg, code = self.getMethCode(cls, name, extractor)

                group = None
                for args in arglist:
                    ep = self.createEntryPoint(
                        code,
                        selfarg,
                        (inst,) + args,
                        [],
                        nullWrapper,
                        nullWrapper,
                        group,
                    )
                    if group is None:
                        group = ep

    def __nonzero__(self):
        return bool(self.func) or bool(self.cls)

    __bool__ = __nonzero__

    def entryCode(self):
        return frozenset([point.code for point in self.entryPoint])

    def entryContexts(self):
        entryContexts = set()
        for ep in self.entryPoint:
            entryContexts.update(ep.contexts)
        return entryContexts

    def entryCodeContexts(self):
        entryContexts = set()
        for ep in self.entryPoint:
            for context in ep.contexts:
                entryContexts.add((ep.code, context))
        return entryContexts

    def groupedEntryContexts(self):
        assert self.translated
        entryPointMerge = {}
        for entryPoint in self.entryPoint:
            if entryPoint.group not in entryPointMerge:
                entryPointMerge[entryPoint.group] = []
            entryPointMerge[entryPoint.group].extend(entryPoint.contexts)
        return entryPointMerge
