"""
Argument Normalization Optimization for PyFlow.

This module normalizes function arguments by eliminating *args (variable
positional arguments) when their length is statically known.

The optimization:
- Analyzes functions with *args to determine if length is constant
- Checks if *args is used in ways that allow normalization
- Transforms *args into explicit positional parameters
- Updates all call sites to use the new parameter list

This enables better optimization by making argument passing explicit.
"""

from pyflow.util.typedispatch import *
from pyflow.language.python import ast
from pyflow.language.python import annotations


class _ContainsLocalRef(TypeDispatcher):
    """Identity-based local reference finder."""

    def __init__(self, target):
        self.target = target
        self.found = False

    @dispatch(ast.Local)
    def visitLocal(self, node):
        if node is self.target:
            self.found = True

    @dispatch(list, tuple)
    def visitContainer(self, node):
        if self.found:
            return
        for child in node:
            self(child)

    @defaultdispatch
    def visitDefault(self, node):
        if self.found:
            return
        node.visitChildren(self)


class ArgumentNormalizationAnalysis(TypeDispatcher):
    """Analyzes whether argument normalization is applicable.

    Checks if a function's *args parameter can be normalized into explicit
    positional parameters by verifying the length is constant and usage
    patterns allow transformation.

    Args:
        storeGraph: Store graph for analyzing object relationships
    """

    def __init__(self, storeGraph):
        TypeDispatcher.__init__(self)
        self.storeGraph = storeGraph
        self.applicable = True
        self.vparam = None

    @dispatch(ast.Local)
    def visitLocal(self, node):
        if node is self.vparam:
            self.applicable = False

    @dispatch(ast.Call, ast.MethodCall)
    def visitCall(self, node):
        if self.applicable:
            self(node.expr)
            self(node.args)
            self(node.kwds)

            if node.vargs is self.vparam:
                self.applicable = False

    @dispatch(ast.DirectCall)
    def visitDirectCall(self, node):
        if self.applicable:
            self(node.selfarg)
            self(node.args)
            self(node.kwds)

            if node.vargs is self.vparam:
                self.applicable = False

    @dispatch(list, tuple)
    def visitContainer(self, node):
        for child in node:
            self(child)

    @dispatch(ast.leafTypes, ast.Existing)
    def visitLeaf(self, node):
        pass

    @defaultdispatch
    def visitDefault(self, node):
        if self.applicable:
            node.visitChildren(self)

    def process(self, node):
        """
        Analyze a code node to determine if argument normalization is applicable.

        Checks if the function's *args parameter can be normalized by:
        1. Verifying it's standard code (not a stub)
        2. Checking if *args length is constant
        3. Ensuring *args is not used in ways that prevent normalization
           (e.g., passed as *args to another function, used in loops)

        Args:
            node: Code node to analyze

        Returns:
            tuple: (applicable, vparam_length)
                   - applicable: True if normalization can be applied
                   - vparam_length: Length of *args if constant, 0 otherwise
        """
        if not node.isStandardCode():
            return False, 0

        if node.annotation.descriptive:
            return False, 0

        p = node.codeparameters
        if p.vparam:
            refs = p.vparam.annotation.references
            if refs is None:
                return False, 0

            lengths = set()
            for ref in refs[0]:
                length = ref.knownField(self.storeGraph.lengthSlotName)
                for obj in length:
                    obj = obj.xtype
                    if not obj.isExisting():
                        return False, 0
                    obj = obj.obj
                    if not obj.isConstant():
                        return False, 0
                    lengths.add(obj.pyobj)

            # We don't "partially" optimize variable length vparams
            # as this would require rewriting the heap.
            if len(lengths) != 1:
                return False, 0

            vparamLen = lengths.pop()

            self.applicable = True
            self.vparam = p.vparam
            self(node.ast)
            return self.applicable, vparamLen
        else:
            return False, 0


class ArgumentNormalizationTransform(TypeDispatcher):
    """Transforms code to normalize arguments.

    Replaces *args with explicit positional parameters and updates all
    call sites accordingly.

    Args:
        storeGraph: Store graph for analyzing object relationships
    """

    def __init__(self, storeGraph):
        self.storeGraph = storeGraph
        self.last_skip_reason = None

    @defaultdispatch
    def visitDefault(self, node):
        return node.rewriteChildren(self)

    @dispatch(list, tuple)
    def visitContainer(self, node):
        items = [self(child) for child in node]
        if isinstance(node, tuple):
            return tuple(items)
        return items

    @dispatch(ast.leafTypes)
    def visitLeaf(self, node):
        return node

    @dispatch(ast.Call)
    def visitCall(self, node):
        if node.vargs is self.vparam:
            expr = self(node.expr)
            args = self.extend(self(node.args), self.newParams)
            kwds = self(node.kwds)
            kargs = self(node.kargs)
            result = ast.Call(expr, args, kwds, None, kargs)

            result.annotation = node.annotation
            return result
        else:
            return node.rewriteChildren(self)

    @dispatch(ast.MethodCall)
    def visitMethodCall(self, node):
        if node.vargs is self.vparam:
            expr = self(node.expr)
            args = self.extend(self(node.args), self.newParams)
            kwds = self(node.kwds)
            kargs = self(node.kargs)
            result = ast.MethodCall(expr, node.name, args, kwds, None, kargs)

            result.annotation = node.annotation
            return result
        else:
            return node.rewriteChildren(self)

    @dispatch(ast.DirectCall)
    def visitDirectCall(self, node):
        if node.vargs is self.vparam:
            selfarg = self(node.selfarg)
            args = self.extend(self(node.args), self.newParams)
            kwds = self(node.kwds)
            kargs = self(node.kargs)
            result = ast.DirectCall(node.code, selfarg, args, kwds, None, kargs)

            result.annotation = node.annotation
            return result

        else:
            return node.rewriteChildren(self)

    def extend(self, old, new):
        return list(old) + new

    # Generic heap.field -> local transfer
    # TODO refactor into library?
    def transferReferences(self, src, field, dst):
        refs = src.annotation.references
        cout = []
        for cindex, context in enumerate(self.code.annotation.contexts):
            values = set()
            for ref in refs[1][cindex]:
                values.update(ref.knownField(field))
            cout.append(annotations.annotationSet(values))

        refs = annotations.makeContextualAnnotation(cout)
        dst.rewriteAnnotation(references=refs)

    def process(self, node, vparamLen):
        self.last_skip_reason = None
        p = node.codeparameters

        self.code = node
        self.vparam = p.vparam

        # Conservative safety gate: if the variadic parameter is still referenced
        # directly in the body, skipping normalization avoids stale local metadata.
        finder = _ContainsLocalRef(self.vparam)
        finder(node.ast)
        if finder.found:
            self.last_skip_reason = "vparam_local_referenced_in_body"
            return False

        self.newParams = [ast.Local(None) for i in range(vparamLen)]
        self.newNames = [None for i in range(vparamLen)]

        if vparamLen > 0:
            # Defaults are never used
            defaults = ()
        else:
            # Number of arguments unchanged, defaults may be used, do nothing
            defaults = p.defaults

        for i, lcl in enumerate(self.newParams):
            field = self.storeGraph.canonical.fieldName(
                "Array", self.storeGraph.extractor.getObject(i)
            )
            self.transferReferences(self.vparam, field, lcl)

        selfparam = p.selfparam
        parameters = self.extend(p.params, self.newParams)
        parameternames = self.extend(p.paramnames, self.newNames)
        vparam = None
        kparam = p.kparam
        returnparams = p.returnparams

        node.codeparameters = ast.CodeParameters(
            selfparam=selfparam,
            posonlyparams=p.posonlyparams,
            posonlynames=p.posonlynames,
            params=parameters,
            paramnames=parameternames,
            defaults=defaults,
            vparam=vparam,
            kparam=kparam,
            returnparams=returnparams,
            type_params=p.type_params,
        )
        node.ast = self(node.ast)
        self.vparam.rewriteAnnotation(references=None)
        return True


def evaluate(compiler, prgm):
    """Main entry point for argument normalization.

    Args:
        compiler: Compiler context
        prgm: Program to optimize

    Analyzes functions and transforms those where normalization is applicable.
    """
    with compiler.console.scope("argument normalization"):
        analysis = ArgumentNormalizationAnalysis(prgm.storeGraph)
        transform = ArgumentNormalizationTransform(prgm.storeGraph)
        changed = False
        safety_blocked = 0

        for code in prgm.liveCode:
            applicable, vparamLen = analysis.process(code)
            if applicable:
                transformed = bool(transform.process(code, vparamLen))
                changed = transformed or changed
                if not transformed and transform.last_skip_reason is not None:
                    safety_blocked += 1

        if safety_blocked:
            compiler.console.output(
                f"Argument normalization skipped for {safety_blocked} code objects due to safety guards."
            )

        return changed
