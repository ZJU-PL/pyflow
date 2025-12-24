"""Constant folding optimization pass.

This module implements constant folding optimization, which evaluates constant
expressions at compile time and replaces them with their computed values.
"""

from pyflow.util.typedispatch import *
from ..language.asttools import annotation

from pyflow.optimization.dataflow.forward import *
from pyflow.optimization.dataflow.base import top, undefined, MutateCode
from pyflow.language.python import fold
from pyflow.analysis import tools
from pyflow.optimization import termrewrite
from pyflow.optimization.termrewrite import DirectCallRewriter

from . import rewrite


def floatMulRewrite(self, node):
    """Rewrite float multiplication with constant optimization.
    
    Optimizes multiplication by 0, 1, or -1 for floating point operations.
    
    Args:
        node: AST node representing the multiplication operation.
        
    Returns:
        AST node: Optimized node or None if no optimization applies.
    """
    if not termrewrite.hasNumArgs(node, 2):
        return

    if termrewrite.isZero(node.args[0]):
        return node.args[0]
    elif termrewrite.isOne(node.args[0]):
        return node.args[1]
    elif termrewrite.isZero(node.args[1]):
        return node.args[1]
    elif termrewrite.isOne(node.args[1]):
        return node.args[0]

    # TODO negative 1 -> invert
    # Requires calling new code?


def floatAddRewrite(self, node):
    if not termrewrite.hasNumArgs(node, 2):
        return

    if termrewrite.isZero(node.args[0]):
        return node.args[1]
    elif termrewrite.isZero(node.args[1]):
        return node.args[0]


def convertToBoolRewrite(self, node):
    if not termrewrite.hasNumArgs(node, 1):
        return

    if termrewrite.isAnalysisInstance(node.args[0], bool):
        return node.args[0]


def makeCallRewrite(extractor):
    callRewrite = DirectCallRewriter(extractor)
    callRewrite.addRewrite("prim_float_mul", floatMulRewrite)
    callRewrite.addRewrite("prim_float_add", floatAddRewrite)
    callRewrite.addRewrite("convertToBool", convertToBoolRewrite)
    return callRewrite


class FoldRewrite(TypeDispatcher):
    """
    Rewriter that performs constant folding transformations.
    
    This class implements the core constant folding logic by:
    - Replacing constant expressions with their computed values
    - Propagating constants through assignments
    - Folding binary and unary operations on constants
    - Converting method calls to direct calls where possible
    - Eliminating dead arguments from calls
    
    The rewriter uses forward data flow analysis to track constant values
    as they flow through the program, enabling constant propagation in
    addition to constant folding.
    
    Attributes:
        extractor: Object extractor for creating new objects
        storeGraph: Store graph for type information (may be None)
        code: Code object being optimized
        created: Set of objects created during folding
        callRewrite: Term rewriter for call optimizations
        annotationsExist: Whether context annotations are available
        flow: FlowDict for tracking constant values (set by analysis)
    """
    def __init__(self, extractor, storeGraph, code):
        """
        Initialize constant folding rewriter.
        
        Args:
            extractor: Object extractor
            storeGraph: Store graph (may be None)
            code: Code object to optimize
        """
        TypeDispatcher.__init__(self)
        self.extractor = extractor
        self.storeGraph = storeGraph
        self.code = code

        # Track objects created during folding
        self.created = set()

        # Term rewriter for call optimizations
        self.callRewrite = makeCallRewrite(extractor)

        # Check if we have context annotations for type-based optimizations
        self.annotationsExist = (
            code.annotation.contexts is not None and storeGraph is not None
        )

    def descriptive(self):
        """
        Check if the code is descriptive (detailed behavior).
        
        Descriptive code is not folded as aggressively to preserve
        behavioral information.
        
        Returns:
            bool: True if code is descriptive
        """
        return self.code.annotation.descriptive

    @defaultdispatch
    def visitOK(self, node):
        """Default handler: return node unchanged."""
        return node

    def logCreated(self, node):
        """
        Log objects created during folding.
        
        Tracks newly created objects so they can be added to the
        extractor's object list.
        
        Args:
            node: AST node (if Existing, logs its object)
        """
        if isinstance(node, ast.Existing):
            self.created.add(node.object)

    @dispatch(ast.Call)
    def visitCall(self, node):
        func = tools.singleCall(node)
        if func is not None:
            result = ast.DirectCall(
                func, node.expr, node.args, node.kwds, node.vargs, node.kargs
            )
            result.annotation = node.annotation
            return self(result)

        return node

    def getObjects(self, ref):
        if isinstance(ref, (ast.Local, ast.Existing)):
            refs = ref.annotation.references
            if refs is not None:
                return refs[0]
            else:
                return ()  # HACK?
        else:
            assert False, type(ref)

    def getExistingNames(self, ref):
        if isinstance(ref, ast.Local):
            refs = ref.annotation.references
            if refs is not None:
                return [ref.xtype.obj for ref in refs[0]]
            else:
                return ()  # HACK?

        elif isinstance(ref, ast.Existing):
            return (ref.object,)

    def _cobjSlotRefs(self, cobj, slotType, key):
        fieldName = self.storeGraph.canonical.fieldName(slotType, key)
        slot = cobj.knownField(fieldName)
        return tuple(iter(slot))

    def getMethodFunction(self, expr, name):
        # Static setup
        typeStrObj = self.extractor.getObject("type")
        dictStrObj = self.extractor.getObject("dictionary")

        # Dynamic setup
        funcs = set()
        exprObjs = self.getObjects(expr)
        nameObjs = self.getExistingNames(name)

        for exprObj in exprObjs:
            assert not isinstance(exprObj, tuple), exprObj
            typeObjs = self._cobjSlotRefs(exprObj, "LowLevel", typeStrObj)
            for t in typeObjs:
                dictObjs = self._cobjSlotRefs(t, "LowLevel", dictStrObj)
                for d in dictObjs:
                    for nameObj in nameObjs:
                        funcObjs = self._cobjSlotRefs(d, "Dictionary", nameObj)
                        funcs.update(funcObjs)

        if len(funcs) == 1:
            cobj = funcs.pop()
            result = self.existingFromNode(cobj)
            return result
        else:
            return None

    def typeMatch(self, ref, group):
        return ref.xtype.obj.type in group

    # Filter out all the references that don't match the type.
    def filterReferenceAnnotationByType(self, a, group):
        filtered = [
            annotation.annotationSet(
                [ref for ref in crefs if self.typeMatch(ref, group)]
            )
            for crefs in a.references.context
        ]
        filtered = annotation.makeContextualAnnotation(filtered)
        return a.rewrite(references=filtered)

    # If the argument at pos in the invocation context does not have a
    # type in group, kill the invocation
    def filterInvokesByType(self, invokes, group, pos):
        newinvokes = []
        for inv in invokes:
            code, context = inv
            if context.signature.params[pos].obj.type in group:
                newinvokes.append(inv)
        return tuple(newinvokes)

    # It is obvious that some invocations will no longer occur, as they
    # require the wrong type for the argument under consideration.
    # Filter out these invocations.
    def filterOpAnnotationByType(self, a, group, pos):
        newcinvokes = [
            self.filterInvokesByType(invokes, group, pos)
            for invokes in a.invokes.context
        ]
        invokes = annotation.makeContextualAnnotation(newcinvokes)
        return a.rewrite(invokes=invokes)

    # Make a mask to kill contexts that have no references... they will never be evaluated.
    def makeRemapMask(self, a):
        return [i if crefs else -1 for i, crefs in enumerate(a.references.context)]

    # This is the policy that determined how a node is split into a type switch.
    # Currently, it groups the types by what code is called.  Similar invocation targets get grouped.
    def groupTypes(self, node, arg, pos):
        types = sorted(
            set([ref.xtype.obj.type for ref in arg.annotation.references.merged])
        )

        # Trivial case, less that two types.
        if len(types) <= 1:
            return None

        groupLUT = {}
        invmerged = node.annotation.invokes.merged
        for type in types:
            # Find the code that this type may call.
            invfiltered = self.filterInvokesByType(invmerged, (type,), pos)
            invtargets = tuple(sorted(set([code for code, context in invfiltered])))

            if invtargets not in groupLUT:
                groupLUT[invtargets] = [type]
            else:
                groupLUT[invtargets].append(type)

        return sorted(groupLUT.values())

    def methodCallToTypeSwitch(self, node, arg, pos, targets):
        # TODO if mutable types are allowed, we should be looking at the LowLevel type slot?
        # TODO localy rebuild read/modify/allocate information using filtered invokes.
        # TODO should the return value be SSAed?  This might interfere with nessled type switches.
        # If so, retarget the return value and fix up return types

        groups = self.groupTypes(node, arg, pos)
        if groups is None or len(groups) <= 1:
            return None  # Don't create trivial type switches

        cases = []
        for group in groups:
            # Create a filtered version of the argument.
            name = arg.name if isinstance(arg, ast.Local) else None
            expr = ast.Local(name)
            expr.annotation = self.filterReferenceAnnotationByType(
                arg.annotation, group
            )

            # Create the new op
            opannotation = node.annotation

            # Kill contexts where the filtered expression has no references.
            # (In these contexts, the new op will never be evaluated.)
            mask = self.makeRemapMask(expr.annotation)
            if -1 in mask:
                opannotation = opannotation.contextSubset(mask)

            # Filter out invocations that don't have the right type for the given parameter.
            opannotation = self.filterOpAnnotationByType(opannotation, group, pos)

            # Rewrite the op to use expr instead of the original arg.
            newop = rewrite.rewriteTerm(node, {arg: expr})
            assert newop is not node
            newop.annotation = opannotation

            # Try to reduce it to a direct call
            newop = self(newop)

            # Create the suite for this case
            stmts = []
            if targets is None:
                stmts.append(ast.Discard(newop))
            else:
                # HACK should SSA it?
                stmts.append(ast.Assign(newop, list(targets)))
            suite = ast.Suite(stmts)

            case = ast.TypeSwitchCase(
                [self.existingFromObj(t) for t in group], expr, suite
            )
            cases.append(case)

        ts = ast.TypeSwitch(arg, cases)
        return ts

    @dispatch(ast.MethodCall)
    def visitMethodCall(self, node):
        func = tools.singleCall(node)
        if func is not None:
            funcobj = self.getMethodFunction(node.expr, node.name)

            # TODO deal with single call / multiple function object case?
            if not funcobj:
                return node

            newargs = [node.expr]
            newargs.extend(node.args)
            result = ast.DirectCall(
                func, funcobj, newargs, node.kwds, node.vargs, node.kargs
            )
            result.annotation = node.annotation
            return self(result)
        return node

    @dispatch(ast.Assign)
    def visitAssign(self, node):
        if isinstance(node.expr, ast.MethodCall):
            expr = node.expr
            result = self.methodCallToTypeSwitch(expr, expr.expr, 0, node.lcls)
            if result:
                return self(result)

        return node

    @dispatch(ast.Discard)
    def visitDiscard(self, node):
        if isinstance(node.expr, ast.MethodCall):
            expr = node.expr
            result = self.methodCallToTypeSwitch(expr, expr.expr, 0, None)
            if result:
                return self(result)

        return node

    def localToExisting(self, lcl, obj):
        node = ast.Existing(obj)
        node.annotation = lcl.annotation
        return node

    def existingFromNode(self, cobj):
        node = ast.Existing(cobj.xtype.obj)
        references = annotation.makeContextualAnnotation(
            [(cobj,) for context in self.code.annotation.contexts]
        )
        node.rewriteAnnotation(references=references)
        return node

    def storeGraphForExistingObject(self, obj):
        slotName = self.storeGraph.canonical.existingName(self.code, obj, None)
        slot = self.storeGraph.root(slotName)
        xtype = self.storeGraph.canonical.existingType(obj)
        return slot.initializeType(xtype)

    def existingFromObj(self, obj):
        if self.annotationsExist:
            cobj = self.storeGraphForExistingObject(obj)
            node = self.existingFromNode(cobj)
            return node
        else:
            return ast.Existing(obj)

    @dispatch(ast.Local)
    def visitLocal(self, node):
        # Replace with query
        obj = tools.singleObject(node)
        if obj is not None:
            return self.localToExisting(node, obj)

        if hasattr(self, "flow"):
            # Replace with dataflow
            const = self.flow.lookup(node)
            if const is not undefined:
                if isinstance(const, ast.Local):
                    # Reach for the local definition
                    return const
                elif const is not top:
                    # Reach for the constant definition
                    return self.existingFromObj(const)

        return node

    def annotateFolded(self, node):
        if isinstance(node, ast.Existing):
            node = self.existingFromObj(node.object)
        return node

    @dispatch(ast.BinaryOp)
    def visitBinaryOp(self, node):
        if self.descriptive():
            return node
        result = self.annotateFolded(fold.foldBinaryOpAST(self.extractor, node))
        self.logCreated(result)
        return result

    @dispatch(ast.Is)
    def visitIs(self, node):
        result = self.annotateFolded(fold.foldIsAST(self.extractor, node))
        self.logCreated(result)
        return result

    @dispatch(ast.UnaryPrefixOp)
    def visitUnaryPrefixOp(self, node):
        if self.descriptive():
            return node
        result = self.annotateFolded(fold.foldUnaryPrefixOpAST(self.extractor, node))
        self.logCreated(result)
        return result

    @dispatch(ast.ConvertToBool)
    def visitConvertToBool(self, node):
        if node.expr.alwaysReturnsBoolean():
            return self(node.expr)

        if self.descriptive():
            return node
        result = self.annotateFolded(fold.foldBoolAST(self.extractor, node))
        self.logCreated(result)
        return result

    @dispatch(ast.Not)
    def visitNot(self, node):
        if self.descriptive():
            return node
        result = self.annotateFolded(fold.foldNotAST(self.extractor, node))
        self.logCreated(result)
        return result

    def tryDirectCallRewrite(self, node):
        result = self.callRewrite(self, node)
        if result is not None:
            self.logCreated(result)
            return self(result)
        return node

    def eliminateDeadArguments(self, node):
        if isinstance(node, ast.DirectCall):
            if (
                node.code
                and isinstance(node.code.codeparameters.selfparam, ast.DoNotCare)
                and not isinstance(node.selfarg, ast.DoNotCare)
            ):
                result = ast.DirectCall(
                    node.code,
                    ast.DoNotCare(),
                    node.args,
                    node.kwds,
                    node.vargs,
                    node.kargs,
                )
                result.annotation = node.annotation
                return result
        return node

    @dispatch(ast.DirectCall)
    def visitDirectCall(self, node):
        if self.descriptive():
            return node

        if node.code is None:
            return node

        foldFunc = node.code.annotation.staticFold
        if foldFunc and not node.kwds and not node.vargs and not node.kargs:
            result = self.annotateFolded(
                fold.foldCallAST(self.extractor, node, foldFunc, node.args)
            )
            if result is not node:
                self.logCreated(result)
                return result

        node = self.tryDirectCallRewrite(node)
        node = self.eliminateDeadArguments(node)
        return node


class FoldAnalysis(TypeDispatcher):
    @defaultdispatch
    def visitOK(self, node):
        return node

    @dispatch(ast.Assign)
    def visitAssign(self, node):
        if len(node.lcls) == 1:
            lcl = node.lcls[0]
            if fold.existingConstant(node.expr):
                self.flow.define(lcl, node.expr.object)
                return node
            elif isinstance(node.expr, ast.Local):
                # Propagate names.
                if lcl.name and not node.expr.name:
                    node.expr.name = lcl.name
                elif not lcl.name and node.expr.name:
                    lcl.name = node.expr.name

                self.flow.define(lcl, node.expr)
                return node

        for lcl in node.lcls:
            self.flow.define(lcl, top)

        return node

    @dispatch(ast.Delete)
    def visitDelete(self, node):
        self.flow.undefine(node.lcl)
        return node


# Restricted traversal, so not all locals are rewritten.
class FoldTraverse(TypeDispatcher):
    """
    Bottom-up AST traverser for constant folding.
    
    This traverser visits AST nodes in bottom-up order (children before
    parents), allowing constant folding to work from leaves upward. It
    applies the strategy (FoldRewrite) to each node after processing
    its children.
    
    Special handling:
    - Assignment targets are not folded (only expressions)
    - Delete targets are not folded
    - Code parameters are not processed
    
    Attributes:
        strategy: FoldRewrite instance to apply transformations
        code: Code object being processed
    """
    def __init__(self, strategy, function):
        """
        Initialize fold traverser.
        
        Args:
            strategy: FoldRewrite instance
            function: Code object being processed
        """
        self.strategy = strategy
        self.code = function

    @dispatch(ast.leafTypes)
    def visitLeaf(self, node):
        """Visit leaf nodes (no children to process)."""
        return node

    @dispatch(list)
    def visitList(self, node):
        """
        Visit Python lists in AST.
        
        Handles raw Python lists that might appear in the AST structure.
        Only processes items that have rewriteChildren method.
        
        Args:
            node: List node
            
        Returns:
            List with processed items
        """
        # Handle raw Python lists that might appear in the AST
        return [self(item) for item in node if hasattr(item, 'rewriteChildren')]

    @defaultdispatch
    def default(self, node):
        """
        Default handler: process children first, then apply strategy.
        
        Bottom-up traversal: children are processed before the parent,
        enabling constant folding to work from leaves upward.
        
        Args:
            node: AST node to process
            
        Returns:
            Transformed node
        """
        # Bottom up: process children first
        return self.strategy(node.rewriteChildren(self))

    @dispatch(ast.CodeParameters)
    def visitCodeParameters(self, node):
        """
        Visit code parameters (not folded).
        
        Code parameters are not subject to constant folding.
        
        Args:
            node: CodeParameters node
            
        Returns:
            Node unchanged
        """
        return node

    @dispatch(ast.Assign)
    def visitAssign(self, node):
        """
        Visit assignment: fold expression but not targets.
        
        Only the expression is folded; assignment targets (lcls) are
        preserved as-is. This ensures variable names are not changed.
        
        Args:
            node: Assign node
            
        Returns:
            Assign node with folded expression
        """
        # Modified bottom up
        # Avoids folding assignment targets
        node = ast.Assign(self(node.expr), node.lcls)
        node = self.strategy(node)
        return node

    @dispatch(ast.Delete)
    def visitDelete(self, node):
        """
        Visit delete: don't fold delete targets.
        
        Delete targets are not folded to preserve the deletion semantics.
        
        Args:
            node: Delete node
            
        Returns:
            Node with strategy applied (but targets not folded)
        """
        # Avoids folding delete targets
        node = self.strategy(node)
        return node


def constMeet(values):
    """
    Meet function for constant propagation.
    
    Combines constant values from multiple control flow paths. If all paths
    have the same constant value, returns that value. Otherwise, returns
    top (indicating uncertainty).
    
    This implements the meet operation for the constant propagation lattice:
    - Same constant from all paths -> that constant
    - Different constants -> top (uncertain)
    - undefined (no info) -> ignored
    
    Args:
        values: List of constant values from different paths
        
    Returns:
        The constant if all paths agree, or top if they differ
    """
    prototype = values[0]
    for value in values[1:]:
        if value != prototype:
            return top
    return prototype


def evaluateCode(compiler, prgm, node):
    """
    Perform constant folding on a code node.
    
    This is the main entry point for constant folding. It performs:
    1. Forward data flow analysis to track constant values
    2. Constant folding of expressions (binary ops, unary ops, calls)
    3. Constant propagation through assignments
    4. Direct call conversion where possible
    
    For standard code, uses forward data flow analysis. For non-standard
    code (like stubs), performs simple bottom-up folding without data flow.
    
    Args:
        compiler: Compiler instance with extractor and other components
        prgm: Program being optimized (may be None)
        node: Code node to optimize
        
    Returns:
        The optimized code node (modified in place)
    """
    assert node.isCode(), type(node)

    # Get store graph if available
    if prgm is None:
        storeGraph = None
    else:
        storeGraph = prgm.storeGraph

    if node.isStandardCode():
        # Standard code: use forward data flow analysis
        analyze = FoldAnalysis()
        rewrite = FoldRewrite(compiler.extractor, storeGraph, node)
        rewriteS = FoldTraverse(rewrite, node)

        # Create forward flow traverser with constant meet function
        traverse = ForwardFlowTraverse(constMeet, analyze, rewriteS)
        t = MutateCode(traverse)

        # HACK: Share flow dictionary between analysis and rewrite
        analyze.flow = traverse.flow
        rewrite.flow = traverse.flow

        # Apply transformation
        t(node)
    else:
        # Non-standard code: simple bottom-up folding without data flow
        # HACK: bypass dataflow analysis, as there's no real "flow"
        rewrite = FoldRewrite(compiler.extractor, storeGraph, node)
        rewriteS = FoldTraverse(rewrite, node)
        node.replaceChildren(rewriteS)

    # Add newly created objects to extractor's object list
    existing = set(compiler.extractor.desc.objects)
    newobj = rewrite.created - existing

    for obj in newobj:
        compiler.extractor.desc.objects.append(obj)

    return node
