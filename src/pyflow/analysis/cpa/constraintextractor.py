"""Constraint extractor for CPA (Constraint-based Analysis).

This module provides the ExtractDataflow class, which traverses Python AST nodes
and extracts constraints representing data flow relationships. The extractor visits
each AST node and creates appropriate constraints in the CPA system.

The extractor handles:
- Variable assignments and data flow
- Function calls (direct and indirect)
- Object field access (load/store)
- Object allocation
- Control flow (switches, loops)
- Type checks and assertions

Key design:
- Uses TypeDispatcher for AST traversal
- Creates constraints lazily (only once per node)
- Handles complex Python constructs (closures, generators, etc.)
"""

from pyflow.util.typedispatch import *
from pyflow.language.python import ast
from pyflow.ir.core import format_source

# from pyflow.language.python import program
# from pyflow.language.python import annotations

from . import constraints
from .constraints import (
    IsConstraint,
    DeferedSwitchConstraint,
    DeferedTypeSwitchConstraint,
)

# from pyflow.analysis import cpasignature
import pyflow.analysis as analysis


class ExtractDataflow(TypeDispatcher):
    """Extracts data flow constraints from Python AST nodes.

    This class traverses the AST representation of Python code and creates
    constraints that model data flow relationships. It uses the TypeDispatcher
    pattern to visit different AST node types and extract appropriate constraints.

    The extractor operates in a specific analysis context and creates constraints
    that connect abstract values (slots) in the store graph. Constraints are
    created lazily - each node is processed only once to avoid redundant work.

    Attributes:
        system: The CPA system instance (InterproceduralDataflow)
        context: AnalysisContext for this extraction
        folded: Whether this function was constant-folded
        code: Code object being analyzed
        processed: Set of nodes that have been processed (currently unused)
    """

    def __init__(self, system, context, folded):
        """Initialize the constraint extractor.

        Args:
            system: The CPA system instance
            context: AnalysisContext for this extraction
            folded: Whether the function was constant-folded (skip constraint extraction)
        """
        self.system = system
        self.context = context
        self.folded = folded
        self.code = self.context.signature.code

        self.processed = set()
        self._tmpuid = 0

    @property
    def exports(self):
        """Get exports from the extractor's stubs.

        Returns:
            Dictionary of exported stub functions
        """
        return self.system.extractor.intrinsic_manager.stubs.exports

    def doOnce(self, node):
        """Check if a node should be processed only once.

        Bug M fix: the original implementation had ``return True`` as the
        very first statement, making the rest of the method dead code.  This
        caused every node to be processed on every visit, creating duplicate
        constraints (e.g. duplicate CallConstraints for the same call site)
        which bloated the constraint graph and could cause incorrect analysis
        results.  The fix removes the early ``return True`` so that the
        processed-set guard actually runs.

        Args:
            node: AST node to check

        Returns:
            bool: True if the node has not been processed before (first visit)
        """
        if node not in self.processed:
            self.processed.add(node)
            return True
        else:
            return False

    def localSlot(self, lcl):
        """Get the store graph slot for a local variable.

        Maps an AST Local node to its corresponding slot in the store graph
        for this analysis context.

        Args:
            lcl: AST Local node (or None)

        Returns:
            SlotNode for the local variable, or None
        """
        if lcl is not None:
            sys = self.system
            name = sys.canonical.localName(self.code, lcl, self.context)
            group = self.context.group
            return group.root(name)
        else:
            return None

    def _freshLocalSlot(self, prefix):
        slot = self.localSlot(ast.Local("%s_%d" % (prefix, self._tmpuid)))
        self._tmpuid += 1
        return slot

    def existingSlot(self, obj):
        """Get the store graph slot for an existing object.

        Maps a Python object to its corresponding slot in the store graph.
        Used for constants and other existing objects.

        Args:
            obj: Python object (program.Object)

        Returns:
            SlotNode for the existing object
        """
        sys = self.system
        name = sys.canonical.existingName(self.code, obj, self.context)
        group = self.context.group
        return group.root(name)

    def contextOp(self, node):
        """Get the operation context for an AST node.

        Creates a canonical operation context that combines the code, AST node,
        and analysis context. Used for logging operations in constraints.

        Args:
            node: AST node (or None)

        Returns:
            OpContext for this operation
        """
        return self.system.canonical.opContext(self.code, node, self.context)

    def directCall(self, node, code, selfarg, args, vargs, kargs, targets):
        if self.doOnce(node):
            if not code.isCode():
                catalog = self.code.ir_catalog
                trace = format_source(catalog.source_of(node, code=self.code))
                assert False, ("Incorrect code parameter %r\n" % code) + trace
            op = self.contextOp(node)
            kwds = []  # HACK
            constraints.DirectCallConstraint(
                self.system, op, code, selfarg, args, kwds, vargs, kargs, targets
            )
        return targets

    def assign(self, src, dst):
        self.system.createAssign(src, dst)

    def init(self, node, obj):
        result = self.existingSlot(obj)
        if self.doOnce(node):
            sys = self.system
            result.initializeType(sys.canonical.existingType(obj))
        return result

    def call(self, node, expr, args, kwds, vargs, kargs, targets):
        # HACK for all the examples we have, indirect calls should be resolved after the first pass!
        # In the future this may not be the case.
        # Note: Removed assertion that required firstPass=True as it prevented second pass from working

        # Fast path: if the callee is an Existing object we can resolve up-front,
        # treat it as a direct call so folding and stub resolution work.
        if isinstance(node.expr, ast.Existing):
            target_code = self.system.getCall(node.expr.object)
            if target_code is not None:
                constraints.DirectCallConstraint(
                    self.system,
                    self.contextOp(node),
                    target_code,
                    None,
                    args,
                    [],
                    vargs,
                    kargs,
                    targets,
                )
                return targets

        if self.doOnce(node):
            op = self.contextOp(node)
            # Filter out None values from kwds
            filtered_kwds = [
                kw
                for kw in kwds
                if kw is not None
                and (
                    not isinstance(kw, (list, tuple))
                    or (len(kw) >= 2 and kw[0] is not None)
                )
            ]
            constraints.CallConstraint(
                self.system, op, expr, args, filtered_kwds, vargs, kargs, targets
            )
        return targets

    def isOp(self, node, left, right, targets):
        if self.doOnce(node):
            assert len(targets) == 1
            op = self.contextOp(node)
            IsConstraint(self.system, op, left, right, targets[0])
        return targets

    def load(self, node, expr, fieldtype, name, targets):
        if self.doOnce(node):
            assert len(targets) == 1
            op = self.contextOp(node)
            constraints.LoadConstraint(
                self.system, op, expr, fieldtype, name, targets[0]
            )
        return targets

    def store(self, node, expr, fieldtype, name, value):
        op = self.contextOp(node)
        constraints.StoreConstraint(self.system, op, expr, fieldtype, name, value)

    def allocate(self, node, expr, targets):
        if self.doOnce(node):
            assert len(targets) == 1
            op = self.contextOp(node)
            constraints.AllocateConstraint(self.system, op, expr, targets[0])
        return targets

    def check(self, node, expr, fieldtype, name, targets):
        if self.doOnce(node):
            assert len(targets) == 1
            op = self.contextOp(node)
            constraints.CheckConstraint(
                self.system, op, expr, fieldtype, name, targets[0]
            )
        return targets

    ##################################
    ### Generic feature extraction ###
    ##################################

    @dispatch(str, type(None))
    def visitJunk(self, node):
        pass

    @dispatch(ast.Suite, ast.Condition)
    def visitOK(self, node):
        node.visitChildren(self)

    @dispatch(ast.Assert)
    def visitAssert(self, node, targets=None):
        # Evaluate assert test and optional message for side effects
        if node.test:
            self(node.test)
        if node.message:
            self(node.message)
        if targets is not None:
            assert len(targets) == 1
            # No assignment semantics for assert; just ignore
            pass
        return None

    @dispatch(list)
    def visitList(self, node):
        return [self(child) for child in node if child is not None]

    @dispatch(tuple)
    def visitTuple(self, node):
        # Filter out tuples where the first element is None (invalid keyword args)
        if len(node) >= 2 and node[0] is None:
            return None
        return tuple([self(child) for child in node if child is not None])

    @dispatch(ast.Call)
    def visitCall(self, node, targets=None):
        return self.call(
            node,
            self(node.expr),
            self(node.args),
            self(node.kwds),
            self(node.vargs),
            self(node.kargs),
            targets,
        )

    # ------------------------------------------------------------------
    # Container literal helpers
    # ------------------------------------------------------------------

    def _existingKeySlot(self, pyobj):
        """Return an initialised slot for a constant key object.

        Args:
            pyobj: Python object to use as the key (int index, string, sentinel …)

        Returns:
            SlotNode already initialised with the existingType for *pyobj*.
        """
        obj = self.system.extractor.getObject(pyobj)
        slot = self.existingSlot(obj)
        slot.initializeType(self.system.canonical.existingType(obj))
        return slot

    def _allocateContainer(self, node, python_type, targets):
        """Emit an AllocateConstraint for a container type.

        Args:
            node:        AST node (used as the operation anchor).
            python_type: The Python type object (list, tuple, dict …).
            targets:     Single-element list of destination SlotNodes.

        Returns:
            OpContext for the allocation (reuse for subsequent stores).
        """
        op = self.contextOp(node)
        type_obj = self.system.extractor.getObject(python_type)
        type_slot = self.existingSlot(type_obj)
        type_slot.initializeType(self.system.canonical.existingType(type_obj))
        constraints.AllocateConstraint(self.system, op, type_slot, targets[0])
        return op

    def _storeContainerLength(self, op, target_slot, length):
        """Store the integer *length* into the LowLevel/length slot of a container.

        Args:
            op:          OpContext for the store.
            target_slot: SlotNode for the container object.
            length:      Integer length value.
        """
        length_key_slot = self._existingKeySlot("length")
        length_val_slot = self._existingKeySlot(length)
        constraints.StoreConstraint(
            self.system, op, target_slot, "LowLevel", length_key_slot, length_val_slot
        )

    # ------------------------------------------------------------------
    # BuildTuple  –  precise per-index Array slots
    # ------------------------------------------------------------------

    @dispatch(ast.BuildTuple)
    def visitBuildTuple(self, node, targets=None):
        """Model a tuple literal with precise per-index Array slots.

        Each element is stored into Array/<i> on the freshly allocated tuple
        object, mirroring the *args tuple mechanism used by the CPA engine.
        """
        # Evaluate all element expressions first (may have side effects).
        arg_slots = [self(arg) for arg in node.args]

        if targets is None:
            return None

        assert len(targets) == 1

        op = self._allocateContainer(node, tuple, targets)
        self._storeContainerLength(op, targets[0], len(node.args))

        for i, arg_slot in enumerate(arg_slots):
            if arg_slot is not None:
                idx_key_slot = self._existingKeySlot(i)
                constraints.StoreConstraint(
                    self.system, op, targets[0], "Array", idx_key_slot, arg_slot
                )

    # ------------------------------------------------------------------
    # BuildList  –  summary Array slot (array smashing)
    # ------------------------------------------------------------------

    # Sentinel key used for the summary (smashed) element slot.
    _LIST_SUMMARY_KEY = "*"

    @dispatch(ast.BuildList)
    def visitBuildList(self, node, targets=None):
        """Model a list literal using a summary Array slot.

        All elements are merged into a single Array/"*" slot so that any
        subsequent load from the list returns the union of element types.
        The length is stored precisely when it is statically known.
        """
        arg_slots = [self(arg) for arg in node.args]

        if targets is None:
            return None

        assert len(targets) == 1

        op = self._allocateContainer(node, list, targets)
        self._storeContainerLength(op, targets[0], len(node.args))

        summary_key_slot = self._existingKeySlot(self._LIST_SUMMARY_KEY)
        for arg_slot in arg_slots:
            if arg_slot is not None:
                constraints.StoreConstraint(
                    self.system, op, targets[0], "Array", summary_key_slot, arg_slot
                )

    # ------------------------------------------------------------------
    # BuildMap  –  precise Dictionary slots for constant keys, summary otherwise
    # ------------------------------------------------------------------

    # Sentinel key used for the summary (smashed) value slot.
    _DICT_SUMMARY_KEY = "*"

    @dispatch(ast.BuildMap)
    def visitBuildMap(self, node, targets=None):
        """Model a dict literal with per-key Dictionary slots where possible.

        For each (key, value) pair:
        - If the key is an ast.Existing constant, store into Dictionary/<key>.
        - Otherwise merge into the summary Dictionary/"*" slot.

        This gives precise lookup for string/int-keyed dicts (the common case)
        while remaining sound for dynamic keys.
        """
        # node.args is a flat list [key0, val0, key1, val1, …]
        pairs = list(zip(node.args[0::2], node.args[1::2]))

        # Evaluate all sub-expressions first.
        evaluated = [(self(k), self(v)) for k, v in pairs]

        if targets is None:
            return None

        assert len(targets) == 1

        op = self._allocateContainer(node, dict, targets)
        self._storeContainerLength(op, targets[0], len(pairs))

        summary_key_slot = None  # created lazily

        for (k_node, _v_node), (k_slot, v_slot) in zip(pairs, evaluated):
            if v_slot is None:
                continue

            if isinstance(k_node, ast.Existing):
                # Precise: use the constant key object directly.
                key_slot = self._existingKeySlot(k_node.object)
            else:
                # Dynamic key: fall back to summary slot.
                if summary_key_slot is None:
                    summary_key_slot = self._existingKeySlot(self._DICT_SUMMARY_KEY)
                key_slot = summary_key_slot

            constraints.StoreConstraint(
                self.system, op, targets[0], "Dictionary", key_slot, v_slot
            )

    @dispatch(ast.BuildSlice)
    def visitBuildSlice(self, node, targets=None):
        # Evaluate slice components for side effects; slices are pure values
        return None

    @dispatch(ast.FunctionDef)
    def visitFunctionDef(self, node, targets=None):
        for default in node.code.codeparameters.defaults:
            self(default)
        for decorator in node.decorators:
            self(decorator)
        if targets is not None:
            assert len(targets) == 1
        return None

    @dispatch(ast.ClassDef)
    def visitClassDef(self, node, targets=None):
        for base in node.bases:
            self(base)
        for keyword in node.keywords:
            if isinstance(keyword, (tuple, list)) and len(keyword) == 2:
                self(keyword[1])
        self(node.body)
        for decorator in node.decorators:
            self(decorator)
        if targets is not None:
            assert len(targets) == 1
        return None

    @dispatch(ast.Import)
    def visitImport(self, node, targets=None):
        # Import statements are handled at module level, skip for dataflow
        return None

    @dispatch(ast.GlobalDecl, ast.NonlocalDecl)
    def visitScopeDecl(self, node, targets=None):
        return None

    @dispatch(ast.TypeAlias)
    def visitTypeAlias(self, node, targets=None):
        del node, targets
        return None

    def _shared_placeholder(self, node, label: str):
        return self.init(node, self.system.extractor.getObject(label))

    @dispatch(ast.GetGlobal, ast.GetCellDeref)
    def visitSharedRead(self, node, targets=None):
        value = self._shared_placeholder(node, f"__pyflow_shared__:{type(node).__name__}")
        if targets is not None:
            assert len(targets) == 1
            self.assign(value, targets[0])
            return targets
        return value

    @dispatch(ast.SetGlobal, ast.SetCellDeref)
    def visitSharedWrite(self, node, targets=None):
        value = self(node.value)
        if value is not None:
            self.assign(
                value,
                self._shared_placeholder(
                    node, f"__pyflow_shared__:{type(node).__name__}"
                ),
            )
        del targets
        return None

    @dispatch(ast.DeleteGlobal)
    def visitDeleteGlobal(self, node, targets=None):
        del node, targets
        return None

    @dispatch(ast.Yield)
    def visitYield(self, node, targets=None):
        return None

    @dispatch(ast.YieldFrom)
    def visitYieldFrom(self, node, targets=None):
        if node.expr:
            self(node.expr)
        return None

    @dispatch(ast.Await)
    def visitAwait(self, node, targets=None):
        value = self(node.expr)
        if targets is not None and value is not None:
            assert len(targets) == 1
            self.assign(value, targets[0])
            return targets
        return value

    @dispatch(ast.NamedExpr)
    def visitNamedExpr(self, node, targets=None):
        value = self(node.value)
        local = self.localSlot(node.target)
        if value is not None:
            self.assign(value, local)
        if targets is not None:
            assert len(targets) == 1
            self.assign(local, targets[0])
            return targets
        return local

    @dispatch(ast.ConditionalExpr)
    def visitConditionalExpr(self, node, targets=None):
        """Merge the possible types from both arms of a conditional expression."""
        self(node.test)

        result = None
        if targets is None:
            result = self._freshLocalSlot("conditional")
            targets = [result]

        self(node.body, targets)
        self(node.orelse, targets)
        return result

    @dispatch(ast.AnnAssign)
    def visitAnnAssign(self, node):
        if getattr(node, "value", None) is None:
            return None
        value = self(node.value)
        if value is not None:
            self.assign(value, self.localSlot(node.target))
        return None

    @dispatch(ast.ShortCircutAnd, ast.ShortCircutOr)
    def visitShortCircutBool(self, node, targets=None):
        for term in node.terms:
            self(term)
        return None

    @dispatch(ast.MakeFunction)
    def visitMakeFunction(self, node, targets=None):
        # Lambda functions are pure values, skip constraint extraction
        # The lambda body is analyzed separately when the lambda is called
        return None

    @dispatch(ast.TryExceptFinally)
    def visitTryExceptFinally(self, node, targets=None):
        # Evaluate try block and handlers for side effects
        self(node.body)
        for handler in node.handlers:
            self(handler)
        if node.else_:
            self(node.else_)
        if node.finally_:
            self(node.finally_)
        if targets is not None:
            assert len(targets) == 1
            # Just pass for try/except blocks
            pass
        return None

    @dispatch(ast.ExceptionHandler)
    def visitExceptionHandler(self, node, targets=None):
        # Evaluate exception handler for side effects
        self(node.preamble)
        self(node.body)
        if targets is not None:
            assert len(targets) == 1
            # Just pass for exception handlers
            pass
        return None

    @dispatch(ast.Raise)
    def visitRaise(self, node, targets=None):
        # Evaluate raise expression for side effects
        if node.exception:
            self(node.exception)
        if node.parameter:
            self(node.parameter)
        if node.traceback:
            self(node.traceback)
        if targets is not None:
            assert len(targets) == 1
            # Just pass for raise statements
            pass
        return None

    @dispatch(ast.GetAttr)
    def visitGetAttr(self, node, targets=None):
        obj = self(node.expr)
        name = self(node.name)
        if targets is not None:
            assert len(targets) == 1
            # For attribute access, we need to load from the object
            # This is a simplified version - in practice this would need more complex handling
            pass
        return obj

    @dispatch(ast.SetAttr)
    def visitSetAttr(self, node):
        obj = self(node.expr)
        name = self(node.name)
        value = self(node.value)
        # For attribute assignment, we need to store to the object
        # This is a simplified version - in practice this would need more complex handling
        pass

    @dispatch(ast.DirectCall)
    def visitDirectCall(self, node, targets=None):
        return self.directCall(
            node,
            node.code,
            self(node.selfarg),
            self(node.args),
            self(node.vargs),
            self(node.kargs),
            targets,
        )

    @dispatch(ast.Assign)
    def visitAssign(self, node):
        self(node.expr, self(node.lcls))

    @dispatch(ast.Discard)
    def visitDiscard(self, node):
        self(node.expr, None)

    @dispatch(ast.Return)
    def visitReturn(self, node):
        if not self.folded:
            callee = self.code.codeParameters()

            # Handle mismatched return expressions gracefully
            if len(node.exprs) != len(callee.returnparams):
                # Use the minimum length to avoid index errors
                min_len = min(len(node.exprs), len(callee.returnparams))
                for expr, param in zip(
                    node.exprs[:min_len], callee.returnparams[:min_len]
                ):
                    # Prefer evaluating expression into the return slot when possible
                    dst = self(param)
                    if dst is not None:
                        self(expr, [dst])
                    else:
                        self.assign(self(expr), dst)
            else:
                for expr, param in zip(node.exprs, callee.returnparams):
                    dst = self(param)
                    if dst is not None:
                        self(expr, [dst])
                    else:
                        self.assign(self(expr), dst)

    @dispatch(ast.Local)
    def visitLocal(self, node, targets=None):
        value = self.localSlot(node)

        if targets is not None:
            assert len(targets) == 1
            self.assign(value, targets[0])
        else:
            return value

    @dispatch(ast.DoNotCare)
    def visitDoNotCare(self, node):
        return analysis.cpasignature.DoNotCare

    @dispatch(ast.Existing)
    def visitExisting(self, node, targets=None):
        value = self.init(node.object, node.object)

        if targets is not None:
            targets[0].initializeType(self.system.canonical.existingType(node.object))
        else:
            return value

    @dispatch(ast.Is)
    def visitIs(self, node, targets):
        return self.isOp(node, self(node.left), self(node.right), targets)

    @dispatch(ast.Load)
    def visitLoad(self, node, targets):
        return self.load(
            node, self(node.expr), node.fieldtype, self(node.name), targets
        )

    @dispatch(ast.Store)
    def visitStore(self, node):
        return self.store(
            node, self(node.expr), node.fieldtype, self(node.name), self(node.value)
        )

    @dispatch(ast.Allocate)
    def visitAllocate(self, node, targets):
        return self.allocate(node, self(node.expr), targets)

    @dispatch(ast.Check)
    def visitCheck(self, node, targets):
        return self.check(
            node, self(node.expr), node.fieldtype, self(node.name), targets
        )

    @dispatch(ast.Switch)
    def visitSwitch(self, node):
        self(node.condition)

        cond = self.localSlot(node.condition.conditional)
        DeferedSwitchConstraint(self.system, self, cond, node.t, node.f)

    @dispatch(ast.TypeSwitch)
    def visitTypeSwitch(self, node):
        op = self.contextOp(None)  # HACK logs the read onto the code.
        cond = self.localSlot(node.conditional)
        DeferedTypeSwitchConstraint(self.system, op, self, cond, node.cases)

    @dispatch(ast.Break)
    def visitBreak(self, node):
        pass  # Flow insensitive

    @dispatch(ast.Continue)
    def visitContinue(self, node):
        pass  # Flow insensitive

    @dispatch(ast.While)
    def visitWhile(self, node):
        self(node.condition)
        self(node.body)

        if node.else_:
            self(node.else_)

    @dispatch(ast.For)
    def visitFor(self, node):
        self(node.loopPreamble)

        self(node.bodyPreamble)
        self(node.body)

        if node.else_:
            self(node.else_)

    @dispatch(ast.Code)
    def visitCode(self, node):
        self(node.ast)

    ### Entry point ###
    def process(self):
        if self.code.isStandardCode():
            self(self.code)
        else:
            self.code.extractConstraints(self)
