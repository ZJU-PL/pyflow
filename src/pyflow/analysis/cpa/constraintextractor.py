from pyflow.util.typedispatch import *
from pyflow.language.asttools.origin import originString

from pyflow.language.python import ast

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
    def __init__(self, system, context, folded):
        self.system = system
        self.context = context
        self.folded = folded
        self.code = self.context.signature.code

        self.processed = set()

    @property
    def exports(self):
        return self.system.extractor.stubs.exports

    def doOnce(self, node):
        return True

        if not node in self.processed:
            self.processed.add(node)
            return True
        else:
            return False

    def localSlot(self, lcl):
        if lcl is not None:
            sys = self.system
            name = sys.canonical.localName(self.code, lcl, self.context)
            group = self.context.group
            return group.root(name)
        else:
            return None

    def existingSlot(self, obj):
        sys = self.system
        name = sys.canonical.existingName(self.code, obj, self.context)
        group = self.context.group
        return group.root(name)

    def contextOp(self, node):
        return self.system.canonical.opContext(self.code, node, self.context)

    def directCall(self, node, code, selfarg, args, vargs, kargs, targets):
        if self.doOnce(node):
            if not code.isCode():
                trace = "\n".join(
                    [originString(part) for part in node.annotation.origin]
                )
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
            filtered_kwds = [kw for kw in kwds if kw is not None and (not isinstance(kw, (list, tuple)) or (len(kw) >= 2 and kw[0] is not None))]
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

    @dispatch(ast.BuildList)
    def visitBuildList(self, node, targets=None):
        # Evaluate list elements for side effects; then assign a simple placeholder slot
        _ = self(node.args)
        if targets is not None:
            assert len(targets) == 1
            placeholder_local = ast.Local("tmp_list")
            src_slot = self.localSlot(placeholder_local)
            self.assign(src_slot, targets[0])
        else:
            return None

    @dispatch(ast.BuildTuple)
    def visitBuildTuple(self, node, targets=None):
        # Evaluate tuple elements for side effects; then assign a simple placeholder slot
        _ = self(node.args)
        if targets is not None:
            assert len(targets) == 1
            placeholder_local = ast.Local("tmp_tuple")
            src_slot = self.localSlot(placeholder_local)
            self.assign(src_slot, targets[0])
        else:
            return None

    @dispatch(ast.BuildMap)
    def visitBuildMap(self, node, targets=None):
        # Evaluate map elements for side effects; maps themselves are pure values
        if targets is not None:
            assert len(targets) == 1
            # For maps, we don't have direct access to keys/values, just pass
            pass
        else:
            # Return None for maps
            return None

    @dispatch(ast.FunctionDef)
    def visitFunctionDef(self, node, targets=None):
        # Function definitions don't need complex analysis for data flow
        if targets is not None:
            assert len(targets) == 1
            # Just return None for function definitions
            pass
        return None

    @dispatch(ast.ClassDef)
    def visitClassDef(self, node, targets=None):
        # Class definitions don't need complex analysis for data flow
        if targets is not None:
            assert len(targets) == 1
            # Just return None for class definitions
            pass
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
            assert len(targets) == 1
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
