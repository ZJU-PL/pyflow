from pyflow.util.typedispatch import *
from pyflow.language.python import ast, program
from .constraints import qualifiers
from .calling import cpa


class MarkParameters(TypeDispatcher):
    def __init__(self, ce):
        self.ce = ce

    @dispatch(type(None), ast.DoNotCare)
    def visitNone(self, node):
        pass

    @dispatch(ast.Local)
    def visitLocal(self, node):
        cnode = self.ce(node)
        self.ce.context.params.append(cnode)
        cnode.critical.markCritical(self.ce.context, cnode)

    def process(self, codeParameters):
        self(codeParameters.selfparam)
        for param in codeParameters.params:
            self(param)

        self(codeParameters.vparam)
        self(codeParameters.kparam)

        for param in codeParameters.returnparams:
            self.ce.context.returns.append(self.ce(param))


class ConstraintExtractor(TypeDispatcher):
    def __init__(self, analysis, context, code):
        self.analysis = analysis
        self.context = context
        self.code = code

        self.existing = {}

    @dispatch(ast.leafTypes)
    def visitLeaf(self, node):
        return node

    @dispatch(ast.Local)
    def visitLocal(self, node, targets=None):
        lcl = self.context.local(node)

        if targets is None:
            return lcl
        else:
            assert len(targets) == 1
            self.context.assign(lcl, targets[0])

    def existingObject(self, object):
        assert isinstance(object, program.AbstractObject), object
        xtype = self.analysis.canonical.existingType(object)
        return self.analysis.objectName(xtype, qualifiers.GLBL)

    def existingTemp(self, obj):
        lcl = self.context.local(ast.Local("existing_temp"))
        lcl.updateSingleValue(obj)
        return lcl

    @dispatch(ast.Existing)
    def visitExisting(self, node, targets=None):
        obj = self.existingObject(node.object)

        if targets is None:
            # Just an argument, can be stuck in the same region
            if obj not in self.existing:
                lcl = self.existingTemp(obj)
                self.existing[obj] = lcl
            else:
                lcl = self.existing[obj]
            return lcl
        else:
            # Assigned somewhere else, avoid collapsing regions
            assert len(targets) == 1
            lcl = self.existingTemp(obj)
            self.context.assign(lcl, targets[0])

    @dispatch(ast.DoNotCare)
    def visitDoNotCare(self, node):
        return None

    def call(self, node, expr, args, kwds, vargs, kargs, targets):
        assert not kwds, self.code
        assert kargs is None, self.code

        # Handle cases where both selfarg and vargs are None (e.g., function calls without 'self')
        if expr is None and vargs is None:
            # Skip this call as it's likely an invalid/unresolvable call
            return None

        self.context.call(node, expr, args, kwds, vargs, kargs, targets)

    def dcall(self, node, code, expr, args, kwds, vargs, kargs, targets):
        assert not kwds, self.code
        assert kargs is None, self.code

        self.context.dcall(node, code, expr, args, kwds, vargs, kargs, targets)

    def allocate(self, node, expr, targets):
        assert expr.isNode(), expr
        assert len(targets) == 1
        self.context.allocate(node, expr, targets[0])

    def load(self, node, expr, fieldtype, name, targets):
        assert len(targets) == 1
        self.context.load(expr, fieldtype, name, targets[0])

    def check(self, node, expr, fieldtype, name, targets):
        assert len(targets) == 1
        self.context.check(expr, fieldtype, name, targets[0])

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

    @dispatch(ast.DirectCall)
    def visitDirectCall(self, node, targets=None):
        return self.dcall(
            node,
            node.code,
            self(node.selfarg),
            self(node.args),
            self(node.kwds),
            self(node.vargs),
            self(node.kargs),
            targets,
        )

    @dispatch(ast.Is)
    def visitIs(self, node, targets):
        assert len(targets) == 1
        return self.context.is_(self(node.left), self(node.right), targets[0])

    @dispatch(ast.Allocate)
    def visitAllocate(self, node, targets):
        return self.allocate(node, self(node.expr), targets)

    @dispatch(ast.Load)
    def visitLoad(self, node, targets):
        return self.load(
            node, self(node.expr), node.fieldtype, self(node.name), targets
        )

    @dispatch(ast.Check)
    def visitCheck(self, node, targets):
        return self.check(
            node, self(node.expr), node.fieldtype, self(node.name), targets
        )

    @dispatch(ast.Assign)
    def visitAssign(self, node):
        self(node.expr, self(node.lcls))

    @dispatch(ast.Discard)
    def visitDiscard(self, node):
        self(node.expr, None)

    @dispatch(ast.Return)
    def visitReturn(self, node):
        # Tolerate mismatch or None expressions
        params = self(self.codeParameters.returnparams)
        expr_nodes = []
        for e in node.exprs:
            if e is None:
                expr_nodes.append(None)
            else:
                expr_nodes.append(self(e))

        for expr, param in zip(expr_nodes, params):
            if expr is not None:
                self.context.assign(expr, param)

    @dispatch(list, tuple)
    def visitList(self, node):
        return [self(child) for child in node]

    @dispatch(ast.BuildList)
    def visitBuildList(self, node, targets=None):
        # Evaluate list elements for side effects; lists themselves are pure values
        elts = self(node.args)
        if targets is not None:
            # Assign a placeholder temp if needed
            temp = self.context.local(ast.Local("tmp_list"))
            # No actual allocation modeled here; just propagate existence
            for _ in elts:
                pass
            self.context.assign(temp, targets[0])
        else:
            return None

    @dispatch(ast.BuildTuple)
    def visitBuildTuple(self, node, targets=None):
        # Evaluate tuple elements for side effects; tuples themselves are pure values
        elts = self(node.args)
        if targets is not None:
            # Assign a placeholder temp if needed
            temp = self.context.local(ast.Local("tmp_tuple"))
            # No actual allocation modeled here; just propagate existence
            for _ in elts:
                pass
            self.context.assign(temp, targets[0])
        else:
            return None

    @dispatch(ast.BuildMap)
    def visitBuildMap(self, node, targets=None):
        # Evaluate map elements for side effects; maps themselves are pure values
        # Note: BuildMap is used for dict literals
        if targets is not None:
            # Assign a placeholder temp if needed
            temp = self.context.local(ast.Local("tmp_dict"))
            self.context.assign(temp, targets[0])
        else:
            return None

    @dispatch(ast.TryExceptFinally)
    def visitTryExceptFinally(self, node, targets=None):
        # Evaluate try block and handlers for side effects
        # Note: TryExceptFinally is used for try/except/finally blocks
        self(node.body)
        for handler in node.handlers:
            self(handler)
        if node.else_:
            self(node.else_)
        if node.finally_:
            self(node.finally_)
        if targets is not None:
            # Assign a placeholder temp if needed
            temp = self.context.local(ast.Local("tmp_try"))
            self.context.assign(temp, targets[0])
        else:
            return None

    @dispatch(ast.ExceptionHandler)
    def visitExceptionHandler(self, node, targets=None):
        # Evaluate exception handler for side effects
        # Note: ExceptionHandler is used for except blocks
        self(node.preamble)
        self(node.body)
        if targets is not None:
            # Assign a placeholder temp if needed
            temp = self.context.local(ast.Local("tmp_except"))
            self.context.assign(temp, targets[0])
        else:
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
            # Assign a placeholder temp if needed
            temp = self.context.local(ast.Local("tmp_raise"))
            self.context.assign(temp, targets[0])
        else:
            return None

    @dispatch(ast.FunctionDef)
    def visitFunctionDef(self, node, targets=None):
        # Evaluate function definition for side effects (name, decorators, etc.)
        # The actual function body is handled separately via the code object
        if targets is not None:
            # Assign a placeholder temp if needed
            temp = self.context.local(ast.Local("tmp_funcdef"))
            self.context.assign(temp, targets[0])
        else:
            return None

    @dispatch(ast.ClassDef)
    def visitClassDef(self, node, targets=None):
        # Evaluate class definition for side effects (name, bases, decorators, body)
        # Class definitions themselves don't need complex analysis for IPA
        if targets is not None:
            # Assign a placeholder temp if needed
            temp = self.context.local(ast.Local("tmp_classdef"))
            self.context.assign(temp, targets[0])
        else:
            return None

    @dispatch(ast.GetAttr)
    def visitGetAttr(self, node, targets=None):
        obj = self(node.expr)
        name = self(node.name)
        if obj is None:
            if targets is None:
                return None
            else:
                # Can't load attribute from None, assign None to target
                return
        if targets is None:
            tmp = self.context.local(ast.Local("attr_tmp"))
            self.load(node, obj, "Attribute", name, [tmp])
            return tmp
        else:
            self.load(node, obj, "Attribute", name, targets)

    @dispatch(ast.SetAttr)
    def visitSetAttr(self, node):
        obj = self(node.expr)
        name = self(node.name)
        value = self(node.value)
        self.context.store(value, obj, "Attribute", name)

    @dispatch(ast.DeleteAttr)
    def visitDeleteAttr(self, node):
        # Treat as a check/use of the attribute
        obj = self(node.expr)
        name = self(node.name)
        tmp = self.context.local(ast.Local("delattr_chk"))
        self.check(node, obj, "Attribute", name, [tmp])

    @dispatch(ast.Suite, ast.Condition, ast.Switch, ast.Assert)
    def visitOK(self, node):
        node.visitChildren(self)
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

    @dispatch(ast.Break)
    def visitBreak(self, node):
        pass

    @dispatch(ast.Continue)
    def visitContinue(self, node):
        pass

    def vparamObj(self):
        inst = self.analysis.pyObjInst(tuple)
        xtype = self.analysis.canonical.contextType(self.context.signature, inst, None)
        return self.analysis.objectName(xtype, qualifiers.HZ)

    def setupVParam(self, vparam):
        # Assign the vparam object to the vparam local
        vparamObj = self.vparamObj()
        lcl = self.context.local(vparam)
        lcl.updateSingleValue(vparamObj)

        numVParam = len(self.context.signature.vparams)

        # Set the length of the vparam object
        slot = self.context.field(vparamObj, "LowLevel", self.analysis.pyObj("length"))
        slot.clearNull()
        slot.updateSingleValue(self.context.allocatePyObj(numVParam))

        # Copy the vparam locals into the vparam fields
        for i in range(numVParam):
            # Create a vparam field
            slot = self.context.field(vparamObj, "Array", self.analysis.pyObj(i))
            slot.clearNull()
            self.context.vparamField.append(slot)
            slot.critical.markCritical(self.context, slot)

    def doFold(self):
        foldFunc = self.code.annotation.dynamicFold
        if foldFunc:
            sig = self.context.signature

            # TODO ignoring selfparam?

            params = []
            for param in sig.params:
                if param and param is not cpa.anyType and param.isExisting():
                    params.append(param.obj.pyobj)
                else:
                    return

            for param in sig.vparams:
                if param and param is not cpa.anyType and param.isExisting():
                    params.append(param.obj.pyobj)
                else:
                    return

            try:
                result = foldFunc(*params)
            except:
                return

            obj = self.context.analysis.pyObj(result)
            self.context.foldObj = self.existingObject(obj)

    ### Entry point ###
    def process(self):
        code = self.code
        self.codeParameters = code.codeParameters()

        MarkParameters(self).process(self.codeParameters)

        vparam = self.codeParameters.vparam
        if vparam and not vparam.isDoNotCare():
            self.setupVParam(vparam)

        if code.isStandardCode():
            self(code.ast)
        else:
            code.extractConstraints(self)

        self.doFold()


def evaluate(analysis, context, code):
    ce = ConstraintExtractor(analysis, context, code)
    ce.process()
