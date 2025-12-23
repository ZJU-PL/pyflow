"""Call binding for IPA.

This module provides call binding functionality that connects call sites
to callee contexts, transferring arguments and return values.
"""

class CallBinder(object):
    """Binds call sites to callee contexts.
    
    CallBinder transfers arguments from call sites to callee parameters
    and return values from callees back to call sites. It uses type
    filtering to match call arguments to callee parameters.
    
    Attributes:
        call: Call constraint (source)
        invoke: Invocation connecting call to context
        context: Callee context (destination)
        params: Code parameters for the callee
    """
    def __init__(self, call, context):
        """Initialize call binder.
        
        Args:
            call: Call constraint (FlatCallConstraint)
            context: Callee context to bind to
        """
        # Source
        self.call = call
        self.invoke = call.context.getInvoke(call.op, context)

        # Desination
        self.context = context
        self.params = self.context.signature.code.codeParameters()

    def getSelfArg(self):
        return self.call.selfarg

    def getArg(self, i):
        return self.call.args[i]

    def getVArg(self, i):
        return self.call.vargSlots[i]

    def getDefault(self, i):
        return self.call.defaultSlots[i]

    def unusedSelfParam(self):
        pass

    def unusedParam(self, i):
        pass

    def unusedVParam(self, i):
        pass

    def setSelfParam(self, value):
        typeFilter = self.context.signature.selfparam
        dst = self.context.local(self.params.selfparam)
        self.copyDownFiltered(value, typeFilter, dst)

    def setParam(self, i, value):
        typeFilter = self.context.signature.params[i]
        dst = self.context.local(self.params.params[i])
        self.copyDownFiltered(value, typeFilter, dst)

    def setVParam(self, i, value):
        typeFilter = self.context.signature.vparams[i]
        dst = self.context.vparamField[i]
        self.copyDownFiltered(value, typeFilter, dst)

    def getReturnParam(self, i):
        return self.context.returns[i]

    def setReturnArg(self, i, value):
        if self.context.foldObj:
            assert i == 0
            self.call.targets[i].updateSingleValue(self.context.foldObj)
        else:
            target = self.call.targets[i]
            self.invoke.up(value, target)

    def copyDownFiltered(self, src, typeFilter, dst):
        if src is None:
            return
        self.invoke.down(src.getFiltered(typeFilter), dst)


def bind(call, context, info):
    binder = CallBinder(call, context)
    info.transfer(binder, binder)
    return binder.invoke
