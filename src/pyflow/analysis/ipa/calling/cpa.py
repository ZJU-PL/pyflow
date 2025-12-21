import itertools
from pyflow.util import canonical
from pyflow.analysis.storegraph import extendedtypes


def cpaArgOK(arg):
    return arg is None or arg is anyType or isinstance(arg, extendedtypes.ExtendedType)


class CPAContextSignature(canonical.CanonicalObject):
    def __init__(self, code, selfparam, params, vparams):

        assert cpaArgOK(selfparam), selfparam
        for param in params:
            assert cpaArgOK(param), param
        for param in vparams:
            assert cpaArgOK(param), param

        self.code = code
        self.selfparam = selfparam
        self.params = params
        self.vparams = vparams

        # Sanity check, probably a runaway loop in the analysis logic.
        assert len(vparams) < 30, code

        self.setCanonical(code, selfparam, params, vparams)

    def __repr__(self):
        return "cpa(%r, %r, %r, %r/%d)" % (
            self.code,
            self.selfparam,
            self.params,
            self.vparams,
            id(self),
        )


anyType = object()
nullIter = (None,)


class CPATypeSigBuilder(object):
    def __init__(self, analysis, call, info):
        self.analysis = analysis
        self.call = call

        self.code = self.call.code
        self.selfparam = None
        self.params = [None for i in range(info.numParams())]
        self.vparams = [None for i in range(info.numVParams())]

        assert not info.numKParams()

    def unusedSelfParam(self):
        self.selfparam = nullIter

    def setSelfParam(self, value):
        if value is None:
            self.selfparam = nullIter
        else:
            self.selfparam = value

    def unusedParam(self, index):
        self.params[index] = nullIter

    def setParam(self, index, value):
        if value is None:
            self.params[index] = nullIter
        else:
            self.params[index] = value

    def unusedVParam(self, index):
        self.vparams[index] = nullIter

    def setVParam(self, index, value):
        if value is None:
            self.vparams[index] = nullIter
        else:
            self.vparams[index] = value

    def getSelfArg(self):
        if self.call.selfarg is None:
            return None
        return self.call.selfarg.typeSplit.types()

    def getArg(self, index):
        if index >= len(self.call.args) or self.call.args[index] is None:
            return None
        return self.call.args[index].typeSplit.types()

    def getVArg(self, index):
        if index >= len(self.call.vargSlots) or self.call.vargSlots[index] is None:
            return None
        return self.call.vargSlots[index].typeSplit.types()

    def getDefault(self, index):
        if index >= len(self.call.defaultSlots) or self.call.defaultSlots[index] is None:
            return None
        return self.call.defaultSlots[index].typeSplit.types()

    def setReturnArg(self, i, value):
        pass

    def getReturnParam(self, i):
        pass

    def flatten(self):
        flat = [self.selfparam]
        flat.extend(self.params)
        flat.extend(self.vparams)
        return flat

    def split(self, flat):
        psplit = len(self.params) + 1
        return flat[0], flat[1:psplit], flat[psplit:]

    def signatures(self):
        results = []
        for concrete in itertools.product(*self.flatten()):
            selfparam, params, vparams = self.split(concrete)

            sig = CPAContextSignature(self.code, selfparam, params, vparams)
            results.append(sig)

        return results


externalContext = CPAContextSignature(None, None, (), ())
