"""Call constraints for IPA.

This module provides constraints for modeling inter-procedural calls:
- CallConstraint: Indirect calls (resolved dynamically)
- DirectCallConstraint: Direct calls with known code
- ConcreteCallConstraint: Calls with concrete arguments
- FlatCallConstraint: Calls with flattened arguments (for CPA)

Call constraints resolve call sites to callee contexts and transfer
arguments and return values.
"""

import itertools
import logging
from ..calling import cpa, transfer, callbinder
from . import node

LOG = logging.getLogger(__name__)


class AbstractCall(object):
    """Base class for call constraints.

    Call constraints model inter-procedural calls. They maintain:
    - dirty flag: Whether call needs reprocessing
    - cache: Cache of resolved call contexts

    Attributes:
        dirty: Whether this call needs reprocessing
        cache: Dictionary caching resolved contexts
    """

    def __init__(self):
        """Initialize abstract call."""
        self.dirty = False
        self.cache = {}


def argIsOK(arg):
    return arg is None or isinstance(arg, node.ConstraintNode)


nullObjects = {None: None}


class UserCallConstraint(AbstractCall):
    def __init__(self, context, op, selfarg, args, kwds, varg, karg, targets):
        AbstractCall.__init__(self)
        self.context = context
        self.op = op
        self.selfarg = selfarg
        self.args = args
        self.kwds = kwds
        self.varg = varg
        self.karg = karg
        self.targets = targets

        self._unresolved_callee = self.selfarg is None and self.varg is None
        if self._unresolved_callee:
            LOG.warning(
                "creating call constraint with unresolved callee at %r; "
                "call will be skipped until callee information is available",
                op,
            )

        if self.selfarg:
            self.selfarg.attachExactSplit(self.splitChanged)

        if self.varg:
            self.varg.attachExactSplit(self.splitChanged)

    def splitChanged(self):
        if not self.dirty:
            self.dirty = True
            self.context.dirtyCall(self)

    def __repr__(self):
        return "[CALL %r(%r, %r, *%r, **%r) -> %r]" % (
            self.selfarg,
            self.args,
            self.kwds,
            self.varg,
            self.karg,
            self.targets,
        )

    def selfObjects(self):
        if self.selfarg:
            return self.selfarg.exactSplit.objects
        else:
            return nullObjects

    def vargObjects(self):
        if self.varg:
            return self.varg.exactSplit.objects
        else:
            return nullObjects

    def tupleSlots(self, tupleObj):
        slots = []

        if tupleObj is None:
            return slots

        if tupleObj.obj().pythonType() is not tuple:
            LOG.warning(
                "expected tuple object for vargs/defaults at %r, got %r; "
                "ignoring variable/default argument expansion",
                self.op,
                tupleObj,
            )
            return slots

        analysis = self.context.analysis

        lengthSlot = self.context.field(tupleObj, "LowLevel", analysis.pyObj("length"))
        if len(lengthSlot.values) != 1:
            LOG.warning(
                "tuple length is ambiguous at %r; ignoring variable/default argument expansion",
                self.op,
            )
            return slots
        length = tuple(lengthSlot.values)[0].pyObj()
        if not isinstance(length, int) or length < 0:
            LOG.warning(
                "tuple length is non-concrete at %r (%r); ignoring variable/default argument expansion",
                self.op,
                length,
            )
            return slots

        for i in range(length):
            slot = self.context.field(tupleObj, "Array", analysis.pyObj(i))
            slots.append(slot)

        return slots

    def defaultSlots(self, selfObj):
        if selfObj is None:
            return []

        # Relies on __defaults__ being immutable.

        defaultsSlot = self.context.field(
            selfObj, "Attribute", self.context.analysis.funcDefaultName
        )
        if defaultsSlot.null:
            if defaultsSlot.values:
                LOG.warning(
                    "defaults slot has mixed null/non-null state at %r; "
                    "ignoring defaults for conservativeness",
                    self.op,
                )
            return []

        if len(defaultsSlot.values) != 1:
            LOG.warning(
                "defaults slot is ambiguous at %r; ignoring defaults for conservativeness",
                self.op,
            )
            return []

        defaultsObj = tuple(defaultsSlot.values)[0]

        pt = defaultsObj.obj().pythonType()
        if pt is type(None):
            return []
        elif pt is tuple:
            return self.tupleSlots(defaultsObj)
        else:
            LOG.warning(
                "unsupported __defaults__ type at %r: %r; ignoring defaults",
                self.op,
                pt,
            )
            return []

    def resolve(self, context):
        self.dirty = False

        if self._unresolved_callee:
            # Conservatively keep analysis running without crashing.
            return

        for (selfobj, selflcl), (vargobj, varglcl) in itertools.product(
            self.selfObjects().items(), self.vargObjects().items()
        ):
            key = (selfobj, vargobj)
            if key not in self.cache:
                self.cache[key] = None

                if selfobj is None:
                    LOG.warning(
                        "skipping unresolved indirect call at %r (callee object is None)",
                        self.op,
                    )
                    continue

                code = self.getCode(context, selfobj)

                vargSlots = self.tupleSlots(vargobj)
                defaultSlots = self.defaultSlots(selfobj)

                context.fcall(
                    self.op,
                    code,
                    selflcl,
                    self.args,
                    vargSlots,
                    defaultSlots,
                    self.targets,
                )


class CallConstraint(UserCallConstraint):
    def getCode(self, context, selfobj):
        return context.analysis.getCode(selfobj)


class DirectCallConstraint(UserCallConstraint):
    def __init__(self, context, op, code, selfarg, args, kwds, varg, karg, targets):
        UserCallConstraint.__init__(
            self, context, op, selfarg, args, kwds, varg, karg, targets
        )
        self.code = code

    def getCode(self, context, selfobj):
        return self.code


class ConcreteCallConstraint(AbstractCall):
    def __init__(
        self,
        context,
        op,
        code,
        selfarg,
        args,
        kwds,
        varg,
        karg,
        targets,
        vargSlots,
        defaultSlots,
    ):
        assert code is not None
        assert argIsOK(selfarg), selfarg
        AbstractCall.__init__(self)
        self.context = context
        self.op = op
        self.code = code
        self.selfarg = selfarg
        self.args = args
        self.kwds = kwds
        self.varg = varg
        self.karg = karg
        self.targets = targets

        # TODO no need for the split locals?
        self.varg.attachExactSplit(self.splitChanged)

    def splitChanged(self):
        if not self.dirty:
            self.dirty = True
            # Bug B fix: Context has no dirtyDCall; ConcreteCallConstraint is a
            # concrete call and must be queued via dirtyCCall (the ccall queue).
            self.context.dirtyCCall(self)

    def __repr__(self):
        return "[DCALL %s %r(%r, %r, *%r, **%r) -> %r]" % (
            self.code,
            self.selfarg,
            self.args,
            self.kwds,
            self.varg,
            self.karg,
            self.targets,
        )

    def vargObjSlots(self, vargObj):
        slots = []

        if vargObj is None:
            return slots

        analysis = self.context.analysis

        lengthSlot = self.context.field(vargObj, "LowLevel", analysis.pyObj("length"))
        assert len(lengthSlot.values) == 1
        length = tuple(lengthSlot.values)[0].pyObj()

        for i in range(length):
            slot = self.context.field(vargObj, "Array", analysis.pyObj(i))
            slots.append(slot)

        return slots

    def resolve(self, context):
        self.dirty = False

        assert self.varg

        for vargObj in self.varg.exactSplit.objects.keys():
            key = vargObj
            if key not in self.cache:
                self.cache[key] = None

                vargSlots = self.vargObjSlots(vargObj)
                # Bug 4 fix: Context.fcall signature is
                #   fcall(op, code, selfarg, args, vargSlots, defaultSlots, targets)
                # The original code passed kwds/karg/targets in the wrong positions,
                # causing TypeError.  ConcreteCallConstraint has no defaults, so
                # pass an empty list for defaultSlots.
                context.fcall(
                    self.op,
                    self.code,
                    self.selfarg,
                    self.args,
                    vargSlots,
                    [],           # defaultSlots (none for concrete calls)
                    self.targets,
                )


class FlatCallConstraint(AbstractCall):
    def __init__(
        self, context, op, code, selfarg, args, vargSlots, defaultSlots, targets
    ):
        assert argIsOK(selfarg), selfarg

        AbstractCall.__init__(self)
        self.context = context
        self.op = op
        self.code = code
        self.selfarg = selfarg
        self.args = args
        self.vargSlots = vargSlots
        self.defaultSlots = defaultSlots
        self.targets = targets

        returnarglen = len(self.targets) if self.targets is not None else 0
        self.info = transfer.computeTransferInfo(
            self.code,
            self.selfarg is not None,
            len(self.args),
            len(self.vargSlots),
            len(self.defaultSlots),
            returnarglen,
        )
        self._invalid_info_logged = False

        if self.info.maybeOK():
            if self.selfarg is not None:
                self.selfarg.attachTypeSplit(self.splitChanged)

            for arg in args:
                if arg is not None:
                    arg.attachTypeSplit(self.splitChanged)

            for arg in vargSlots:
                if arg is not None:
                    arg.attachTypeSplit(self.splitChanged)

            for arg in defaultSlots:
                if arg is not None:
                    arg.attachTypeSplit(self.splitChanged)
        else:
            # The call shape cannot be represented by the current transfer model.
            # Keep the engine running and retain debug detail instead of trying
            # to build impossible invocations.
            if not self._invalid_info_logged:
                LOG.debug(
                    "skipping call binding for %r: %s",
                    self.op,
                    self.info.reason,
                )
                self._invalid_info_logged = True
            self.dirty = False

    def splitChanged(self):
        if not self.dirty:
            self.dirty = True
            self.context.dirtyFCall(self)

    def __repr__(self):
        return "[FCALL %r %r(%r, %r, %r) -> %r]" % (
            self.code,
            self.selfarg,
            self.args,
            self.vargSlots,
            self.defaultSlots,
            self.targets,
        )

    def resolve(self, context):
        self.dirty = False

        info = self.info
        if not info.maybeOK():
            if not self._invalid_info_logged:
                LOG.debug(
                    "skipping call binding for %r: %s",
                    self.op,
                    info.reason,
                )
                self._invalid_info_logged = True
            return

        ctsb = cpa.CPATypeSigBuilder(context.analysis, self, info)
        info.transfer(ctsb, ctsb)
        sigs = ctsb.signatures()

        for sig in sigs:
            if not sig in self.cache:
                # print(sig)

                # HACK - varg can be weird, must take it into account?
                self.cache[sig] = None

                invokedC = context.analysis.getContext(sig)
                invoke = callbinder.bind(self, invokedC, info)

                # TODO is this a good idea?
                invoke.apply()
