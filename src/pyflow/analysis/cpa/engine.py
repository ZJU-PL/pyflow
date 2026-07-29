"""Constraint-based Analysis (CPA) for PyFlow.

This package provides constraint-based analysis capabilities that use constraint
solving to perform precise inter-procedural analysis of Python programs.
"""

import collections
import itertools
from pyflow.util.io import formatting

from . import base, simpleimagebuilder

from pyflow.ir.storegraph import storegraph, canonicalobjects, extendedtypes
from .. import cpasignature

from .constraintextractor import ExtractDataflow

from .constraints import AssignmentConstraint, DirectCallConstraint

from . import codecloner
from .publication import CodeFacts, OperationFacts, ReferenceFacts, publish_cpa_facts

# Only used for creating return variables
from pyflow.language.python import ast
from pyflow.language.python import program

from pyflow.optimization.callconverter import callConverter

from pyflow.util.python.apply import ApplyError, applyFunction

from pyflow.analysis.astcollector import getOps
from pyflow import analysis  # for references like analysis.cpasignature

# For keeping track of how much time we spend extracting/converting.
import time

from pyflow.util import canonical

# For allocation
import types

#########################
### Utility functions ###
#########################


def foldFunctionIR(extractor, func, vargs=(), kargs=None):
    """Fold a function call with constant arguments.

    Args:
        extractor: Program extractor for accessing objects.
        func: Function to fold.
        vargs: Variable arguments.
        kargs: Keyword arguments.

    Returns:
        Result of the function call.
    """
    newvargs = [arg.pyobj for arg in vargs]

    if kargs is None:
        kargs = {}
    assert not kargs, kargs
    newkargs = {}

    result = applyFunction(func, newvargs, newkargs)
    return extractor.getObject(result)


###############################
### Main class for analysis ###
###############################


class InterproceduralDataflow(object):
    def __init__(self, compiler, graph, opPathLength, clone):
        self.decompileTime = 0
        self.console = compiler.console
        self.extractor = compiler.extractor
        self.clone = clone  # Should we copy the code before annotating it?

        # Has the context been constructed?
        self.liveContexts = set()

        self.liveCode = set()

        # Constraint information, for debugging
        self.constraints = []

        # The worklist
        self.dirty = collections.deque()

        self.canonical = graph.canonical
        self._canonicalContext = canonical.CanonicalCache(base.AnalysisContext)

        # Controls how many previous ops are remembered by a context.
        # TODO remember prior CPA signatures?
        self.opPathLength = opPathLength
        self.cache = {}

        # Information for contextual operations.
        self.opAllocates = collections.defaultdict(set)
        self.opReads = collections.defaultdict(set)
        self.opModifies = collections.defaultdict(set)
        self.opInvokes = collections.defaultdict(set)

        self.codeContexts = collections.defaultdict(set)

        self.storeGraph = graph

        # Setup the "external" context, used for creaing bogus slots.
        self.externalOp = canonical.Sentinel("<externalOp>")

        self.externalFunction = ast.Code(
            "external",
            ast.CodeParameters(
                selfparam=None,
                posonlyparams=[],
                posonlynames=[],
                params=[],
                paramnames=[],
                defaults=[],
                vparam=None,
                kparam=None,
                returnparams=[ast.Local("internal_return")],
                type_params=None,
            ),
            ast.Suite([]),
        )
        externalSignature = self._signature(self.externalFunction, None, ())
        opPath = self.initialOpPath()
        self.externalFunctionContext = self._canonicalContext(
            externalSignature, opPath, self.storeGraph
        )
        self.codeContexts[self.externalFunction].add(self.externalFunctionContext)

        # For vargs
        self.tupleClass = self.extractor.getObject(tuple)
        self.ensureLoaded(self.tupleClass)

        # For kargs
        self.dictionaryClass = self.extractor.getObject(dict)
        self.ensureLoaded(self.dictionaryClass)

        self.entryPointOp = {}

    def initialOpPath(self):
        if self.opPathLength == 0:
            path = None
        elif self.opPathLength == 1:
            path = self.externalOp
        else:
            path = (self.externalOp,) * self.opPathLength

        return self.cache.setdefault(path, path)

    def advanceOpPath(self, original, op):
        assert not isinstance(op, canonicalobjects.OpContext)

        if self.opPathLength == 0:
            path = None
        elif self.opPathLength == 1:
            path = op
        else:
            path = original[1:] + (op,)

        return self.cache.setdefault(path, path)

    def ensureLoaded(self, obj):
        # TODO the timing is no longer guaranteed, as the store graph bypasses this...
        start = time.perf_counter()
        self.extractor.ensureLoaded(obj)
        self.decompileTime += time.perf_counter() - start

    def getCall(self, obj):
        start = time.perf_counter()
        result = self.extractor.getCall(obj)
        self.decompileTime += time.perf_counter() - start
        return result

    def logAllocation(self, cop, cobj):
        assert isinstance(cobj, storegraph.ObjectNode), type(cobj)
        self.opAllocates[(cop.code, cop.op, cop.context)].add(cobj)

    def logRead(self, cop, slot):
        assert isinstance(slot, storegraph.SlotNode), type(slot)
        self.opReads[(cop.code, cop.op, cop.context)].add(slot)

    def logModify(self, cop, slot):
        assert isinstance(slot, storegraph.SlotNode), type(slot)
        self.opModifies[(cop.code, cop.op, cop.context)].add(slot)

    def constraint(self, constraint):
        self.constraints.append(constraint)

    def _signature(self, code, selfparam, params):
        def checkParam(param):
            return (
                param is None
                or param is cpasignature.Any
                or isinstance(param, extendedtypes.ExtendedType)
            )

        assert code.isCode(), type(code)
        assert checkParam(selfparam), selfparam
        for param in params:
            assert checkParam(param), param

        return cpasignature.CPASignature(code, selfparam, params)

    def canonicalContext(self, srcOp, code, selfparam, params):
        assert isinstance(srcOp, canonicalobjects.OpContext), type(srcOp)
        assert code.isCode(), type(code)

        sig = self._signature(code, selfparam, params)
        opPath = self.advanceOpPath(srcOp.context.opPath, srcOp.op)

        if code.annotation.primitive:
            # Call path does not matter.
            opPath = None

        context = self._canonicalContext(sig, opPath, self.storeGraph)

        # Mark that we created the context.
        self.codeContexts[code].add(context)

        return context

    # This is the policy that determines what names a given allocation gets.
    def extendedInstanceType(self, context, xtype, op):
        if xtype.obj is None:
            # Handle case where xtype.obj is None - return a default type
            return None
        self.ensureLoaded(xtype.obj)
        instObj = xtype.obj.abstractInstance()

        pyobj = xtype.obj.pyobj
        if pyobj is types.MethodType:
            # Method types are named by their function and instance
            sig = context.signature
            # TODO check that this == "new"?
            if len(sig.params) == 4:
                # sig.params[0] is the type object for __new__
                func = sig.params[1]
                inst = sig.params[2]
                return self.canonical.methodType(func, inst, instObj, op)
        elif pyobj in (tuple, list, dict):
            # Containers are named by the signature of the context they're allocated in.
            return self.canonical.contextType(context, instObj, op)

        return self.canonical.pathType(context.opPath, instObj, op)

    def process(self):
        while self.dirty:
            current = self.dirty.popleft()
            current.process()

    def createAssign(self, source, dest):
        AssignmentConstraint(self, source, dest)

    def fold(self, targetcontext):
        def notConst(obj):
            return obj is analysis.cpasignature.Any or (
                obj is not None and not obj.obj.isConstant()
            )

        sig = targetcontext.signature
        code = sig.code

        if code.annotation.dynamicFold:
            # It's foldable.
            p = code.codeparameters
            if p.vparam is not None or p.kparam is not None:
                # The constant folder has no variadic argument binding model.
                # Keep the ordinary call constraints instead of aborting the
                # complete analysis for variadic intrinsics such as
                # ``interpreter_call``.
                return False

            # TODO folding with constant vargs?
            # HACK the internal selfparam is usually not "constant" as it's a function, so we ignore it?
            # if notConst(sig.selfparam): return False
            for param in sig.params:
                if notConst(param):
                    return False

            params = [param.obj for param in sig.params]
            try:
                result = foldFunctionIR(
                    self.extractor, code.annotation.dynamicFold, params
                )
            except ApplyError:
                # Constant inputs do not imply that the runtime operation is
                # defined for their types.  A failed speculative fold leaves
                # the context to normal constraint evaluation.
                return False
            resultxtype = self.canonical.existingType(result)

            # Set the return value
            assert len(p.returnparams) == 1
            name = self.canonical.localName(code, p.returnparams[0], targetcontext)
            returnSource = self.storeGraph.root(name)
            returnSource.initializeType(resultxtype)

            return True

        return False

    def initializeContext(self, context):
        # Don't bother if the call can never happen.
        if context.invocationMaySucceed(self):
            # Caller-independant initalization.
            if context not in self.liveContexts:
                # Mark as initialized
                self.liveContexts.add(context)

                code = context.signature.code

                # HACK convert the calls before analysis to eliminate UnpackTuple nodes.
                callConverter(self.extractor, code)

                if code not in self.liveCode:
                    self.liveCode.add(code)

                # Check to see if we can just fold it.
                # Dynamic folding only calculates the output,
                # so we still evaluate the constraints.
                folded = self.fold(context)

                # Extract the constraints
                exdf = ExtractDataflow(self, context, folded)
                exdf.process()
            return True
        else:
            print(f"DEBUG: invocationMaySucceed returned False for context: {context}")
        return False

    def bindCall(self, cop, caller, targetcontext):
        assert isinstance(cop, canonicalobjects.OpContext), type(cop)

        sig = targetcontext.signature
        code = sig.code

        dst = self.canonical.codeContext(code, targetcontext)
        if dst not in self.opInvokes[cop]:
            # Record the invocation
            self.opInvokes[cop].add(dst)

            if self.initializeContext(targetcontext):
                targetcontext.bindParameters(self, caller)

    def makeExternalSlot(self, name):
        code = self.externalFunction
        context = self.externalFunctionContext
        dummyLocal = ast.Local(name)
        dummyName = self.canonical.localName(code, dummyLocal, context)
        dummySlot = self.storeGraph.root(dummyName)
        return dummySlot

    def createEntryOp(self, entryPoint):
        code = self.externalFunction
        context = self.externalFunctionContext

        # Make sure each op is unique.
        op = canonical.Sentinel("entry point op")
        cop = self.canonical.opContext(code, op, context)
        self.entryPointOp[entryPoint] = cop
        return cop

    def getArgSlot(self, xtypes):
        if not xtypes:
            # For empty argument types, create a slot with a default type
            # This ensures the constraint has something to observe
            slot = self.makeExternalSlot("arg")
            # Initialize with a generic object type so the constraint can trigger
            default_obj = self.extractor.getObject(object())
            default_type = self.canonical.existingType(default_obj)
            slot.initializeType(default_type)
            return slot
        slot = self.makeExternalSlot("arg")
        slot.initializeTypes(xtypes)
        return slot

    def addEntryPoint(self, entryPoint, args):
        # The call point
        cop = self.createEntryOp(entryPoint)

        # For regular functions, don't pass a self argument
        selfSlot = None  # Regular functions don't have self
        argSlots = [self.getArgSlot(arg) for arg in args.args]
        kwds = []
        varg = self.getArgSlot(args.vargs)
        karg = self.getArgSlot(args.kargs)
        returnSlots = [self.makeExternalSlot("return_%s" % entryPoint.name())]

        # Create the initial constraint
        constraint = DirectCallConstraint(
            self,
            cop,
            entryPoint.code,
            selfSlot,
            argSlots,
            kwds,
            varg,
            karg,
            returnSlots,
        )

    def solve(self):
        start = time.perf_counter()
        # Process
        self.process()

        end = time.perf_counter()

        self.solveTime = end - start - self.decompileTime

    def annotateEntryPoints(self, cloner):
        # TODO redirect code?

        # Find the contexts that a given entryPoint invokes
        for entryPoint, op in self.entryPointOp.items():
            entryPoint.code = cloner.code(entryPoint.code)
            contexts = [ccontext.context for ccontext in self.opInvokes[op]]
            entryPoint.contexts = contexts

    def reindexResults(self, cloner):
        # Re-index the invocations
        invokeLUT = collections.defaultdict(lambda: collections.defaultdict(set))
        for srcop, dsts in self.opInvokes.items():
            for dst in dsts:
                newdstcode = cloner.code(dst.code)
                invokeLUT[(srcop.code, srcop.op)][srcop.context].add(
                    (newdstcode, dst.context)
                )
        self.invokeLUT = invokeLUT

        # Re-index the locals
        lclLUT = collections.defaultdict(lambda: collections.defaultdict(set))
        for slot in self.storeGraph:
            name = slot.slotName
            if name.isLocal():
                lclLUT[(name.code, name.local)][name.context] = slot
            elif name.isExisting():
                lclLUT[(name.code, name.object)][name.context] = slot
        self.lclLUT = lclLUT

    def annotate(self, prgm=None):
        if self.clone:
            cloner = codecloner.FunctionCloner(self.codeContexts.keys())

            # Translate the live code
            self.liveCode = set([cloner.code(code) for code in self.liveCode])
        else:
            cloner = codecloner.NullCloner(self.codeContexts.keys())

        self.reindexResults(cloner)

        self.annotateEntryPoints(cloner)
        published_records = []

        for code, contexts in self.codeContexts.items():
            if code is self.externalFunction:
                continue

            cloner.process(code)

            contexts = tuple(contexts)

            ops, lcls = getOps(code)

            newcode = cloner.code(code)
            operation_facts = []
            for op in ops:
                newop = cloner.op(op)
                for context in contexts:
                    operation_facts.append(
                        OperationFacts(
                            newop,
                            context,
                            frozenset(self.opReads[(code, op, context)]),
                            frozenset(self.opModifies[(code, op, context)]),
                            frozenset(self.opAllocates[(code, op, context)]),
                            frozenset(self.invokeLUT[(code, op)][context]),
                        )
                    )

            reference_facts = []
            for lcl in lcls:
                if isinstance(lcl, ast.Existing):
                    context_lut = self.lclLUT[(code, lcl.object)]
                    newlcl = cloner.op(lcl)
                else:
                    context_lut = self.lclLUT[(code, lcl)]
                    newlcl = cloner.lcl(lcl)
                for context in contexts:
                    reference_facts.append(
                        ReferenceFacts(
                            newlcl,
                            context,
                            frozenset(context_lut[context]),
                        )
                    )

            published_records.append(
                CodeFacts(
                    newcode,
                    tuple(contexts),
                    {
                        context: frozenset(self.opReads[(code, None, context)])
                        for context in contexts
                    },
                    {
                        context: frozenset(self.opModifies[(code, None, context)])
                        for context in contexts
                    },
                    {
                        context: frozenset(self.opAllocates[(code, None, context)])
                        for context in contexts
                    },
                    tuple(operation_facts),
                    tuple(reference_facts),
                )
            )

        if prgm is not None:
            from pyflow.ir.core import Capabilities, ensure_codes_indexed

            previous_catalog = prgm.ir
            prgm.liveCode = set(self.liveCode)
            catalog = ensure_codes_indexed(self.liveCode)
            if catalog is not previous_catalog:
                catalog.import_contexts_from(previous_catalog)
                catalog.facts.import_producer(
                    previous_catalog.facts,
                    "ipa",
                    (Capabilities.CONTEXTS, Capabilities.CALL_TARGETS),
                )
            prgm.ir = catalog
            publish_cpa_facts(catalog, published_records)

    ### Debugging methods ###

    def checkConstraints(self):
        badConstraints = []
        allBad = set()
        allWrite = set()
        for c in self.constraints:
            bad = c.getBad()
            if bad:
                badConstraints.append((c, bad))
                allBad.update(bad)
                allWrite.update(c.writes())

        # Try to find the constraints that started the problem.
        unresolved_count = 0
        for c, bad in badConstraints:
            if not allWrite.issuperset(bad):
                c.check(self.console)
                unresolved_count += 1

        # Show summary if there were unresolved calls but not in verbose mode
        if unresolved_count > 0 and not self.console.verbose:
            self.console.output(
                "Found %d unresolved call(s). Use --verbose for details."
                % unresolved_count
            )

    def slotMemory(self):
        return self.storeGraph.setManager.memory()

    def dumpSolveInfo(self):
        console = self.console
        console.output("Constraints:   %d" % len(self.constraints))
        console.output("Contexts:      %d" % len(self.liveContexts))
        console.output("Code:          %d" % len(self.liveCode))
        console.output(
            "Contexts/Code: %.1f"
            % (float(len(self.liveContexts)) / max(len(self.liveCode), 1))
        )
        console.output("Slot Memory:   %s" % formatting.memorySize(self.slotMemory()))
        console.output("")
        console.output("Extract:       %s" % formatting.elapsedTime(self.decompileTime))
        console.output("Solve:         %s" % formatting.elapsedTime(self.solveTime))
        console.output("")


def evaluateWithImage(compiler, prgm, opPathLength=0, firstPass=True, clone=False):
    with compiler.console.scope("cpa analysis"):
        dataflow = InterproceduralDataflow(
            compiler, prgm.storeGraph, opPathLength, clone
        )
        dataflow.firstPass = firstPass  # HACK for debugging

        for entryPoint, args in prgm.entryPoints:
            dataflow.addEntryPoint(entryPoint, args)

        try:
            with compiler.console.scope("solve"):
                dataflow.solve()
                dataflow.checkConstraints()
                dataflow.dumpSolveInfo()
        finally:
            # Helps free up memory.
            with compiler.console.scope("cleanup"):
                del dataflow.constraints
                dataflow.storeGraph.removeObservers()

        # Publication is a commit step and must never run with a partially
        # solved dataflow system after an exception.
        with compiler.console.scope("annotate"):
            dataflow.annotate(prgm)

        prgm.liveCode = dataflow.liveCode

        return dataflow


def evaluate(compiler, prgm, opPathLength=0, firstPass=True):
    simpleimagebuilder.build(compiler, prgm)
    return evaluateWithImage(compiler, prgm, opPathLength, firstPass)
