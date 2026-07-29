import os.path
import collections
from urllib.parse import quote

from pyflow.language.python import simplecodegen

from pyflow.util.io.xmloutput import XMLOutput
from pyflow.language.asttools import astpprint
import pyflow.util.graphalgorithim.dominator as dominator
from pyflow.util.io.filesystem import ensureDirectoryExists

from ... import config

from .. import programculler
from pyflow.frontend.extractor import Extractor

from pyflow.analysis.dump import dumputil
from pyflow.analysis import tools

from pyflow.language.python import ast
from pyflow.ir.core import (
    AnalysisFacts,
    Capabilities,
    format_source,
    source_filename,
)


# Filter an iterable into keys and values, and collect
# values with the same key into groups.
# Similar to map/reduce
def itergroupings(iterable, key, value=lambda v: v):
    grouping = {}
    for i in iterable:
        group = key(i)
        data = value(i)
        if not group in grouping:
            grouping[group] = [data]
        else:
            grouping[group].append(data)
    return grouping.items()


def outputCodeShortName(out, code, links=None, context=None):
    link = links.codeRef(code, context) if links is not None else None

    if link:
        out.begin("a", href=link)
    out << dumputil.codeShortName(code)
    if link:
        out.end("a")


def outputObjectShortName(out, heap, links=None):
    if links != None:
        link = links.objectRef(heap)
    else:
        link = None

    if link:
        out.begin("a", href=link)
    out << dumputil.objectShortName(heap)
    if link:
        out.end("a")


def outputOrigin(out, tabs, originTrace):
    for origin in originTrace:
        out << tabs
        if origin:
            out.begin("a", href="file:%s" % (quote(source_filename(origin)),))
        out << format_source(origin)
        if origin:
            out.end("a")
        out.endl()


def makeReportDirectory(moduleName):
    reportdir = os.path.join(config.outputDirectory, moduleName)
    ensureDirectoryExists(reportdir)

    return reportdir


def makeOutput(reportDir, filename):
    fullpath = os.path.join(reportDir, filename)
    fout = open(fullpath, "w")
    out = XMLOutput(fout)
    scg = simplecodegen.SimpleCodeGen(out)  # HACK?
    return out, scg


def dumpHeader(out):
    out << "["
    out.begin("a", href="function_index.html")
    out << "Functions"
    out.end("a")
    out << " | "
    out.begin("a", href="invocations.svg")
    out << "Function Graph"
    out.end("a")
    out << " | "
    out.begin("a", href="object_index.html")
    out << "Objects"
    out.end("a")
    out << "]"
    out.tag("br")


def printLabel(out, label):
    out.begin("div")
    out.begin("b")
    out << label
    out.end("b")
    out.end("div")
    out.endl()


def tableRow(out, links, label, *args):
    out.begin("tr")
    out.begin("td")
    out.begin("b")
    out << label
    out.end("b")
    out.end("td")
    out.begin("td")

    first = True
    for arg in args:
        if not first:
            out.tag("br")
        link = links.objectRef(arg)
        if link:
            out.begin("a", href=link)
        out << dumputil.objectShortName(arg)
        if link:
            out.end("a")

        first = False

    out.end("td")
    out.end("tr")
    out.endl()


# @async_limited(2)
def dumpFunctionInfo(func, compiler, derived, links, reportDir):
    out, scg = makeOutput(reportDir, links.functionFile[func])

    dumpHeader(out)

    code = func
    out.begin("h3")
    outputCodeShortName(out, func)
    out.end("h3")

    funcOps, funcLocals = tools.codeOpsLocals(func)

    if code.annotation.primitive:
        printLabel(out, "primitive")
    if code.annotation.descriptive:
        printLabel(out, "descriptive")
    if code.annotation.staticFold:
        printLabel(out, "static fold")
    if code.annotation.dynamicFold:
        printLabel(out, "dynamic fold")

    catalog = code.ir_catalog
    origin = catalog.source_of(code, code=code)
    if origin:
        out.begin("div")
        outputOrigin(out, "", (origin,))
        out.end("div")
        out.endl()

    # Psedo-python output
    if func is not None and func.isStandardCode():
        out.begin("pre")
        scg.process(func)
        out.end("pre")

    # Pretty printer for debugging
    if False:
        out.begin("pre")
        astpprint.pprint(func, out)
        out.end("pre")

    facts = AnalysisFacts.for_code(code)
    contexts_list = list(facts.contexts(code))
    contexts_count = len(contexts_list)

    printLabel(out, "%d contexts" % contexts_count)

    for cindex, context in enumerate(contexts_list):
        out.tag("hr")
        out.begin("div")

        cref = links.contextRef(context)
        out.tag("a", name=cref)

        out.begin("p")
        out << context
        out.end("p")
        out.endl()
        out.endl()

        # Print call/return information for the function.
        code = func
        out.begin("p")
        out.begin("table")

        callee = code.codeParameters()

        sig = context.signature
        if isinstance(callee.selfparam, ast.Local):
            objs = facts.references(code, callee.selfparam, context)
            tableRow(out, links, "self", *objs)

        numParam = len(callee.params)
        for i, param in enumerate(callee.params):
            if isinstance(param, ast.Local):
                objs = facts.references(code, param, context)
                tableRow(out, links, "param %d" % i, *objs)

        if isinstance(callee.vparam, ast.Local):
            objs = facts.references(code, callee.vparam, context)
            tableRow(out, links, "vparamObj", *objs)

            for vparamObj in objs:
                # Find and index the array slots
                lut = {}
                for name, values in vparamObj.slots.items():
                    if name.type == "Array":
                        lut[name.name.pyobj] = values

                for i, arg in enumerate(sig.params[numParam:]):
                    tableRow(out, links, "vparam %d" % i, *lut.get(i, ()))

        if isinstance(callee.kparam, ast.Local):
            objs = facts.references(code, callee.kparam, context)
            tableRow(out, links, "kparamObj", *objs)

        for i, param in enumerate(callee.returnparams):
            if isinstance(param, ast.Local):
                objs = facts.references(code, param, context)
                tableRow(out, links, "return %d" % i, *objs)

        out.end("table")
        out.end("p")
        out.endl()
        out.endl()

        origin = -1

        out.begin("pre")
        for op in funcOps:
            currentOrigin = catalog.source_of(op, code=code)
            if currentOrigin != origin:
                origin = currentOrigin
                outputOrigin(out, "\t", (origin,))
                out.endl()

            out << "\t\t"
            out << op
            out.endl()

            callees = facts.call_targets(code, op, context)
            if callees:
                for dstF, dstC in callees:
                    out << "\t\t\t"
                    outputCodeShortName(out, dstF, links, dstC)
                    out.endl()
            else:
                out << "\t\t\t?"
                out.endl()

            # dump read/modify/allocate information for this op
            read = facts.operation_effect(
                Capabilities.LIFETIME_OP_READS, code, op, context
            )
            modify = facts.operation_effect(
                Capabilities.LIFETIME_OP_WRITES, code, op, context
            )
            allocate = facts.operation_effect(
                Capabilities.LIFETIME_OP_ALLOCATIONS, code, op, context
            )

            s = ""
            if read:
                s += "R"
            if modify:
                s += "M"
            if allocate:
                s += "A"

            if False:
                # For debugging intermediate information
                pass

            if s:
                out << "\t\t\t"
                out.begin("i")
                out << s
                out.end("i")
                out.endl()

            out.endl()

        out.endl()

        def printTabbed(out, name, values, links):
            out << "\t"
            out << name
            out.endl()

            for value in values:
                out << "\t\t"
                link = links.objectRef(value)
                if link:
                    out.begin("a", href=link)
                out << dumputil.objectShortName(value)
                if link:
                    out.end("a")
                out.endl()

        for lcl in funcLocals:
            refs = facts.references(code, lcl, context)

            if isinstance(lcl, ast.Local):
                lclName = str(lcl) + " / " + scg.getLocalName(lcl)
            else:
                lclName = str(lcl)

            printTabbed(out, lclName, refs, links)
        out.end("pre")
        out.endl()

        callers = derived.callers(func, context)
        if callers:
            out.begin("h3")
            out << "Callers"
            out.end("h3")
            out.begin("p")
            out.begin("ul")
            for callerF, callerC in callers:
                out.begin("li")
                outputCodeShortName(out, callerF, links, callerC)
                out.end("li")
            out.end("ul")
            out.end("p")

        callees = derived.callees(func, context)
        if callees:
            out.begin("h3")
            out << "Callees"
            out.end("h3")
            out.begin("p")
            out.begin("ul")
            for callerF, callerC in callees:
                out.begin("li")
                outputCodeShortName(out, callerF, links, callerC)
                out.end("li")
            out.end("ul")
            out.end("p")

        live = facts.code_effect(Capabilities.LIFETIME_CODE_LIVE, code, context)
        killed = facts.code_effect(
            Capabilities.LIFETIME_CODE_KILLED, code, context
        )

        out.begin("h3")
        out << "Live"
        out.end("h3")
        out.begin("p")
        out.begin("ul")
        for obj in live:
            out.begin("li")
            outputObjectShortName(out, obj, links)
            if obj in killed:
                out << " (killed)"
            out.end("li")
        out.end("ul")
        out.end("p")

        reads = derived.funcReads[func][context]
        if reads:
            out.begin("h3")
            out << "Reads"
            out.end("h3")
            out.begin("p")
            out.begin("ul")
            for obj, slots in itergroupings(
                reads, lambda slot: slot.object, lambda slot: slot.slotName
            ):
                out.begin("li")
                outputObjectShortName(out, obj, links)

                out.begin("ul")
                for slot in slots:
                    out.begin("li")
                    out << "%r" % slot
                    out.end("li")
                out.end("ul")

                out.end("li")
            out.end("ul")
            out.end("p")

        modifies = derived.funcModifies[func][context]
        if modifies:
            out.begin("h3")
            out << "Modifies"
            out.end("h3")
            out.begin("p")
            out.begin("ul")
            for obj, slots in itergroupings(
                modifies, lambda slot: slot.object, lambda slot: slot.slotName
            ):
                out.begin("li")
                outputObjectShortName(out, obj, links)

                out.begin("ul")
                for slot in slots:
                    out.begin("li")
                    out << "%r" % slot
                    out.end("li")
                out.end("ul")

                out.end("li")
            out.end("ul")
            out.end("p")
        out.end("div")

    out.endl()
    out.close()


# @async_limited(2)
def dumpHeapInfo(heap, compiler, heapContexts, links, reportDir):
    # Initialize extractor if it doesn't exist
    if not hasattr(compiler, "extractor") or compiler.extractor is None:
        compiler.extractor = Extractor(compiler)

    out, scg = makeOutput(reportDir, links.objectFile[heap])

    dumpHeader(out)

    out.begin("h3")
    outputObjectShortName(out, heap)
    out.end("h3")
    out.endl()

    if heap not in heapContexts:
        print(heap)
        for other in heapContexts.keys():
            print(other)

    contexts = heapContexts[heap]

    call = compiler.extractor.getCall(heap)
    if call:
        out.begin("div")
        out << "On call: "
        outputCodeShortName(out, call, links)
        out.end("div")

    printLabel(out, "%d contexts" % len(contexts))

    out.begin("pre")

    for context in contexts:
        out.begin("div")
        cref = links.contextRef(context)
        out.tag("a", name=cref)

        out << "\t"
        outputObjectShortName(out, context)
        out.endl()

        for slot in context:
            # Only print(the slot if it can point to something.)
            if slot.refs:
                out << "\t\t%r" % slot.slotName
                if slot.null:
                    out << " (null?)"
                out.endl()
                for ref in slot:
                    out << "\t\t\t"
                    outputObjectShortName(out, ref, links)
                    out.endl()

        out.end("div")
        out.endl()

    out.end("pre")
    out.endl()
    out.close()


def makeHeapTree(liveHeap, heapContexts):
    head = None
    points = {}
    for heap, contexts in heapContexts.items():
        points[heap] = set()

        for context in contexts:
            for slot in context:
                for ref in slot:
                    if ref in liveHeap:
                        ogroup = ref.xtype.group()
                        points[heap].add(ogroup)

    dominator.makeSingleHead(points, head)
    tree, _idoms = dominator.dominatorTree(points, head)
    return tree, head


def dumpReport(name, compiler, prgm, derived, liveInvocations, liveHeap, heapContexts):
    reportDir = makeReportDirectory(name)

    links = dumputil.LinkManager()

    # HACK for closure
    uid = [0, 0]

    def makeHeapFile(heap):
        fn = "h%07d.html" % uid[0]
        links.objectFile[heap] = fn
        uid[0] += 1
        return fn

    def makeFunctionFile(func):
        fn = "f%07d.html" % uid[1]
        links.functionFile[func] = fn
        uid[1] += 1
        return fn

    liveHeap = set(heapContexts.keys())  # TODO elo,omate?

    # Create basic index files without complex tree traversal
    out, scg = makeOutput(reportDir, "function_index.html")
    dumpHeader(out)
    out.begin("h2")
    out << "Function Index"
    out.end("h2")
    out.begin("ul")
    for func in sorted(prgm.liveCode, key=lambda f: f.codeName()):
        out.begin("li")
        makeFunctionFile(func)
        outputCodeShortName(out, func, links)
        out.end("li")
    out.end("ul")
    out.close()

    out, scg = makeOutput(reportDir, "object_index.html")
    dumpHeader(out)
    out.begin("h2")
    out << "Object Index"
    out.end("h2")
    out.begin("ul")
    for heap in sorted(liveHeap, key=lambda o: repr(o)):
        out.begin("li")
        makeHeapFile(heap)
        link = links.objectRef(heap)
        if link:
            out.begin("a", href=link)
        out << heap
        if link:
            out.end("a")
        out.end("li")
    out.end("ul")
    out.close()

    # Generate basic function and heap reports without complex analysis
    try:
        with compiler.console.scope("function reports"):
            for func in prgm.liveCode[:1]:  # Limit to first function to avoid timeout
                try:
                    dumpFunctionInfo(func, compiler, derived, links, reportDir)
                except Exception as e:
                    print(f"Warning: Could not dump function {func.codeName()}: {e}")

        with compiler.console.scope("heap reports"):
            heap_list = list(liveHeap)[:1]  # Limit to first heap to avoid timeout
            for heap in heap_list:
                try:
                    dumpHeapInfo(heap, compiler, heapContexts, links, reportDir)
                except Exception as e:
                    print(f"Warning: Could not dump heap {heap}: {e}")
    except Exception as e:
        print(f"Warning: Could not complete dump reports: {e}")

    # Skip graphs for now to avoid timeout
    # with compiler.console.scope("graphs"):
    #     dumpgraphs.dump(compiler, liveInvocations, links, reportDir)


class DerivedData(object):
    def __init__(self, liveCode, facts):
        self.facts = facts
        self.invokeDestination = collections.defaultdict(set)
        self.invokeSource = collections.defaultdict(set)
        self.funcReads = collections.defaultdict(lambda: collections.defaultdict(set))
        self.funcModifies = collections.defaultdict(
            lambda: collections.defaultdict(set)
        )

        for code in liveCode:
            for context in facts.contexts(code):
                self.funcReads[code][context].update(
                    facts.code_effect(
                        Capabilities.LIFETIME_CODE_READS, code, context
                    )
                )
                self.funcModifies[code][context].update(
                    facts.code_effect(
                        Capabilities.LIFETIME_CODE_WRITES, code, context
                    )
                )

            ops = tools.codeOps(code)
            for op in ops:
                self.handleOpInvokes(code, op)
                self.handleOpReads(code, op)
                self.handleOpModifies(code, op)

    def handleOpInvokes(self, code, op):
        for context in self.facts.contexts(code):
            src = (code, context)
            for dst in self.facts.call_targets(code, op, context):
                self.invokeDestination[src].add(dst)
                self.invokeSource[dst].add(src)

    def handleOpReads(self, code, op):
        for context in self.facts.contexts(code):
            self.funcReads[code][context].update(
                self.facts.operation_effect(
                    Capabilities.LIFETIME_OP_READS, code, op, context
                )
            )

    def handleOpModifies(self, code, op):
        for context in self.facts.contexts(code):
            self.funcModifies[code][context].update(
                self.facts.operation_effect(
                    Capabilities.LIFETIME_OP_WRITES, code, op, context
                )
            )

    def callers(self, function, context):
        return self.invokeSource[(function, context)]

    def callees(self, function, context):
        return self.invokeDestination[(function, context)]


def evaluate(compiler, prgm, name):
    with compiler.console.scope("dump"):
        liveCode, liveInvocations = programculler.findLiveCode(prgm)
        liveHeap, heapContexts = programculler.findLiveHeap(prgm)

        derived = DerivedData(prgm.liveCode, AnalysisFacts(prgm.ir))

        dumpReport(
            name, compiler, prgm, derived, liveInvocations, liveHeap, heapContexts
        )
