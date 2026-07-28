"""Static Single Assignment (SSA) form conversion for CFGs.

This module implements the conversion of control flow graphs to SSA form,
including phi function insertion and variable renaming.
"""

from pyflow.util.typedispatch import *
from pyflow.language.python import ast

from . import graph as cfg
from .dfs import CFGDFS
from . import dom


class UnsupportedSSAError(Exception):
    """Raised when CFG SSA is requested for unsupported structured control flow."""


class CollectModifies(TypeDispatcher):
    """Collects variable modifications for SSA construction.

    This class traverses CFG blocks to identify where variables are modified,
    which is needed to determine where phi functions should be inserted.

    Attributes:
        mod: Dictionary mapping variables to sets of blocks that modify them.
        order: List of blocks in traversal order.
    """

    def __init__(self):
        """Initialize the modifier collector."""
        self.mod = {}
        self.order = []

    def modified(self, node):
        """Mark a variable as modified in the current block.

        Args:
            node: AST node representing the modified variable.
        """
        assert isinstance(node, ast.Local)
        self._modified(node, self.current)

    def _modified(self, node, block):
        """Record a variable modification in a specific block.

        Args:
            node: AST node representing the modified variable.
            block: CFG block where the modification occurs.
        """
        if not node in self.mod:
            self.mod[node] = set()

        # .data is the djnode
        self.mod[node].add(block.data)

    @dispatch(cfg.Entry, cfg.Exit, cfg.Merge, cfg.Yield, cfg.Switch)
    def visitLeaf(self, node):
        self.order.append(node)

    @dispatch(cfg.TypeSwitch)
    def visitTypeSwitch(self, node):
        self.order.append(node)

        for i, case in enumerate(node.original.cases):
            if case.expr:
                self._modified(case.expr, node.getExit(i))

    @dispatch(ast.Discard, ast.Return, ast.SetAttr, ast.Store, ast.OutputBlock)
    def visitDiscard(self, node):
        pass

    @dispatch(ast.leafTypes, ast.Local, ast.Existing, ast.GetCellDeref, ast.Code, ast.DoNotCare)
    def visitASTLeaf(self, node):
        pass

    @dispatch(ast.InputBlock)
    def visitInputBlock(self, node):
        for input in node.inputs:
            self.modified(input.lcl)

    @dispatch(ast.Assign)
    def visitAssign(self, node):
        for target in node.lcls:
            self.modified(target)

    @dispatch(ast.UnpackSequence)
    def visitUnpackSequence(self, node):
        for target in node.targets:
            self.modified(target)

    @dispatch(ast.Suite)
    def visitASTSuite(self, node):
        for block in node.blocks:
            self(block)

    @dispatch(ast.ExceptionHandler)
    def visitExceptionHandler(self, node):
        if node.value is not None:
            self.modified(node.value)

        self(node.preamble)
        if node.type is not None:
            self(node.type)
        self(node.body)

    @dispatch(ast.TryExceptFinally)
    def visitTryExceptFinally(self, node):
        self(node.body)
        for handler in node.handlers:
            self(handler)
        if node.defaultHandler is not None:
            self(node.defaultHandler)
        if node.else_ is not None:
            self(node.else_)
        if node.finally_ is not None:
            self(node.finally_)

    @dispatch(ast.For)
    def visitStructuredFor(self, node):
        """Leave preserved source-level iteration outside CFG SSA.

        The CFG intentionally keeps ``For`` structured until iterator-aware
        lowering exists. Treating its nested assignments as if they all occur
        in the containing basic block would manufacture invalid phi placement.
        AST/PDG consumers retain the original def-use structure instead.
        """
        del node

    @dispatch(cfg.Suite)
    def visitSuite(self, node):
        self.order.append(node)
        self.current = node
        for op in node.ops:
            self(op)
        self.current = None


class SSARename(TypeDispatcher):
    """Renames variables to SSA form during CFG traversal.

    This class performs the variable renaming phase of SSA construction.
    It maintains a frame (mapping from original variables to SSA versions)
    for each CFG block, and renames variables as it traverses the CFG.

    The renaming process:
    - At each block, inherits the frame from its predecessor
    - When a variable is defined, creates a new SSA version
    - When a variable is used, uses the current SSA version from the frame
    - At merge points, prepares for phi node insertion

    Attributes:
        g: CFG Code object being transformed
        rename: Set of variables that need renaming
        merge: Dictionary mapping merge blocks to sets of variables needing phi nodes
        frames: Dictionary mapping CFG blocks to variable frames
        currentFrame: Current variable frame being built
        read: Set of SSA variables that are read (used to determine if phi needed)
        fixup: List of merge blocks that need phi node insertion
    """

    def __init__(self, g, rename, merge):
        """Initialize the SSA renamer.

        Args:
            g: CFG Code object to transform
            rename: Set of variables to rename
            merge: Dictionary mapping merge blocks to variables needing phi nodes
        """
        self.g = g
        self.rename = rename
        self.merge = merge

        self.frames = {}
        self.currentFrame = None

        self.read = set()

        self.fixup = []

    def clone(self, lcl, frame):
        """Clone a local variable and add it to the frame.

        Creates a new SSA version of a local variable and records it
        in the variable frame. Used when encountering a new definition.

        Args:
            lcl: Original local variable (or None)
            frame: Variable frame to add the clone to

        Returns:
            ast.Local: Cloned local variable, or None if lcl is None
        """
        if lcl:
            result = lcl.clone()
            frame[lcl] = result
            return result
        else:
            return None

    def renameWithFrame(self, node, frame):
        previous = self.currentFrame
        self.currentFrame = dict(frame)
        result = self(node)
        out = self.currentFrame
        self.currentFrame = previous
        return result, out

    def mergeStructuredFrames(self, incoming, branches):
        merged = {}

        keys = set()
        for _, frame in branches:
            keys.update(frame.keys())

        for name in keys:
            values = [frame.get(name) for _, frame in branches]
            first = values[0]

            if all(value is first for value in values):
                if first is not None:
                    merged[name] = first
                continue

            fallback = incoming.get(name)
            if any(value is None and fallback is None for value in values):
                continue

            target = name.clone()
            merged[name] = target

            for suite, frame in branches:
                value = frame.get(name, fallback)
                if value is not None and value is not target:
                    suite.append(ast.Assign(value, [target]))

        return merged

    @dispatch(cfg.Entry)
    def visitCFGEntry(self, node):
        frame = {}

        cparam = self.g.code.codeparameters

        # Set the parameters

        selfparam = self.clone(cparam.selfparam, frame)
        params = [self.clone(p, frame) for p in cparam.params]
        vparam = self.clone(cparam.vparam, frame)
        kparam = self.clone(cparam.kparam, frame)
        posonlyparams = [self.clone(p, frame) for p in cparam.posonlyparams]

        self.g.code.codeparameters = ast.CodeParameters(
            selfparam=selfparam,
            posonlyparams=posonlyparams,
            posonlynames=cparam.posonlynames,
            params=params,
            paramnames=cparam.paramnames,
            defaults=cparam.defaults,
            vparam=vparam,
            kparam=kparam,
            returnparams=cparam.returnparams,
            type_params=cparam.type_params,
        )

        self.currentFrame = frame
        self.frames[node] = frame

    @dispatch(cfg.Exit)
    def visitCFGLeaf(self, node):
        pass

    @dispatch(cfg.Suite)
    def visitCFGSuite(self, node):
        prev = node.prev
        if prev is None or prev not in self.frames:
            self.currentFrame = {}
        else:
            self.currentFrame = dict(self.frames[prev])

        ops = []
        for op in node.ops:
            result = self(op)
            if result is not None:
                ops.append(result)
        node.ops = ops

        self.frames[node] = self.currentFrame

    @dispatch(cfg.Switch)
    def visitCFGSwitch(self, node):
        self.currentFrame = dict(self.frames[node.prev])

        node.condition = self(node.condition)

        self.frames[node] = self.currentFrame

    @dispatch(cfg.TypeSwitch)
    def visitTypeSwitch(self, node):
        self.currentFrame = dict(self.frames[node.prev])

        conditional = self(node.original.conditional)

        cases = []
        for i, case in enumerate(node.original.cases):
            if case.expr:
                # TODO slightly unsound, modifies the expressions in the wrong frame.
                expr = self.clone(case.expr, self.currentFrame)

                cases.append(ast.TypeSwitchCase(case.types, expr, case.body))
            else:
                cases.append(case)

        node.original = ast.TypeSwitch(conditional, cases)

        self.frames[node] = self.currentFrame

    @dispatch(cfg.Yield)
    def visitCFGYield(self, node):
        self.currentFrame = dict(self.frames[node.prev])
        self.frames[node] = self.currentFrame

    @dispatch(cfg.Merge)
    def visitCFGMerge(self, node):
        # Copy a previous frame, any previous frame.
        frame = None
        complete = True
        for prev in node.reverse():
            if prev in self.frames:
                if frame is None:
                    frame = dict(self.frames[prev])
            else:
                complete = False

        # Guard: if no predecessor has been processed yet (can happen in
        # certain loop configurations), start with an empty frame rather
        # than crashing with TypeError when we try to index None.
        if frame is None:
            frame = {}

        # Mask variables that need to be merged.
        if node in self.merge:
            for name in self.merge[node]:
                frame[name] = name.clone()

            self.fixup.append(node)

        self.frames[node] = frame

    @dispatch(ast.Local)
    def visitLocal(self, node):
        if node in self.currentFrame:
            result = self.currentFrame[node]
        else:
            # Handle missing local variables by cloning them
            result = self.clone(node, self.currentFrame)
        self.read.add(result)
        return result

    @dispatch(ast.InputBlock)
    def visitInputBlock(self, node):
        return ast.InputBlock(
            [
                ast.Input(input.src, self.clone(input.lcl, self.currentFrame))
                for input in node.inputs
            ]
        )

    @dispatch(ast.OutputBlock)
    def visitOutputBlock(self, node):
        return ast.OutputBlock(
            [ast.Output(self(output.expr), output.dst) for output in node.outputs]
        )

    @dispatch(ast.Suite)
    def visitASTSuite(self, node):
        blocks = []
        for block in node.blocks:
            result = self(block)
            if result is not None:
                blocks.append(result)
        return ast.Suite(blocks)

    @dispatch(ast.ExceptionHandler)
    def visitExceptionHandler(self, node):
        preamble = self(node.preamble)
        type_ = self(node.type) if node.type is not None else None

        if node.value is not None:
            value = self.clone(node.value, self.currentFrame)
        else:
            value = None

        body = self(node.body)
        return ast.ExceptionHandler(preamble, type_, value, body)

    @dispatch(ast.TryExceptFinally)
    def visitTryExceptFinally(self, node):
        incoming = dict(self.currentFrame)

        body, body_frame = self.renameWithFrame(node.body, incoming)

        handlers = []
        handler_branches = []
        for handler in node.handlers:
            renamed, frame = self.renameWithFrame(handler, incoming)
            handlers.append(renamed)
            handler_branches.append((renamed.body, frame))

        if node.defaultHandler is not None:
            defaultHandler, default_frame = self.renameWithFrame(
                node.defaultHandler, incoming
            )
            default_branch = (defaultHandler, default_frame)
        else:
            defaultHandler = None
            default_branch = None

        if node.else_ is not None:
            else_, else_frame = self.renameWithFrame(node.else_, body_frame)
            normal_branches = [(else_, else_frame)]
        else:
            else_ = None
            normal_branches = [(body, body_frame)]

        normal_branches.extend(handler_branches)
        if default_branch is not None:
            normal_branches.append(default_branch)

        if normal_branches:
            pre_finally = self.mergeStructuredFrames(incoming, normal_branches)
        else:
            pre_finally = dict(incoming)

        if node.finally_ is not None:
            finally_, final_frame = self.renameWithFrame(node.finally_, pre_finally)
        else:
            finally_ = None
            final_frame = pre_finally

        self.currentFrame = final_frame
        return ast.TryExceptFinally(body, handlers, defaultHandler, else_, finally_)

    @dispatch(ast.For)
    def visitStructuredFor(self, node):
        """Preserve structured iteration during CFG-local SSA renaming."""
        return node

    @dispatch(
        ast.BinaryOp,
        ast.Call,
        ast.ConvertToBool,
        ast.UnaryPrefixOp,
        ast.BuildTuple,
        ast.Return,
        ast.DirectCall,
        ast.Is,
        ast.GetGlobal,
        ast.SetGlobal,
        ast.DeleteGlobal,
        ast.GetAttr,
        ast.SetAttr,
        ast.DeleteAttr,
        ast.GetSubscript,
        ast.SetSubscript,
        ast.DeleteSubscript,
        ast.Allocate,
        ast.Load,
        ast.Store,
        ast.Check,
    )
    def visitOK(self, node):
        return node.rewriteChildren(self)

    @dispatch(ast.Discard)
    def visitDiscard(self, node):
        """Rewrite a Discard node, eliminating it if its expression is a constant.

        The check must be on ``result.expr`` (the wrapped expression after
        rewriting children), not on ``node`` itself (which is always
        ``ast.Discard``).  Checking ``isinstance(node, ast.Existing)`` is
        always ``False`` and would never eliminate any discard.
        """
        result = node.rewriteChildren(self)
        # Check result.expr (the wrapped expression), not node itself.
        if isinstance(result.expr, ast.Existing):
            return None
        return result

    @dispatch(ast.leafTypes, ast.Existing, ast.GetCellDeref, ast.Code, ast.DoNotCare)
    def visitASTLeaf(self, node):
        return node

    @dispatch(ast.Assign)
    def visitAssign(self, node):
        expr = self(node.expr)
        if isinstance(expr, ast.Local) and len(node.lcls) == 1:
            # Reach-through optimisation: if the RHS is a simple local, we can
            # map the LHS directly to the (already-renamed) RHS local instead
            # of emitting a copy assignment.
            #
            # Bug #6 fix: the old code also accepted ast.Existing here, but
            # Existing nodes are constants and should never be stored in the
            # frame as the representative of a mutable local — doing so would
            # cause downstream passes to see a constant where they expect a
            # local, breaking SSA invariants.  Only Local-to-Local reach-
            # through is safe.
            #
            # Additionally, the old code stored `expr` (the renamed RHS) in
            # the frame under the *original* LHS key.  That is correct only
            # when `expr` is a freshly-cloned SSA name.  We keep the same
            # logic but restrict it to Local nodes only.
            self.currentFrame[node.lcls[0]] = expr
            return None

        lcls = [self.clone(lcl, self.currentFrame) for lcl in node.lcls]
        return ast.Assign(expr, lcls)

    @dispatch(ast.UnpackSequence)
    def visitUnpackSequence(self, node):
        expr = self(node.expr)

        lcls = [self.clone(lcl, self.currentFrame) for lcl in node.targets]
        return ast.UnpackSequence(expr, lcls)

    # Insert the merges, now that we know all the sources
    def doFixup(self):
        """Insert phi nodes at merge points.

        After renaming is complete, inserts phi nodes at merge blocks
        for variables that are read. The phi nodes merge values from
        all predecessor blocks.

        Uses an iterative approach: only inserts phi nodes for variables
        that are actually read. If a phi node's arguments include variables
        that are read, those variables may need phi nodes too, so the
        process repeats until fixed point.
        """
        merges = []

        changed = True

        for merge in self.fixup:
            for name in self.merge[merge]:
                merges.append((merge, name))

        while merges and changed:
            changed = False
            defer = []

            for merge, name in merges:
                target = self.frames[merge][name]

                if target in self.read:
                    # Variable is read, need phi node
                    arguments = []
                    for prev in merge.reverse():
                        arguments.append(self.frames[prev].get(name))

                    if not any(arg is not None for arg in arguments):
                        defer.append((merge, name))
                        continue

                    self.read.update(arg for arg in arguments if arg is not None)

                    phi = ast.Phi(arguments, target)
                    merge.phi.append(phi)

                    changed = True
                else:
                    # Variable not read, defer phi insertion
                    defer.append((merge, name))

            merges = defer


def evaluate(compiler, g):
    """Convert a CFG to SSA form.

    Main entry point for SSA conversion. Performs:
    1. Dominance analysis to compute dominance frontiers
    2. Collection of variable modifications
    3. Computation of merge points for phi insertion
    4. Variable renaming
    5. Phi node insertion

    Args:
        compiler: Compiler context (unused, kept for interface consistency)
        g: CFG Code object to convert to SSA form

    Algorithm:
        The algorithm follows the standard SSA construction:
        1. Compute dominance frontiers using dominance analysis
        2. For each variable, find all blocks that modify it
        3. Compute iterated dominance frontier (IDF) for modification points
        4. Variables modified in multiple blocks need renaming
        5. Rename variables during reverse post-order traversal
        6. Insert phi nodes at merge points for variables that are read
    """
    if _contains_try_except_finally(g.entryTerminal):
        raise UnsupportedSSAError(
            "CFG SSA does not support TryExceptFinally; refusing to return a non-SSA graph."
        )

    # Analysis: Compute dominance information
    def forward(node):
        return node.forward()

    def bind(node, djnode):
        node.data = djnode

    dom.evaluate([g.entryTerminal], forward, bind)

    # Transform: Collect variable modifications
    cm = CollectModifies()
    dfs = CFGDFS(post=cm)
    dfs.process(g.entryTerminal)

    # Find which variables need renaming and at which merge points
    renames = set()
    merges = {}

    # TODO linear versions of idf?
    for k, v in cm.mod.items():
        # Compute iterated dominance frontier for this variable's modifications
        idf = set()
        pending = set()
        pending.update(v)

        while pending:
            djnode = pending.pop()
            for child in djnode.idf:
                if child not in idf:
                    idf.add(child)
                    pending.add(child)

        # Record merge points where phi nodes are needed
        for djnode in idf:
            if not djnode.node in merges:
                merges[djnode.node] = set()
            merges[djnode.node].add(k)

        if idf:
            renames.add(k)

    # Rename variables in reverse post-order (process definitions before uses)
    order = cm.order
    order.reverse()

    ssar = SSARename(g, renames, merges)
    for node in order:
        ssar(node)
    ssar.doFixup()


def _contains_try_except_finally(entry):
    pending = [entry]
    seen_cfg = set()
    seen_ast = set()

    while pending:
        node = pending.pop()
        if node in seen_cfg:
            continue
        seen_cfg.add(node)

        if isinstance(node, cfg.Suite):
            for op in node.ops:
                if _ast_contains_try_except_finally(op, seen_ast):
                    return True
        elif isinstance(node, cfg.Switch):
            if _ast_contains_try_except_finally(node.condition, seen_ast):
                return True
        elif isinstance(node, cfg.TypeSwitch):
            if _ast_contains_try_except_finally(node.original, seen_ast):
                return True

        pending.extend(node.forward())

    return False


def _ast_contains_try_except_finally(node, seen):
    if node is None:
        return False

    if isinstance(node, ast.TryExceptFinally):
        return True

    node_id = id(node)
    if node_id in seen:
        return False
    seen.add(node_id)

    fields = getattr(type(node), "__fields__", ())
    if isinstance(fields, str):
        fields = (fields,)

    for field in fields:
        name = field.split(":", 1)[0].rstrip("?*")
        child = getattr(node, name, None)
        if isinstance(child, (list, tuple)):
            for item in child:
                if _ast_contains_try_except_finally(item, seen):
                    return True
        elif _ast_contains_try_except_finally(child, seen):
            return True

    return False
