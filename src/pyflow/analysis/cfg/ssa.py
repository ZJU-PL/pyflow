"""Static Single Assignment (SSA) form conversion for CFGs.

This module implements the conversion of control flow graphs to SSA form,
including phi function insertion and variable renaming.
"""

from pyflow.util.typedispatch import *
from pyflow.language.python import ast

from . import graph as cfg
from .dfs import CFGDFS
from . import dom


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

    @dispatch(cfg.Entry)
    def visitCFGEntry(self, node):
        frame = {}

        cparam = self.g.code.codeparameters

        # Set the parameters

        selfparam = self.clone(cparam.selfparam, frame)
        params = [self.clone(p, frame) for p in cparam.params]
        vparam = self.clone(cparam.vparam, frame)
        kparam = self.clone(cparam.kparam, frame)

        # Construct the parameters
        self.g.code.codeparameters = ast.CodeParameters(
            selfparam,
            params,
            cparam.paramnames,
            cparam.defaults,
            vparam,
            kparam,
            cparam.returnparams,
        )

        self.currentFrame = frame
        self.frames[node] = frame

    @dispatch(cfg.Exit)
    def visitCFGLeaf(self, node):
        pass

    @dispatch(cfg.Suite)
    def visitCFGSuite(self, node):
        self.currentFrame = dict(self.frames[node.prev])

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
        result = node.rewriteChildren(self)
        if isinstance(node, ast.Existing):
            return None
        return result

    @dispatch(ast.leafTypes, ast.Existing, ast.GetCellDeref, ast.Code, ast.DoNotCare)
    def visitASTLeaf(self, node):
        return node

    @dispatch(ast.Assign)
    def visitAssign(self, node):
        expr = self(node.expr)
        if isinstance(expr, (ast.Local, ast.Existing)):
            if len(node.lcls) == 1:
                # Reach
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

                    self.read.update(arguments)

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
