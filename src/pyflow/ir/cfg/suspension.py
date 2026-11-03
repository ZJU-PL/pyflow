"""Lift expression suspensions into explicit CFG pause/resume boundaries."""

from pyflow.language.python import ast

from . import graph


class SuspensionLowerer:
    def __init__(self, transformer):
        self.transformer = transformer
        self.contains = {}

    def has_suspension(self, root):
        pending = [(root, False)]
        while pending:
            node, expanded = pending.pop()
            if id(node) in self.contains:
                continue
            if isinstance(node, (ast.Yield, ast.YieldFrom, ast.AsyncYield, ast.Await)):
                self.contains[id(node)] = (node, True)
                continue
            if isinstance(node, ast.Code):
                self.contains[id(node)] = (node, False)
                continue
            children = (
                tuple(node)
                if isinstance(node, (list, tuple))
                else tuple(getattr(node, "children", lambda: ())())
            )
            if expanded or not children:
                self.contains[id(node)] = (
                    node,
                    any(self.contains[id(child)][1] for child in children),
                )
            else:
                pending.append((node, True))
                pending.extend((child, False) for child in reversed(children))
        return self.contains[id(root)][1]

    def capture(self, value):
        target = ast.Local(None)
        assignment = ast.Assign(value, [target])
        assignment.annotation = value.annotation
        self.transformer.emit_raw(assignment)
        return target

    def lower(self, root):
        if not self.has_suspension(root):
            return root
        stack, result = [self.steps(root)], None
        try:
            while stack:
                try:
                    child, capture = stack[-1].send(result)
                except StopIteration as done:
                    result = done.value
                    stack.pop()
                else:
                    stack.append(self.steps(child, capture))
                    result = None
            return result
        finally:
            for continuation in reversed(stack):
                continuation.close()

    def branch(self, condition):
        owner = self.transformer
        switch = graph.Switch(owner.region, ast.ConvertToBool(condition))
        owner.attachStandardHandlers(switch)
        owner.attachCurrent(switch)
        return switch

    def resume_join(self, merge):
        owner = self.transformer
        owner.attachCurrent(merge)
        merge.setExit("normal", owner.makeNewSuite())

    def steps(self, node, capture=False):
        owner = self.transformer
        if not self.has_suspension(node):
            if capture and isinstance(node, ast.Expression) and not isinstance(node, ast.Existing):
                return self.capture(node)
            return node
        if isinstance(node, (ast.Yield, ast.YieldFrom, ast.AsyncYield, ast.Await)):
            value = yield node.expr, False
            expression = type(node)(value)
            expression.annotation = node.annotation
            operation = ast.Discard(expression)
            operation.annotation = node.annotation
            owner.emit_raw(operation)
            owner._emitYieldBlock(graph.Await if isinstance(node, ast.Await) else graph.Yield)
            target = ast.Local(None)
            source = "await_result" if isinstance(node, ast.Await) else "send"
            operation = ast.InputBlock([ast.Input(ast.IOName(source), target)])
            operation.annotation = node.annotation
            owner.emit_raw(operation)
            return target
        if isinstance(node, ast.NamedExpr):
            value = yield node.value, False
            result = ast.NamedExpr(node.target, value)
            result.annotation = node.annotation
        elif isinstance(node, ast.ConditionalExpr):
            condition = yield node.test, False
            switch, merge, result = self.branch(condition), owner.createMerge(), ast.Local(None)
            switch.setExit("true", owner.makeNewSuite())
            value = yield node.body, False
            owner.emit_raw(ast.Assign(value, [result]))
            owner.attachCurrent(merge)
            switch.setExit("false", owner.makeNewSuite())
            value = yield node.orelse, False
            owner.emit_raw(ast.Assign(value, [result]))
            self.resume_join(merge)
        elif isinstance(node, (ast.ShortCircutAnd, ast.ShortCircutOr)):
            merge, result = owner.createMerge(), ast.Local(None)
            for index, term in enumerate(node.terms):
                value = yield term, False
                owner.emit_raw(ast.Assign(value, [result]))
                if index + 1 < len(node.terms):
                    switch = self.branch(result)
                    proceed, stop = (
                        ("true", "false")
                        if isinstance(node, ast.ShortCircutAnd)
                        else ("false", "true")
                    )
                    switch.setExit(stop, merge)
                    switch.setExit(proceed, owner.makeNewSuite())
            self.resume_join(merge)
        else:
            children = []
            if isinstance(node, (list, tuple)):
                children.extend(node)
            else:
                node.rewriteChildren(lambda child: children.append(child) or child)
            rewritten = []
            last_pause = max(
                (i for i, child in enumerate(children) if self.has_suspension(child)), default=-1
            )
            for index, child in enumerate(children):
                rewritten.append((yield child, index < last_pause))
            if isinstance(node, (list, tuple)):
                return type(node)(rewritten)
            values = iter(rewritten)
            result = node.rewriteChildren(lambda child: next(values))
        return self.capture(result) if capture and isinstance(result, ast.Expression) else result
