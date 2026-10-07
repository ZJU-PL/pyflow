"""Lazy generator suspension compiled into ordinary seven-instruction MIR.

A factory call binds Python parameters and allocates a persistent environment.
The generator's raw resume closure captures that environment.  Each resume call
dispatches on a stored program counter, and every temporary that can cross a
yield is lifted into the frame.  No native generator, Python execution hook, or
eager execution of the body is involved.

The implemented lifecycle includes iteration, send, return values, delegation
with yield-from, and PEP 479 conversion of escaping StopIteration.  Throw/close
and asynchronous generators require additional exception-injection protocols.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field as dataclass_field

from .builder import Builder, field
from .model import (
    Alloc,
    Assume,
    Attr,
    Binary,
    Bind,
    Call,
    Delete,
    DictExpr,
    Env,
    Lambda,
    Length,
    ListExpr,
    Literal,
    Node,
    Not,
    Var,
)


class _YieldFinder(ast.NodeVisitor):
    def __init__(self):
        self.found = False

    def visit_Yield(self, node):
        self.found = True

    visit_YieldFrom = visit_Yield

    def visit_FunctionDef(self, node):
        # Defaults/decorators run in the enclosing scope; the nested body does not.
        for item in (
            *node.decorator_list,
            *node.args.defaults,
            *(value for value in node.args.kw_defaults if value is not None),
        ):
            self.visit(item)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Lambda(self, node):
        for item in (
            *node.args.defaults,
            *(value for value in node.args.kw_defaults if value is not None),
        ):
            self.visit(item)

    def visit_ClassDef(self, node):
        for item in (
            *node.decorator_list,
            *node.bases,
            *(keyword.value for keyword in node.keywords),
        ):
            self.visit(item)


def contains_yield(node) -> bool:
    """Inspect one function's body, excluding nested functions/classes/lambdas."""
    finder = _YieldFinder()
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        nodes = node.body
    elif isinstance(node, ast.Lambda):
        nodes = [node.body]
    elif isinstance(node, (list, tuple)):
        nodes = node
    else:
        nodes = [node]
    for item in nodes:
        finder.visit(item)
    return finder.found


@dataclass
class GeneratorState:
    name: str
    continuations: list[int] = dataclass_field(default_factory=list)


def _frame():
    return Var("$parent")


def _generator():
    return field(_frame(), "$generator")


def _stop(compiler, value):
    b, rt = compiler.b, compiler.runtime
    b.assign(field(_generator(), "$done"), rt.raw(b, True))
    b.assign(field(_frame(), "$pc"), rt.raw(b, -1))
    exception = rt.obj(b, "StopIteration")
    b.assign(field(exception, "value"), value)
    empty, returned = b.branch(Binary("=", value, rt.none))
    b.use(empty)
    b.assign(field(exception, "args"), rt.sequence(b, (), "tuple"))
    empty_tails = set(b.tails)
    b.use(returned)
    b.assign(field(exception, "args"), rt.sequence(b, (value,), "tuple"))
    b.join(empty_tails, b.tails)
    b.assign(rt.exception, exception)
    b.ret(rt.none)


def emit_generator_return(compiler, node=None) -> None:
    """Compile a source Return (or an implicit return) without running eagerly."""
    b, rt = compiler.b, compiler.runtime
    if isinstance(node, ast.Return):
        value = compiler.expression(node.value) if node.value is not None else rt.none
    elif node is None:
        value = rt.none
    else:
        value = node
    value = b.bind(value, "generator_returned")
    compiler._run_finalizers()
    if b.tails:
        _stop(compiler, value)


def _yield_value(compiler, value):
    b = compiler.b
    state = compiler.generator_state
    if state is None:
        raise ValueError("A yield requires an active generator lowering state")
    continuation = b.node()
    state.continuations.append(continuation)
    b.assign(field(_frame(), "$pc"), b.alloc(Literal(continuation), "resume_pc"))
    b.ret(value)
    b.use({continuation})
    return field(_frame(), "$sent")


def emit_yield(compiler, node):
    """Lower Yield/YieldFrom and return the value received by the expression."""
    if isinstance(node, ast.Yield):
        value = compiler.expression(node.value) if node.value is not None else compiler.runtime.none
        return _yield_value(compiler, value)
    if not isinstance(node, ast.YieldFrom):
        raise TypeError("Expected Yield or YieldFrom")
    b, rt = compiler.b, compiler.runtime
    iterator = compiler.call(rt.builtin("iter"), (compiler.expression(node.value),))
    sent = b.bind(rt.none, "delegate_sent")
    result = b.bind(rt.none, "delegate_return")
    yielded = Var(b.temp("delegated_value"))
    head, exhausted, done = b.node(), b.node(), b.node()
    previous_exception = compiler.exception_target
    b.jump(head)
    b.use({head})
    compiler.exception_target = exhausted
    next_, send = b.branch(Binary("=", sent, rt.none))
    b.use(next_)
    b.assign(yielded, compiler.call(rt.builtin("next"), (iterator,)))
    next_tails = set(b.tails)
    b.use(send)
    method = compiler.get_attribute(iterator, "send")
    b.assign(yielded, compiler.call(method, (sent,)))
    b.join(next_tails, b.tails)
    compiler.exception_target = previous_exception
    b.assign(sent, _yield_value(compiler, yielded))
    b.jump(head)
    b.use({exhausted})
    stopped = rt.contains_class(b, field(rt.exception, "__class__"), rt.builtin("StopIteration"))
    stop, other = b.branch(stopped)
    b.use(other)
    b.jump(previous_exception)
    b.use(stop)
    has_value, empty = b.branch(Binary("in", Literal("value"), rt.exception))
    b.use(has_value)
    b.assign(result, field(rt.exception, "value"))
    b.join(b.tails, empty)
    b.assign(rt.exception, rt.none)
    b.jump(done)
    b.use({done})
    return result


_LOCAL_CONTEXT = {
    "$args",
    "$kwargs",
    "$parent",
    "$return",
    "$builtins",
    "$global",
    "$modules",
    "$env",
}


def _lift_expression(expression):
    if isinstance(expression, Var):
        return expression if expression.name in _LOCAL_CONTEXT else field(_frame(), expression.name)
    if isinstance(expression, Attr):
        return Attr(_lift_expression(expression.base), _lift_expression(expression.key))
    if isinstance(expression, ListExpr):
        return ListExpr(tuple(_lift_expression(item) for item in expression.items))
    if isinstance(expression, DictExpr):
        return DictExpr(tuple((key, _lift_expression(value)) for key, value in expression.items))
    if isinstance(expression, (Not, Length)):
        return type(expression)(_lift_expression(expression.operand))
    if isinstance(expression, Binary):
        return Binary(
            expression.op, _lift_expression(expression.left), _lift_expression(expression.right)
        )
    # Lambda captures the actual resume environment; lexical lookup explicitly
    # skips that wrapper when entering a generator's persistent parent frame.
    return expression


def _lift_frame(cfg):
    """Persist allocations, bindings, environments and call-result temporaries.

    Core Alloc/Call/Env have identifier targets, so a transformed instruction
    writes a fresh resume-local scratch identifier and an added Bind publishes
    its address in the frame.  Original node IDs remain valid continuation PCs.
    """
    next_node = max(cfg.nodes) + 1
    for node_id, node in list(cfg.nodes.items()):
        instruction = node.instruction
        target = None
        if isinstance(instruction, Alloc):
            target = instruction.target
            instruction = Alloc(target, _lift_expression(instruction.value))
        elif isinstance(instruction, Call):
            target = instruction.target
            instruction = Call(
                target,
                _lift_expression(instruction.function),
                _lift_expression(instruction.args),
                _lift_expression(instruction.kwargs),
            )
        elif isinstance(instruction, Env):
            target = instruction.target
        elif isinstance(instruction, Bind):
            instruction = Bind(
                _lift_expression(instruction.target), _lift_expression(instruction.source)
            )
        elif isinstance(instruction, Delete):
            instruction = Delete(_lift_expression(instruction.target))
        elif isinstance(instruction, Assume):
            instruction = Assume(_lift_expression(instruction.condition))
        if target is not None and target not in _LOCAL_CONTEXT:
            scratch = f"$resume_scratch_{node_id}"
            if isinstance(instruction, Alloc):
                instruction = Alloc(scratch, instruction.value)
            elif isinstance(instruction, Call):
                instruction = Call(
                    scratch, instruction.function, instruction.args, instruction.kwargs
                )
            else:
                instruction = Env(scratch)
            cfg.nodes[next_node] = Node(
                next_node,
                Bind(field(_frame(), target), Var(scratch)),
                node.successors,
                node.lineno,
            )
            node.successors = (next_node,)
            next_node += 1
        node.instruction = instruction


def lower_generator(compiler, node, lambda_body=None, _body_emitter=None):
    """Return a Python function object whose calls create lazy MIR generators."""
    from .lowering import Scope, _Bindings

    outer, parent, rt = compiler.b, compiler.scope, compiler.runtime
    compiler.serial += 1
    short = getattr(node, "name", f"<lambda{compiler.serial}>")
    name = f"{parent.name}.{short}"
    if name in compiler.program.cfgs:
        name += f"@{getattr(node, 'lineno', compiler.serial)}:{compiler.serial}"
    factory_name = name + ".$factory"
    decorators = [compiler.expression(item) for item in getattr(node, "decorator_list", ())]
    defaults = [compiler.expression(item) for item in node.args.defaults]
    kwdefaults = [
        (arg.arg, compiler.expression(default))
        for arg, default in zip(node.args.kwonlyargs, node.args.kw_defaults)
        if default is not None
    ]
    defaults_ref = outer.alloc(ListExpr(tuple(defaults)), "defaults")
    kwdefaults_ref = outer.alloc(DictExpr(tuple(kwdefaults)), "kwdefaults")
    saved = compiler._state()
    body = [ast.Return(value=lambda_body)] if lambda_body is not None else node.body
    bindings = _Bindings(body, node.args)
    lexical_parent = parent.parent if parent.kind == "class" else parent
    method_class = (
        parent.class_object.name
        if parent.kind == "class" and isinstance(parent.class_object, Var)
        else None
    )
    positional = (*node.args.posonlyargs, *node.args.args)
    first = positional[0].arg if positional else None

    factory = Builder(compiler.program, factory_name, compiler.module.filename, synthetic=True)
    compiler.b = factory
    compiler.scope = Scope(
        name,
        "function",
        parent.module,
        bindings,
        lexical_parent,
        method_class_name=method_class,
        first_parameter=first,
    )
    compiler.exception_target = factory.cfg.exit
    compiler.loop_targets, compiler.finalizers, compiler.active_exception = [], [], None
    compiler.generator_state = None
    for context in ("$builtins", "$global", "$modules"):
        factory.assign(context, field(Var("$parent"), context))
    factory.emit(Env("$env"))
    factory.assign("$return", rt.none)
    compiler.parameters(node.args, defaults_ref.name, kwdefaults_ref.name)
    generator = rt.obj(factory, "generator")
    factory.assign("$generator", generator)
    factory.assign("$pc", rt.raw(factory, 0))
    factory.assign("$sent", rt.none)
    factory.assign(field(generator, "$frame"), Var("$env"))
    for flag in ("$done", "$started", "$running"):
        factory.assign(field(generator, flag), rt.raw(factory, False))
    resume = factory.alloc(Lambda("$args", "$kwargs", "$parent", name, "$return"), "resume")
    factory.assign(field(generator, "$resume"), resume)
    factory.ret(generator)
    factory.finish()

    b = Builder(compiler.program, name, compiler.module.filename)
    compiler.b = b
    compiler.scope = Scope(
        name,
        "generator",
        parent.module,
        bindings,
        lexical_parent,
        method_class_name=method_class,
        first_parameter=first,
    )
    compiler.loop_targets, compiler.finalizers, compiler.active_exception = [], [], None
    state = GeneratorState(name)
    compiler.generator_state = state
    error_exit = b.node()
    compiler.exception_target = error_exit
    for context in ("$builtins", "$global", "$modules"):
        b.assign(context, field(_frame(), context))
    b.assign("$env", _frame())
    b.assign("$return", rt.none)
    dispatch = b.node()
    b.jump(dispatch)
    first_body = b.node()
    b.use({first_body})
    if _body_emitter is None:
        compiler.statements(body)
    else:
        _body_emitter()
    emit_generator_return(compiler)

    b.use({error_exit})
    b.assign(field(_generator(), "$done"), rt.raw(b, True))
    b.assign(field(_frame(), "$pc"), rt.raw(b, -1))
    stopped = rt.contains_class(b, field(rt.exception, "__class__"), rt.builtin("StopIteration"))
    convert, ordinary = b.branch(stopped)
    b.use(convert)
    previous = b.bind(rt.exception, "generator_stop")
    exception = rt.obj(b, "RuntimeError")
    b.assign(field(exception, "__cause__"), previous)
    b.assign(rt.exception, exception)
    b.join(b.tails, ordinary)
    b.ret(rt.none)

    b.use({dispatch})
    for pc, target in [(0, first_body), *((target, target) for target in state.continuations)]:
        matches, remaining = b.branch(Binary("=", field(_frame(), "$pc"), Literal(pc)))
        b.use(matches)
        b.jump(target)
        b.use(remaining)
    # Direct calls to an exhausted resume closure remain well-defined too.
    _stop(compiler, rt.none)
    b.finish()
    _lift_frame(b.cfg)
    compiler._restore(saved)
    function = rt.function(outer, factory_name)
    for decorator in reversed(decorators):
        function = compiler.call(decorator, (function,))
    return function


def lower_generator_expression(compiler, node):
    """Compile a genexpr, evaluating only its outer iterator at construction."""
    if any(generator.is_async for generator in node.generators):
        compiler.fail(node, "asynchronous generator expressions are not supported")
    compiler.serial += 1
    parameter = f"$genexpr_iterator_{compiler.serial}"
    # iter() on the outermost iterable is evaluated now, as required by Python.
    initial = compiler.call(
        compiler.runtime.builtin("iter"), (compiler.expression(node.generators[0].iter),)
    )
    assignments = [
        ast.Assign(targets=[item.target], value=ast.Constant(None)) for item in node.generators
    ]
    fake = ast.FunctionDef(
        name=f"<genexpr{compiler.serial}>",
        args=ast.arguments(
            posonlyargs=[],
            args=[ast.arg(arg=parameter)],
            vararg=None,
            kwonlyargs=[],
            kw_defaults=[],
            kwarg=None,
            defaults=[],
        ),
        body=assignments,
        decorator_list=[],
        returns=None,
        type_comment=None,
    )
    ast.copy_location(fake, node)

    def emit_body():
        def descend(index):
            b, rt = compiler.b, compiler.runtime
            clause = node.generators[index]
            iterator = (
                compiler.name_ref(parameter)
                if index == 0
                else compiler.call(rt.builtin("iter"), (compiler.expression(clause.iter),))
            )

            def consume(item):
                compiler.store(clause.target, item)
                skipped = []
                for condition in clause.ifs:
                    yes, no = b.branch(compiler.truth(compiler.expression(condition)))
                    skipped.append(no)
                    b.use(yes)
                if index + 1 < len(node.generators):
                    descend(index + 1)
                else:
                    _yield_value(compiler, compiler.expression(node.elt))
                b.join(b.tails, *skipped)

            compiler.iterate(iterator, consume)

        descend(0)

    function = lower_generator(compiler, fake, _body_emitter=emit_body)
    return compiler.call(function, (initial,))


__all__ = [
    "contains_yield",
    "GeneratorState",
    "lower_generator",
    "emit_yield",
    "emit_generator_return",
    "lower_generator_expression",
]
