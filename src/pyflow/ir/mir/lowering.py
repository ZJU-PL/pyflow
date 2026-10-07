"""Source-only Python lowering to the formal seven-instruction MIR.

The AST is consumed here, once. Neither the reference interpreter nor the
PyCG solver imports, executes, or revisits source Python. Unsupported syntax
and unavailable import models are errors with source locations.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field as dataclass_field
from pathlib import Path
import tokenize

from .builder import Builder, field
from .model import (
    Alloc,
    Binary,
    Delete,
    DictExpr,
    Env,
    Length,
    ListExpr,
    Lambda,
    Literal,
    NewObject,
    Not,
    Program,
    Var,
)
from .runtime import Runtime


class LoweringError(ValueError):
    """Python source requires a feature outside the explicit MIR frontend."""

    def __init__(self, message, filename="<string>", lineno=None):
        self.filename, self.lineno = filename, lineno
        location = filename + (f":{lineno}" if lineno is not None else "")
        super().__init__(f"{location}: {message}")


class _Bindings(ast.NodeVisitor):
    def __init__(self, statements=(), arguments=None):
        self.locals, self.globals, self.nonlocals = set(), set(), set()
        for node in statements:
            self.visit(node)
        if arguments is not None:
            self.locals.update(
                arg.arg for arg in (*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs)
            )
            if arguments.vararg:
                self.locals.add(arguments.vararg.arg)
            if arguments.kwarg:
                self.locals.add(arguments.kwarg.arg)
        self.locals.difference_update(self.globals | self.nonlocals)

    def visit_Name(self, node):
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.locals.add(node.id)

    def visit_FunctionDef(self, node):
        self.locals.add(node.name)

    visit_AsyncFunctionDef = visit_FunctionDef
    visit_ClassDef = visit_FunctionDef

    def visit_Lambda(self, node):
        pass

    def visit_Global(self, node):
        self.globals.update(node.names)

    def visit_Nonlocal(self, node):
        self.nonlocals.update(node.names)

    def visit_Import(self, node):
        self.locals.update(alias.asname or alias.name.split(".")[0] for alias in node.names)

    def visit_ImportFrom(self, node):
        self.locals.update(alias.asname or alias.name for alias in node.names if alias.name != "*")

    def visit_ExceptHandler(self, node):
        if node.name:
            self.locals.add(node.name)
        self.generic_visit(node)

    def visit_ListComp(self, node):
        # Comprehension iteration variables live in their own lexical scope.
        self.visit(node.generators[0].iter)

    visit_SetComp = visit_ListComp
    visit_DictComp = visit_ListComp
    visit_GeneratorExp = visit_ListComp


@dataclass
class Scope:
    name: str
    kind: str
    module: str
    bindings: _Bindings
    parent: Scope | None = None
    class_object: object = None
    method_class_name: str | None = None
    first_parameter: str | None = None


@dataclass
class Module:
    name: str
    tree: ast.Module
    filename: str
    package: str
    imports: dict[int, tuple[str, ...]] = dataclass_field(default_factory=dict)


class PythonToMIR:
    """Compile a statically discovered local module graph without importing it."""

    def __init__(self, modules, entry):
        self.modules = modules
        self.entry_module = entry
        self.program = Program({}, "$entry")
        self.runtime = Runtime(self.program)
        self.b = None
        self.scope = None
        self.module = None
        self.exception_target = None
        self.loop_targets = []
        self.finalizers = []
        self.active_exception = None
        self.generator_state = None
        self.serial = 0

    def fail(self, node, message):
        raise LoweringError(message, self.module.filename, getattr(node, "lineno", None))

    def compile(self):
        from .builtins import initialize

        entry = Builder(self.program, "$entry", synthetic=True)
        initialize(self.runtime, entry)
        entry.emit(Env("$global"))
        entry.emit(Alloc("$modules", NewObject()))
        # Register every module before running any body; this supports cycles.
        for name in sorted(self.modules):
            obj = self.runtime.obj(entry, "module")
            entry.assign(field(obj, "$module"), self.runtime.raw(entry, True))
            entry.assign(field(obj, "$loaded"), self.runtime.raw(entry, False))
            loader = entry.alloc(
                Lambda("$args", "$kwargs", "$parent", name, "$return"), "module_loader"
            )
            entry.assign(field(obj, "$loader"), loader)
            entry.assign(field(Var("$modules"), name), obj)
        root = field(Var("$modules"), self.entry_module)
        args, kwargs = entry.alloc(ListExpr(())), entry.alloc(DictExpr(()))
        entry.call(field(root, "$loader"), args, kwargs)
        entry.assign("$return", root)
        entry.finish()
        for module in list(self.modules.values()):
            self.compile_module(module)
        self.program.validate()
        return self.program

    def compile_module(self, module):
        self.module = module
        self.b = Builder(self.program, module.name, module.filename)
        self.scope = Scope(module.name, "module", module.name, _Bindings(module.tree.body))
        self.exception_target = self.b.cfg.exit
        self.loop_targets, self.finalizers, self.active_exception = [], [], None
        b = self.b
        b.assign("$builtins", field(Var("$parent"), "$builtins"))
        b.assign("$modules", field(Var("$parent"), "$modules"))
        b.assign("$module", field(Var("$modules"), module.name))
        b.emit(Env("$global"))
        b.emit(Env("$env"))
        b.assign(field(Var("$module"), "$env"), Var("$env"))
        b.assign(field(Var("$module"), "$loaded"), self.runtime.raw(b, True))
        b.assign("$return", self.runtime.none)
        b.assign("__name__", self.runtime.box(b, module.name))
        b.assign("__package__", self.runtime.box(b, module.package))
        self.statements(module.tree.body)
        b.finish()

    def checked(self):
        b = self.b
        good, bad = b.branch(Binary("=", self.runtime.exception, self.runtime.none))
        b.use(bad)
        b.jump(self.exception_target)
        b.use(good)

    def error(self, kind="TypeError"):
        exc = self.runtime.obj(self.b, kind)
        self.b.assign(self.runtime.exception, exc)
        self.b.jump(self.exception_target)

    def name_ref(self, name, store=False):
        scope = self.scope
        if scope.kind == "class" and name in scope.bindings.locals:
            return field(scope.class_object, name)
        if name in scope.bindings.locals or scope.kind == "module":
            if scope.kind == "generator":
                return field(Var("$parent"), name)
            return Var(name)
        if name in scope.bindings.globals:
            return field(Var("$global"), name)
        parent = scope.parent
        env = field(Var("$parent"), "$parent") if scope.kind == "generator" else Var("$parent")
        while parent is not None and parent.kind != "module":
            if parent.kind == "class":
                parent = parent.parent
                continue
            if parent.kind == "generator":
                env = field(env, "$parent")
            if name in parent.bindings.locals:
                return field(env, name)
            env = field(env, "$parent")
            parent = parent.parent
        if name in scope.bindings.nonlocals:
            raise LoweringError(f"no enclosing binding for nonlocal {name!r}", self.module.filename)
        return field(Var("$global"), name)

    def load_name(self, node):
        b, rt = self.b, self.runtime
        name = node.id
        if name == "__class__" and self.scope.method_class_name:
            parent_env = self.defining_environment()
            return field(parent_env, self.scope.method_class_name)
        if name in {"None", "NotImplemented"}:
            return rt.builtin(name)
        ref = self.name_ref(name)
        if self.scope.kind not in {"class", "module"} and name in self.scope.bindings.locals:
            # Locals have lexical binding even before their first assignment.
            owner = Var("$parent") if self.scope.kind == "generator" else Var("$env")
            exists, absent = b.branch(Binary("in", Literal(name), owner))
            b.use(absent)
            self.error("NameError")
            b.use(exists)
            return ref
        owner = ref.base if hasattr(ref, "base") else Var("$env")
        exists, absent = b.branch(Binary("in", Literal(name), owner))
        result = Var(b.temp("name"))
        b.use(exists)
        b.assign(result, ref)
        present = set(b.tails)
        b.use(absent)
        # Class-body lookup falls through to its enclosing lexical scope.
        if self.scope.kind == "class":
            saved = self.scope
            self.scope = saved.parent
            b.assign(result, self.load_name(node))
            self.scope = saved
        else:
            builtin, missing = b.branch(Binary("in", Literal(name), Var("$builtins")))
            b.use(missing)
            self.error("NameError")
            b.use(builtin)
            b.assign(result, rt.builtin(name))
        b.join(present, b.tails)
        return result

    def statements(self, statements):
        for node in statements:
            if not self.b.tails:
                # Still check/compile unreachable syntax into disconnected CFG
                # nodes. Analyses traverse CFG reachability, not dictionary order.
                pass
            self.statement(node)

    def truth(self, value):
        result = self.runtime.invoke(self.b, "truth", (value,))
        self.checked()
        return result

    def call(self, callee, args=(), kwargs=None, raw_args=None):
        result = self.runtime.call(self.b, callee, args, kwargs, raw_args)
        self.checked()
        return result

    def get_attribute(self, obj, name):
        key = self.runtime.raw(self.b, name) if isinstance(name, str) else name
        result = self.runtime.invoke(self.b, "getattr", (obj, key))
        self.checked()
        return result

    def special(self, obj, method, args=()):
        result = self.runtime.special(self.b, obj, method, args)
        self.checked()
        return result

    def expression(self, node):
        b, rt = self.b, self.runtime
        b.lineno = getattr(node, "lineno", b.lineno)
        if isinstance(node, ast.Constant):
            if node.value is None:
                return rt.none
            if type(node.value) not in (bool, int, str):
                self.fail(
                    node,
                    f"literal {type(node.value).__name__} is not in MIR's "
                    "bool/int/string primitive model",
                )
            return rt.box(b, node.value)
        if isinstance(node, ast.Name):
            return self.load_name(node)
        if isinstance(node, ast.Attribute):
            return self.get_attribute(self.expression(node.value), node.attr)
        if isinstance(node, ast.Call):
            if (
                isinstance(node.func, ast.Name)
                and node.func.id == "super"
                and not node.args
                and not node.keywords
            ):
                if not self.scope.method_class_name or not self.scope.first_parameter:
                    self.fail(
                        node, "zero-argument super() requires a method with a positional receiver"
                    )
                env = self.defining_environment()
                cls = field(env, self.scope.method_class_name)
                receiver = self.load_name(ast.Name(id=self.scope.first_parameter, ctx=ast.Load()))
                return self.call(rt.builtin("super"), (cls, receiver))
            callee = self.expression(node.func)
            positional = b.alloc(ListExpr(()), "positional")
            for arg in node.args:
                if isinstance(arg, ast.Starred):
                    expanded = self.collect_iterable(self.expression(arg.value))
                    b.emit(Alloc(positional.name, Binary("+", positional, expanded)))
                else:
                    value = self.expression(arg)
                    one = b.alloc(ListExpr((value,)), "argument")
                    b.emit(Alloc(positional.name, Binary("+", positional, one)))
            keywords = b.alloc(DictExpr(()), "keywords")
            keyword_keys = b.alloc(ListExpr(()), "keyword_keys")
            for keyword in node.keywords:
                if keyword.arg is None:
                    self.expand_keywords(
                        keywords, keyword_keys, self.expression(keyword.value), node
                    )
                else:
                    value = self.expression(keyword.value)
                    present, absent = b.branch(Binary("in", Literal(keyword.arg), keywords))
                    b.use(present)
                    self.error("TypeError")
                    b.use(absent)
                    b.assign(field(keywords, keyword.arg), value)
                    self._append_raw(keyword_keys, rt.box(b, keyword.arg, "str"))
            abi_kwargs = b.alloc(
                DictExpr((("$values", keywords), ("$keys", keyword_keys))), "keyword_abi"
            )
            return self.call(callee, kwargs=abi_kwargs, raw_args=positional)
        if isinstance(node, ast.Lambda):
            return self.function(node, lambda_body=node.body)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            values = b.alloc(ListExpr(()), "elements")
            for item in node.elts:
                if isinstance(item, ast.Starred):
                    more = self.collect_iterable(self.expression(item.value))
                else:
                    more = b.alloc(ListExpr((self.expression(item),)), "element")
                b.emit(Alloc(values.name, Binary("+", values, more)))
            return rt.box(
                b,
                values,
                (
                    "list"
                    if isinstance(node, ast.List)
                    else "tuple" if isinstance(node, ast.Tuple) else "set"
                ),
            )
        if isinstance(node, ast.Dict):
            result = rt.sequence(b, (), "dict")
            for key, value in zip(node.keys, node.values):
                if key is None:
                    self.fail(
                        node,
                        "dictionary unpacking in displays is not supported; "
                        "use explicit item assignments",
                    )
                self.special(result, "__setitem__", (self.expression(key), self.expression(value)))
            return result
        if isinstance(node, ast.Subscript):
            if isinstance(node.slice, ast.Slice):
                self.fail(node, "slice objects are not part of the current Python-to-MIR runtime")
            return self.special(
                self.expression(node.value), "__getitem__", (self.expression(node.slice),)
            )
        if isinstance(node, ast.BinOp):
            symbols = {
                ast.Add: "+",
                ast.Sub: "-",
                ast.Mult: "*",
                ast.Div: "/",
                ast.FloorDiv: "//",
                ast.Mod: "%",
                ast.Pow: "**",
                ast.MatMult: "@",
                ast.BitAnd: "&",
                ast.BitOr: "|",
                ast.BitXor: "^",
                ast.LShift: "<<",
                ast.RShift: ">>",
            }
            left, right = self.expression(node.left), self.expression(node.right)
            result = rt.invoke(b, "binary", (left, right), symbols[type(node.op)])
            self.checked()
            return result
        if isinstance(node, ast.UnaryOp):
            value = self.expression(node.operand)
            if isinstance(node.op, ast.Not):
                return rt.box(b, Not(self.truth(value)), "bool")
            return self.special(
                value,
                {ast.UAdd: "__pos__", ast.USub: "__neg__", ast.Invert: "__invert__"}[type(node.op)],
            )
        if isinstance(node, ast.BoolOp):
            result = b.bind(self.expression(node.values[0]), "boolop")
            done = b.node()
            for value in node.values[1:]:
                yes, no = b.branch(self.truth(result))
                proceed, stop = (yes, no) if isinstance(node.op, ast.And) else (no, yes)
                b.use(stop)
                b.jump(done)
                b.use(proceed)
                b.assign(result, self.expression(value))
            b.jump(done)
            b.use({done})
            return result
        if isinstance(node, ast.IfExp):
            yes, no = b.branch(self.truth(self.expression(node.test)))
            result = Var(b.temp("choice"))
            b.use(yes)
            b.assign(result, self.expression(node.body))
            first = set(b.tails)
            b.use(no)
            b.assign(result, self.expression(node.orelse))
            b.join(first, b.tails)
            return result
        if isinstance(node, ast.Compare):
            result = Var(b.temp("comparison"))
            left = self.expression(node.left)
            done = b.node()
            names = {
                ast.Eq: "==",
                ast.NotEq: "!=",
                ast.Lt: "<",
                ast.LtE: "<=",
                ast.Gt: ">",
                ast.GtE: ">=",
            }
            for offset, (op, rhs) in enumerate(zip(node.ops, node.comparators)):
                right = self.expression(rhs)
                if isinstance(op, (ast.Is, ast.IsNot)):
                    raw = Binary("=", left, right)
                    value = rt.box(b, Not(raw) if isinstance(op, ast.IsNot) else raw, "bool")
                elif isinstance(op, (ast.In, ast.NotIn)):
                    value = rt.invoke(b, "contains", (left, right))
                    self.checked()
                    if isinstance(op, ast.NotIn):
                        value = rt.box(b, Not(self.truth(value)), "bool")
                else:
                    value = rt.invoke(b, "binary", (left, right), names[type(op)])
                    self.checked()
                b.assign(result, value)
                if offset < len(node.ops) - 1:
                    yes, no = b.branch(self.truth(result))
                    b.use(no)
                    b.jump(done)
                    b.use(yes)
                left = right
            b.jump(done)
            b.use({done})
            return result
        if isinstance(node, ast.NamedExpr):
            value = self.expression(node.value)
            self.store(node.target, value)
            return value
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            return self.comprehension(node)
        if isinstance(node, (ast.Yield, ast.YieldFrom)):
            if self.generator_state is None:
                self.fail(node, "yield outside a generator function")
            from .generators import emit_yield

            return emit_yield(self, node)
        if isinstance(node, (ast.Await, ast.JoinedStr)):
            self.fail(node, f"{type(node).__name__} is not supported by the MIR frontend")
        self.fail(node, f"unsupported expression {type(node).__name__}")

    def collect_iterable(self, value):
        b = self.b
        iterator = self.call(self.runtime.builtin("iter"), (value,))
        elements = b.alloc(ListExpr(()), "unpacked")
        self.iterate(iterator, lambda item: self._append_raw(elements, item))
        return elements

    def _append_raw(self, sequence, value):
        one = self.b.alloc(ListExpr((value,)), "one")
        self.b.emit(Alloc(sequence.name, Binary("+", sequence, one)))

    def iterate(self, iterator, body):
        """Lower iteration, catching only StopIteration from next()."""
        b, rt = self.b, self.runtime
        head, done, exception = b.node(), b.node(), b.node()
        b.jump(head)
        b.use({head})
        saved = self.exception_target
        self.exception_target = exception
        value = self.call(rt.builtin("next"), (iterator,))
        self.exception_target = saved
        body(value)
        b.jump(head)
        b.use({exception})
        stopped = rt.contains_class(
            b, field(rt.exception, "__class__"), rt.builtin("StopIteration")
        )
        yes, no = b.branch(stopped)
        b.use(no)
        b.jump(saved)
        b.use(yes)
        b.assign(rt.exception, rt.none)
        b.jump(done)
        b.use({done})

    def expand_keywords(self, target, keys, value, node):
        b = self.b
        # Dictionary entries retain Python keys; the ABI uses raw string keys.
        entries = b.bind(field(value, "$value"), "entries")
        index = b.alloc(Literal(1), "keyindex")
        head, done = b.node(), b.node()
        b.jump(head)
        b.use({head})
        yes, no = b.branch(Not(Binary("<", Length(entries), index)))
        b.use(no)
        b.jump(done)
        b.use(yes)
        pair = b.bind(field(entries, index), "pair")
        key = b.bind(field(field(pair, "key"), "$value"), "key")
        duplicate, absent = b.branch(Binary("in", key, target))
        b.use(duplicate)
        self.error("TypeError")
        b.use(absent)
        b.assign(field(target, key), field(pair, "value"))
        self._append_raw(keys, field(pair, "key"))
        b.emit(Alloc(index.name, Binary("+", index, Literal(1))))
        b.jump(head)
        b.use({done})

    def store(self, target, value):
        b, rt = self.b, self.runtime
        if isinstance(target, ast.Name):
            b.assign(self.name_ref(target.id, store=True), value)
        elif isinstance(target, ast.Attribute):
            obj = self.expression(target.value)
            rt.invoke(b, "setattr", (obj, rt.raw(b, target.attr), value))
            self.checked()
        elif isinstance(target, ast.Subscript):
            if isinstance(target.slice, ast.Slice):
                self.fail(target, "slice assignment is not supported")
            self.special(
                self.expression(target.value), "__setitem__", (self.expression(target.slice), value)
            )
        elif isinstance(target, (ast.Tuple, ast.List)):
            items = self.collect_iterable(value)
            stars = [i for i, element in enumerate(target.elts) if isinstance(element, ast.Starred)]
            if len(stars) > 1:
                self.fail(target, "multiple starred assignment targets")
            needed = len(target.elts) - bool(stars)
            valid = (
                Not(Binary("<", Length(items), Literal(needed)))
                if stars
                else Binary("=", Length(items), Literal(needed))
            )
            yes, no = b.branch(valid)
            b.use(no)
            self.error("ValueError")
            b.use(yes)
            for index, element in enumerate(target.elts):
                if stars and index == stars[0]:
                    middle = b.alloc(ListExpr(()), "starred")
                    cursor = b.alloc(Literal(index + 1), "cursor")
                    limit = b.alloc(
                        Binary("-", Length(items), Literal(len(target.elts) - index - 1)), "limit"
                    )
                    head, done = b.node(), b.node()
                    b.jump(head)
                    b.use({head})
                    yes, no = b.branch(Not(Binary("<", limit, cursor)))
                    b.use(no)
                    b.jump(done)
                    b.use(yes)
                    self._append_raw(middle, field(items, cursor))
                    b.emit(Alloc(cursor.name, Binary("+", cursor, Literal(1))))
                    b.jump(head)
                    b.use({done})
                    self.store(element.value, rt.box(b, middle, "list"))
                else:
                    offset = Literal(index + 1)
                    if stars and index > stars[0]:
                        offset = Binary("-", Length(items), Literal(len(target.elts) - index - 1))
                    self.store(element, field(items, offset))
        else:
            self.fail(target, f"unsupported assignment target {type(target).__name__}")

    def _state(self):
        return (
            self.b,
            self.scope,
            self.exception_target,
            self.loop_targets,
            self.finalizers,
            self.active_exception,
            self.generator_state,
        )

    def _restore(self, state):
        (
            self.b,
            self.scope,
            self.exception_target,
            self.loop_targets,
            self.finalizers,
            self.active_exception,
            self.generator_state,
        ) = state

    def function(self, node, lambda_body=None):
        from .generators import contains_yield, lower_generator

        if contains_yield(node):
            return lower_generator(self, node, lambda_body=lambda_body)
        outer, parent = self.b, self.scope
        self.serial += 1
        short_name = getattr(node, "name", f"<lambda{self.serial}>")
        name = f"{parent.name}.{short_name}"
        if name in self.program.cfgs:
            name += f"@{getattr(node, 'lineno', self.serial)}:{self.serial}"
        decorators = [self.expression(d) for d in getattr(node, "decorator_list", ())]
        defaults = [self.expression(d) for d in node.args.defaults]
        kw_defaults = [
            (arg.arg, self.expression(default))
            for arg, default in zip(node.args.kwonlyargs, node.args.kw_defaults)
            if default is not None
        ]
        defaults_ref = outer.alloc(ListExpr(tuple(defaults)), "defaults")
        kw_defaults_ref = outer.alloc(DictExpr(tuple(kw_defaults)), "kwdefaults")
        state = self._state()
        body = [ast.Return(value=lambda_body)] if lambda_body is not None else node.body
        bindings = _Bindings(body, node.args)
        lexical_parent = parent.parent if parent.kind == "class" else parent
        method_class = (
            parent.class_object.name
            if parent.kind == "class" and isinstance(parent.class_object, Var)
            else None
        )
        args = (*node.args.posonlyargs, *node.args.args)
        scope = Scope(
            name,
            "function",
            parent.module,
            bindings,
            lexical_parent,
            method_class_name=method_class,
            first_parameter=args[0].arg if args else None,
        )
        self.b = Builder(self.program, name, self.module.filename)
        self.scope, self.exception_target = scope, self.b.cfg.exit
        self.loop_targets, self.finalizers, self.active_exception = [], [], None
        self.generator_state = None
        b, rt = self.b, self.runtime
        b.assign("$builtins", field(Var("$parent"), "$builtins"))
        b.assign("$global", field(Var("$parent"), "$global"))
        b.assign("$modules", field(Var("$parent"), "$modules"))
        b.emit(Env("$env"))
        b.assign("$return", rt.none)
        self.parameters(node.args, defaults_ref.name, kw_defaults_ref.name)
        self.statements(body)
        b.finish()
        self._restore(state)
        value = rt.function(outer, name)
        for decorator in reversed(decorators):
            value = self.call(decorator, (value,))
        return value

    def parameters(self, arguments, defaults_name, kw_defaults_name):
        b, rt = self.b, self.runtime
        defaults_env = Var("$parent")
        if self.scope.parent is not None and self.scope.parent.kind == "generator":
            defaults_env = field(defaults_env, "$parent")
        original = Var("$kwargs")
        nested, flat = b.branch(Binary("in", Literal("$values"), original))
        named, keys = Var(b.temp("named")), Var(b.temp("keys"))
        b.use(nested)
        b.emit(Alloc(named.name, field(original, "$values")))
        b.assign(keys, field(original, "$keys"))
        nested_tails = set(b.tails)
        b.use(flat)
        b.emit(Alloc(named.name, original))
        b.emit(Alloc(keys.name, ListExpr(())))
        b.join(nested_tails, b.tails)
        positional = (*arguments.posonlyargs, *arguments.args)
        default_start = len(positional) - len(arguments.defaults)
        for offset, argument in enumerate(positional):
            haspos, nopos = b.branch(Not(Binary("<", Length(Var("$args")), Literal(offset + 1))))
            b.use(haspos)
            if offset >= len(arguments.posonlyargs):
                duplicate, clean = b.branch(Binary("in", Literal(argument.arg), named))
                b.use(duplicate)
                self.error("TypeError")
                b.use(clean)
            b.assign(argument.arg, field(Var("$args"), offset + 1))
            postails = set(b.tails)
            b.use(nopos)
            if offset >= len(arguments.posonlyargs):
                haskw, nokw = b.branch(Binary("in", Literal(argument.arg), named))
                b.use(haskw)
                b.assign(argument.arg, field(named, argument.arg))
                b.emit(Delete(field(named, argument.arg)))
                kwtails = set(b.tails)
                b.use(nokw)
            else:
                kwtails = set()
            if offset >= default_start:
                default = field(field(defaults_env, defaults_name), offset - default_start + 1)
                b.assign(argument.arg, default)
            else:
                self.error("TypeError")
            b.join(postails, kwtails, b.tails)
        for arg, default in zip(arguments.kwonlyargs, arguments.kw_defaults):
            haskw, nokw = b.branch(Binary("in", Literal(arg.arg), named))
            b.use(haskw)
            b.assign(arg.arg, field(named, arg.arg))
            b.emit(Delete(field(named, arg.arg)))
            kwtails = set(b.tails)
            b.use(nokw)
            if default is not None:
                b.assign(arg.arg, field(field(defaults_env, kw_defaults_name), arg.arg))
            else:
                self.error("TypeError")
            b.join(kwtails, b.tails)
        if arguments.vararg:
            extra = b.alloc(ListExpr(()), "varargs")
            index = b.alloc(Literal(len(positional) + 1), "index")
            head, done = b.node(), b.node()
            b.jump(head)
            b.use({head})
            more, end = b.branch(Not(Binary("<", Length(Var("$args")), index)))
            b.use(end)
            b.jump(done)
            b.use(more)
            self._append_raw(extra, field(Var("$args"), index))
            b.emit(Alloc(index.name, Binary("+", index, Literal(1))))
            b.jump(head)
            b.use({done})
            b.assign(arguments.vararg.arg, rt.box(b, extra, "tuple"))
        else:
            good, bad = b.branch(Not(Binary("<", Literal(len(positional)), Length(Var("$args")))))
            b.use(bad)
            self.error("TypeError")
            b.use(good)
        if arguments.kwarg:
            pairs = b.alloc(ListExpr(()), "kwarg_pairs")
            index = b.alloc(Literal(1), "keyindex")
            head, done = b.node(), b.node()
            b.jump(head)
            b.use({head})
            more, end = b.branch(Not(Binary("<", Length(keys), index)))
            b.use(end)
            b.jump(done)
            b.use(more)
            keyobj = b.bind(field(keys, index), "keyobj")
            key = field(keyobj, "$value")
            remaining, consumed = b.branch(Binary("in", key, named))
            b.use(remaining)
            pair = b.alloc(NewObject(), "pair")
            b.assign(field(pair, "key"), keyobj)
            b.assign(field(pair, "value"), field(named, key))
            self._append_raw(pairs, pair)
            b.join(b.tails, consumed)
            b.emit(Alloc(index.name, Binary("+", index, Literal(1))))
            b.jump(head)
            b.use({done})
            b.assign(arguments.kwarg.arg, rt.box(b, pairs, "dict"))
        else:
            empty, extra = b.branch(Binary("=", Length(named), Literal(0)))
            b.use(extra)
            self.error("TypeError")
            b.use(empty)

    def defining_environment(self):
        """Environment containing a method's lexically created class object."""
        env = Var("$parent")
        if self.scope.kind == "generator":
            env = field(env, "$parent")
        if self.scope.parent is not None and self.scope.parent.kind == "generator":
            env = field(env, "$parent")
        return env

    def _run_finalizers(self, minimum_depth=0):
        saved = list(self.finalizers)
        for index in range(len(saved) - 1, minimum_depth - 1, -1):
            self.finalizers = saved[:index]
            if callable(saved[index]):
                saved[index]()
            else:
                self.statements(saved[index])
        self.finalizers = saved

    def statement(self, node):
        b, rt = self.b, self.runtime
        b.lineno = getattr(node, "lineno", b.lineno)
        if isinstance(node, (ast.Pass, ast.Global, ast.Nonlocal)):
            return
        if isinstance(node, ast.Expr):
            self.expression(node.value)
        elif isinstance(node, ast.Assign):
            value = self.expression(node.value)
            for target in node.targets:
                self.store(target, value)
        elif isinstance(node, ast.AnnAssign):
            if node.value is not None:
                self.store(node.target, self.expression(node.value))
        elif isinstance(node, ast.AugAssign):
            # Capture the receiver/index before RHS, and evaluate each once.
            if isinstance(node.target, ast.Name):
                ref = self.name_ref(node.target.id)
                left = self.load_name(ast.Name(id=node.target.id, ctx=ast.Load()))

                def setter(value):
                    return b.assign(ref, value)

            elif isinstance(node.target, ast.Attribute):
                obj = self.expression(node.target.value)
                left = self.get_attribute(obj, node.target.attr)

                def setter(value):
                    return rt.invoke(b, "setattr", (obj, rt.raw(b, node.target.attr), value))

            elif isinstance(node.target, ast.Subscript) and not isinstance(
                node.target.slice, ast.Slice
            ):
                obj, key = self.expression(node.target.value), self.expression(node.target.slice)
                left = self.special(obj, "__getitem__", (key,))

                def setter(value):
                    return self.special(obj, "__setitem__", (key, value))

            else:
                self.fail(node, "unsupported augmented assignment target")
            right = self.expression(node.value)
            names = {
                ast.Add: ("__iadd__", "+"),
                ast.Sub: ("__isub__", "-"),
                ast.Mult: ("__imul__", "*"),
                ast.Div: ("__itruediv__", "/"),
                ast.FloorDiv: ("__ifloordiv__", "//"),
                ast.Mod: ("__imod__", "%"),
                ast.Pow: ("__ipow__", "**"),
                ast.BitAnd: ("__iand__", "&"),
                ast.BitOr: ("__ior__", "|"),
                ast.BitXor: ("__ixor__", "^"),
                ast.LShift: ("__ilshift__", "<<"),
                ast.RShift: ("__irshift__", ">>"),
                ast.MatMult: ("__imatmul__", "@"),
            }
            methodname, symbol = names[type(node.op)]
            method = rt.lookup(b, field(left, "__class__"), methodname)
            exists, absent = b.branch(Not(Binary("=", method, rt.missing)))
            result = Var(b.temp("augmented"))
            b.use(exists)
            b.assign(
                result,
                self.call(rt.bind_method(b, method, left, field(left, "__class__")), (right,)),
            )
            good, failed = b.branch(Not(Binary("=", result, rt.not_implemented)))
            b.join(absent, failed)
            b.assign(result, rt.invoke(b, "binary", (left, right), symbol))
            self.checked()
            b.join(good, b.tails)
            setter(result)
            self.checked()
        elif isinstance(node, ast.Delete):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    b.emit(Delete(self.name_ref(target.id, store=True)))
                elif isinstance(target, ast.Attribute):
                    rt.invoke(
                        b,
                        "setattr",
                        (self.expression(target.value), rt.raw(b, target.attr)),
                        "delete",
                    )
                    self.checked()
                elif isinstance(target, ast.Subscript) and not isinstance(target.slice, ast.Slice):
                    self.special(
                        self.expression(target.value),
                        "__delitem__",
                        (self.expression(target.slice),),
                    )
                else:
                    self.fail(target, "unsupported deletion target")
        elif isinstance(node, ast.FunctionDef):
            self.store(ast.Name(id=node.name, ctx=ast.Store()), self.function(node))
        elif isinstance(node, ast.ClassDef):
            self.class_definition(node)
        elif isinstance(node, ast.Return):
            if self.scope.kind == "generator":
                from .generators import emit_generator_return

                emit_generator_return(self, node)
                return
            if self.scope.kind == "module":
                self.fail(node, "return outside function")
            result = b.bind(self.expression(node.value) if node.value else rt.none, "returned")
            self._run_finalizers()
            if b.tails:
                b.ret(result)
        elif isinstance(node, ast.If):
            yes, no = b.branch(self.truth(self.expression(node.test)))
            b.use(yes)
            self.statements(node.body)
            first = set(b.tails)
            b.use(no)
            self.statements(node.orelse)
            b.join(first, b.tails)
        elif isinstance(node, ast.While):
            head, done = b.node(), b.node()
            b.jump(head)
            b.use({head})
            yes, no = b.branch(self.truth(self.expression(node.test)))
            b.use(yes)
            self.loop_targets.append((head, done, len(self.finalizers)))
            self.statements(node.body)
            self.loop_targets.pop()
            b.jump(head)
            b.use(no)
            self.statements(node.orelse)
            b.jump(done)
            b.use({done})
        elif isinstance(node, ast.For):
            self.for_statement(node)
        elif isinstance(node, (ast.Break, ast.Continue)):
            if not self.loop_targets:
                self.fail(node, f"{type(node).__name__.lower()} outside loop")
            self._run_finalizers(self.loop_targets[-1][2])
            b.jump(self.loop_targets[-1][1 if isinstance(node, ast.Break) else 0])
        elif isinstance(node, ast.Assert):
            good, bad = b.branch(self.truth(self.expression(node.test)))
            b.use(bad)
            if node.msg is not None:
                self.expression(node.msg)
            self.error("AssertionError")
            b.use(good)
        elif isinstance(node, ast.Raise):
            if node.exc is None:
                if self.active_exception is None:
                    self.error("RuntimeError")
                    return
                exc = self.active_exception
                available, unavailable = b.branch(Not(Binary("=", exc, rt.none)))
                b.use(unavailable)
                self.error("RuntimeError")
                b.use(available)
            else:
                exc = b.bind(self.expression(node.exc), "raised")
                cls, instance = b.branch(Binary("in", Literal("$class"), exc))
                b.use(cls)
                b.assign(exc, self.call(exc))
                b.join(b.tails, instance)
                valid = rt.contains_class(b, field(exc, "__class__"), rt.builtin("BaseException"))
                yes, no = b.branch(valid)
                b.use(no)
                self.error("TypeError")
                b.use(yes)
            if node.cause is not None:
                self.expression(node.cause)
            b.assign(rt.exception, exc)
            b.jump(self.exception_target)
        elif isinstance(node, ast.Try):
            self.try_statement(node)
        elif isinstance(node, ast.With):
            self.with_statement(node)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            self.import_statement(node)
        else:
            self.fail(node, f"unsupported statement {type(node).__name__}")

    def class_definition(self, node):
        b, rt = self.b, self.runtime
        if node.keywords:
            self.fail(
                node, "custom metaclasses and class-definition keywords require a runtime model"
            )
        decorators = [self.expression(d) for d in node.decorator_list]
        bases = [self.expression(base) for base in node.bases] or [rt.builtin("object")]
        raw_bases = b.alloc(ListExpr(tuple(bases)), "bases")
        cls = rt.obj(b, "type")
        b.assign(field(cls, "$class"), rt.raw(b, True))
        b.assign(field(cls, "__name__"), rt.box(b, node.name))
        b.assign(field(cls, "__bases__"), raw_bases)
        mro = rt.invoke(b, "mro", (cls, raw_bases))
        self.checked()
        b.assign(field(cls, "__mro__"), mro)
        saved = self.scope
        self.scope = Scope(
            f"{saved.name}.{node.name}",
            "class",
            saved.module,
            _Bindings(node.body),
            saved,
            class_object=cls,
        )
        self.statements(node.body)
        self.scope = saved
        # __set_name__ is invoked by class creation, even without instantiation.
        for name in sorted(_Bindings(node.body).locals):
            present, absent = b.branch(Binary("in", Literal(name), cls))
            b.use(present)
            value = field(cls, name)
            method = rt.lookup(b, field(value, "__class__"), "__set_name__")
            exists, missing = b.branch(Not(Binary("=", method, rt.missing)))
            b.use(exists)
            self.call(
                rt.bind_method(b, method, value, field(value, "__class__")), (cls, rt.box(b, name))
            )
            b.join(b.tails, missing, absent)
        init_subclass = rt.lookup(b, cls, "__init_subclass__", after=cls)
        exists, missing = b.branch(Not(Binary("=", init_subclass, rt.missing)))
        b.use(exists)
        self.call(rt.bind_method(b, init_subclass, cls, cls))
        b.join(b.tails, missing)
        value = cls
        for decorator in reversed(decorators):
            value = self.call(decorator, (value,))
        self.store(ast.Name(id=node.name, ctx=ast.Store()), value)

    def for_statement(self, node):
        b, rt = self.b, self.runtime
        iterator = self.call(rt.builtin("iter"), (self.expression(node.iter),))
        head, done, exhausted = b.node(), b.node(), b.node()
        b.jump(head)
        b.use({head})
        saved = self.exception_target
        self.exception_target = exhausted
        value = self.call(rt.builtin("next"), (iterator,))
        self.exception_target = saved
        self.store(node.target, value)
        self.loop_targets.append((head, done, len(self.finalizers)))
        self.statements(node.body)
        self.loop_targets.pop()
        b.jump(head)
        b.use({exhausted})
        stopped = rt.contains_class(
            b, field(rt.exception, "__class__"), rt.builtin("StopIteration")
        )
        yes, no = b.branch(stopped)
        b.use(no)
        b.jump(saved)
        b.use(yes)
        b.assign(rt.exception, rt.none)
        self.statements(node.orelse)
        b.jump(done)
        b.use({done})

    def try_statement(self, node):
        b, rt = self.b, self.runtime
        outer = self.exception_target
        dispatch, final_error = b.node(), b.node()

        def run_finalbody():
            saved_target = self.exception_target
            self.exception_target = outer
            self.statements(node.finalbody)
            self.exception_target = saved_target

        self.exception_target = dispatch
        if node.finalbody:
            self.finalizers.append(run_finalbody)
        self.statements(node.body)
        self.exception_target = final_error
        self.statements(node.orelse)
        normal = set(b.tails)
        if node.finalbody:
            self.finalizers.pop()
        b.use({dispatch})
        exception = b.bind(rt.exception, "caught")
        b.assign(rt.exception, rt.none)
        handled = []
        for handler in node.handlers:
            if handler.type is None:
                matching, remaining = set(b.tails), set()
            else:
                types = handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
                match = b.alloc(Literal(False), "matches")
                for typ in types:
                    candidate = self.expression(typ)
                    contains = rt.contains_class(b, field(exception, "__class__"), candidate)
                    b.emit(Alloc(match.name, Binary("or", match, contains)))
                matching, remaining = b.branch(match)
            b.use(matching)
            b.assign(rt.exception, rt.none)
            if handler.name:
                b.assign(self.name_ref(handler.name, store=True), exception)
            active = self.active_exception
            self.active_exception = exception
            if node.finalbody:
                self.finalizers.append(run_finalbody)
            handler_error = b.node()
            self.exception_target = handler_error

            def cleanup_binding(handler_name=handler.name):
                if handler_name:
                    reference = self.name_ref(handler_name, store=True)
                    owner = reference.base if hasattr(reference, "base") else Var("$env")
                    exists, missing = b.branch(Binary("in", Literal(handler_name), owner))
                    b.use(exists)
                    b.emit(Delete(reference))
                    b.join(b.tails, missing)

            self.finalizers.append(cleanup_binding)
            self.statements(handler.body)
            self.finalizers.pop()
            if node.finalbody:
                self.finalizers.pop()
            self.active_exception = active
            cleanup_binding()
            handled.append(set(b.tails))
            b.use({handler_error})
            cleanup_binding()
            b.jump(final_error)
            self.exception_target = final_error
            b.use(remaining)
        b.assign(rt.exception, exception)
        b.jump(final_error)
        self.exception_target = outer
        if not node.finalbody:
            b.use({final_error})
            b.jump(outer)
            b.join(normal, *handled)
            return
        b.join(normal, *handled, {final_error})
        pending = b.bind(rt.exception, "pending_exception")
        b.assign(rt.exception, rt.none)
        active = self.active_exception
        self.active_exception = pending
        self.statements(node.finalbody)
        self.active_exception = active
        noexception, propagate = b.branch(Binary("=", pending, rt.none))
        b.use(propagate)
        b.assign(rt.exception, pending)
        b.jump(outer)
        b.use(noexception)

    def with_statement(self, node):
        b, rt = self.b, self.runtime
        item, *rest = node.items
        manager = self.expression(item.context_expr)
        cls = field(manager, "__class__")
        exitfn = rt.lookup(b, cls, "__exit__")
        enterfn = rt.lookup(b, cls, "__enter__")
        valid = Not(Binary("or", Binary("=", exitfn, rt.missing), Binary("=", enterfn, rt.missing)))
        good, bad = b.branch(valid)
        b.use(bad)
        self.error("TypeError")
        b.use(good)
        exitfn = rt.bind_method(b, exitfn, manager, cls)
        value = self.call(rt.bind_method(b, enterfn, manager, cls))
        outer = self.exception_target
        exceptional, done = b.node(), b.node()
        self.exception_target = exceptional

        def cleanup():
            saved_target = self.exception_target
            self.exception_target = outer
            self.call(exitfn, (rt.none, rt.none, rt.none))
            self.exception_target = saved_target

        self.finalizers.append(cleanup)
        if item.optional_vars is not None:
            self.store(item.optional_vars, value)
        if rest:
            self.with_statement(ast.With(items=rest, body=node.body))
        else:
            self.statements(node.body)
        self.finalizers.pop()
        self.exception_target = outer
        cleanup()
        b.jump(done)
        b.use({exceptional})
        exc = b.bind(rt.exception, "with_exception")
        b.assign(rt.exception, rt.none)
        suppress = self.truth(self.call(exitfn, (field(exc, "__class__"), exc, rt.none)))
        yes, no = b.branch(suppress)
        b.use(no)
        b.assign(rt.exception, exc)
        b.jump(outer)
        b.use(yes)
        b.jump(done)
        b.use({done})

    def comprehension(self, node):
        if isinstance(node, ast.GeneratorExp):
            from .generators import lower_generator_expression

            return lower_generator_expression(self, node)
        for generator in node.generators:
            if generator.is_async:
                self.fail(node, "asynchronous comprehensions are not supported")
        initial = self.expression(node.generators[0].iter)
        state = self._state()
        outer, parent = self.b, self.scope
        self.serial += 1
        name = f"{parent.name}.<comprehension{self.serial}>"
        assignments = [
            ast.Assign(targets=[g.target], value=ast.Constant(None)) for g in node.generators
        ]
        scope = Scope(name, "function", parent.module, _Bindings(assignments), parent)
        self.b = Builder(self.program, name, self.module.filename, synthetic=True)
        self.scope, self.exception_target = scope, self.b.cfg.exit
        self.loop_targets, self.finalizers, self.active_exception = [], [], None
        b, rt = self.b, self.runtime
        b.assign("$builtins", field(Var("$parent"), "$builtins"))
        b.assign("$global", field(Var("$parent"), "$global"))
        b.assign("$modules", field(Var("$parent"), "$modules"))
        b.emit(Env("$env"))
        b.assign("$return", rt.none)
        kind = (
            "dict"
            if isinstance(node, ast.DictComp)
            else "set" if isinstance(node, ast.SetComp) else "list"
        )
        result = rt.sequence(b, (), kind)

        def descend(index):
            generator = node.generators[index]
            iterable = field(Var("$args"), 1) if index == 0 else self.expression(generator.iter)
            iterator = self.call(rt.builtin("iter"), (iterable,))

            def body(value):
                self.store(generator.target, value)
                skipped = []
                for condition in generator.ifs:
                    yes, no = b.branch(self.truth(self.expression(condition)))
                    skipped.append(no)
                    b.use(yes)
                if index + 1 < len(node.generators):
                    descend(index + 1)
                elif isinstance(node, ast.DictComp):
                    self.special(
                        result,
                        "__setitem__",
                        (self.expression(node.key), self.expression(node.value)),
                    )
                else:
                    value = self.expression(node.elt)
                    self.call(
                        self.get_attribute(result, "add" if kind == "set" else "append"), (value,)
                    )
                b.join(b.tails, *skipped)

            self.iterate(iterator, body)

        descend(0)
        b.ret(result)
        b.finish()
        self._restore(state)
        value = outer.invoke(name, (initial,))
        self.checked()
        return value

    def load_module(self, name):
        b, rt = self.b, self.runtime
        if name == "builtins":
            obj = rt.obj(b, "module")
            b.assign(field(obj, "$module"), rt.raw(b, True))
            b.assign(field(obj, "$env"), Var("$builtins"))
            return obj
        parts = name.split(".")
        for length in range(1, len(parts) + 1):
            current = ".".join(parts[:length])
            if current not in self.modules:
                continue
            module = field(Var("$modules"), current)
            loaded, unloaded = b.branch(field(module, "$loaded"))
            b.use(unloaded)
            b.call(field(module, "$loader"), b.alloc(ListExpr(())), b.alloc(DictExpr(())))
            self.checked()
            b.join(loaded, b.tails)
            if length > 1:
                parent = field(Var("$modules"), ".".join(parts[: length - 1]))
                b.assign(field(field(parent, "$env"), parts[length - 1]), module)
        return field(Var("$modules"), name)

    def import_statement(self, node):
        if isinstance(node, ast.Import):
            for alias in node.names:
                module = self.load_module(alias.name)
                value = module if alias.asname else self.load_module(alias.name.split(".")[0])
                self.b.assign(
                    self.name_ref(alias.asname or alias.name.split(".")[0], store=True), value
                )
            return
        if node.module == "__future__":
            return
        names = self.module.imports.get(id(node), ())
        if not names:
            self.fail(node, "unresolved relative import")
        source = names[0]
        module = self.load_module(source)
        for alias in node.names:
            if alias.name == "*":
                if source not in self.modules:
                    self.fail(node, "star import from builtin modules is not supported")
                imported = self.modules[source]
                exported = sorted(
                    n for n in _Bindings(imported.tree.body).locals if not n.startswith("_")
                )
                for stmt in imported.tree.body:
                    if isinstance(stmt, ast.Assign) and any(
                        isinstance(t, ast.Name) and t.id == "__all__" for t in stmt.targets
                    ):
                        if not isinstance(stmt.value, (ast.List, ast.Tuple)) or not all(
                            isinstance(e, ast.Constant) and isinstance(e.value, str)
                            for e in stmt.value.elts
                        ):
                            self.fail(
                                node,
                                "star import requires a literal __all__ "
                                "or static public definitions",
                            )
                        exported = [e.value for e in stmt.value.elts]
                for name in exported:
                    self.b.assign(self.name_ref(name, store=True), self.get_attribute(module, name))
                continue
            submodule = source + "." + alias.name
            if submodule in self.modules:
                # Python prefers an already-defined package attribute, then
                # attempts a submodule. Preserve that ordering explicitly.
                b = self.b
                exists, absent = b.branch(Binary("in", Literal(alias.name), field(module, "$env")))
                value = Var(b.temp("imported"))
                b.use(exists)
                b.assign(value, field(field(module, "$env"), alias.name))
                attr_tails = set(b.tails)
                b.use(absent)
                b.assign(value, self.load_module(submodule))
                b.join(attr_tails, b.tails)
            else:
                value = self.get_attribute(module, alias.name)
            self.b.assign(self.name_ref(alias.asname or alias.name, store=True), value)


def _source(path):
    with tokenize.open(path) as handle:
        return handle.read()


def _module_name(path, root):
    relative = path.relative_to(root).with_suffix("")
    parts = list(relative.parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts) or root.name


def _default_root(path):
    root = path.parent
    while (root / "__init__.py").is_file():
        root = root.parent
    return root


def _discover(source, name, filename, root):
    """Read only local .py modules; never use importlib or execute import hooks."""
    modules = {}

    def locate(module):
        if root is None:
            return None
        path = root.joinpath(*module.split("."))
        for candidate in (path.with_suffix(".py"), path / "__init__.py"):
            if candidate.is_file() and candidate.resolve().is_relative_to(root):
                return candidate
        if path.is_dir() and path.resolve().is_relative_to(root):
            return path / "__init__.py"  # empty namespace package
        return None

    def load(text, module_name, file):
        if module_name in modules:
            return
        try:
            tree = ast.parse(text, filename=file)
        except SyntaxError as exc:
            raise LoweringError(exc.msg, file, exc.lineno) from exc
        package = (
            module_name if Path(file).name == "__init__.py" else module_name.rpartition(".")[0]
        )
        module = Module(module_name, tree, file, package)
        modules[module_name] = module

        def ensure(target, node, optional=False):
            if target in {"builtins", "__future__"} or target in modules:
                return True
            path = locate(target)
            if path is None:
                if optional:
                    return False
                raise LoweringError(
                    f"import {target!r} has no local source or MIR runtime model", file, node.lineno
                )
            # Package initializers execute before imported children.
            components = target.split(".")
            for index in range(1, len(components)):
                ensure(".".join(components[:index]), node)
            load(_source(path) if path.is_file() else "", target, str(path))
            return True

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    ensure(alias.name, node)
                module.imports[id(node)] = tuple(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                if node.module == "__future__":
                    continue
                if node.level:
                    parts = package.split(".") if package else []
                    if len(parts) < node.level:
                        raise LoweringError(
                            "relative import escapes the package", file, node.lineno
                        )
                    prefix = parts[: len(parts) - node.level + 1]
                    target = ".".join(prefix + ([node.module] if node.module else []))
                else:
                    target = node.module or ""
                ensure(target, node)
                submodules = []
                for alias in node.names:
                    submodule = target + "." + alias.name
                    if alias.name != "*" and ensure(submodule, node, optional=True):
                        submodules.append(submodule)
                module.imports[id(node)] = (target, *submodules)

    load(source, name, filename)
    return modules


def lower_source(
    source: str,
    module_name: str = "__main__",
    filename: str = "<string>",
    *,
    project_root: str | None = None,
) -> Program:
    """Lower authoritative source text; filename supplies import context only.

    Local imports are discovered when a real filename/project root is supplied.
    The file named by ``filename`` is never substituted for ``source``.
    """
    path = Path(filename).resolve() if filename != "<string>" else None
    root = Path(project_root).resolve() if project_root else _default_root(path) if path else None
    modules = _discover(source, module_name, filename, root)
    return PythonToMIR(modules, module_name).compile()


def lower_file(path: str | Path, project_root: str | Path | None = None) -> Program:
    """Lower an entry file and its statically discoverable local imports."""
    entry = Path(path).resolve()
    if not entry.is_file():
        raise FileNotFoundError(entry)
    root = Path(project_root).resolve() if project_root else _default_root(entry)
    if not entry.is_relative_to(root):
        raise LoweringError("entry file is outside project_root", str(entry))
    name = _module_name(entry, root)
    return lower_source(_source(entry), name, str(entry), project_root=str(root))


__all__ = ["LoweringError", "PythonToMIR", "lower_source", "lower_file"]
