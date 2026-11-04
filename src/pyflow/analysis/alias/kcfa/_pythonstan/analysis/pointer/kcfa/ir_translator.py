"""IR to constraint translation.

This module translates IR events to pointer constraints for analysis.
"""

from typing import List, TYPE_CHECKING, Optional, Tuple, Dict, Set, Union
import logging, ast
import copy
from collections import defaultdict
from dataclasses import replace

from .constraints import *
from .config import Config
from .context import CallSite
from .variable import Variable, VariableFactory, VariableKind
from .heap_model import dict_keys, elem, attr, key
from .builtin_types import BUILTIN_EXCEPTION_NAMES
from pyflow.analysis.alias.kcfa._pythonstan.ir.ir_statements import *
from .object import AllocSite, AllocKind
from .stable_key import stable_token

logger = logging.getLogger(__name__)

__all__ = ["IRTranslator"]

BINOP_TABLE = {
    ast.Add: "__add__",  # +
    ast.Sub: "__sub__",  # -
    ast.Mult: "__mul__",  # *
    ast.Div: "__truediv__",  # /
    ast.FloorDiv: "__floordiv__",  # //
    ast.Mod: "__mod__",  # %
    ast.Pow: "__pow__",  # **
    ast.LShift: "__lshift__",  # <<
    ast.RShift: "__rshift__",  # >>
    ast.BitOr: "__or__",  # |
    ast.BitXor: "__xor__",  # ^
    ast.BitAnd: "__and__",  # &
    ast.MatMult: "__matmul__",  # @ (矩阵乘法)
    ast.Eq: "__eq__",  # ==
    ast.NotEq: "__ne__",  # !=
    ast.Lt: "__lt__",  # <
    ast.LtE: "__le__",  # <=
    ast.Gt: "__gt__",  # >
    ast.GtE: "__ge__",  # >=
    ast.In: "__contains__",  # in
}

UNARYOP_TABLE = {
    ast.UAdd: "__pos__",  # +x
    ast.USub: "__neg__",  # -x
    ast.Not: "__bool__",  # not x
    ast.Invert: "__invert__",  # ~x
}


class IRTranslator:
    """Translates IR to pointer constraints."""

    def __init__(self, config: "Config"):
        self.config = config
        self._var_factory = VariableFactory()
        self._current_scope: Optional["IRScope"] = None
        self._current_module: Optional["IRModule"] = None
        self._scope_constraints: Dict[IRScope, List["Constraint"]] = {}
        self._import_depth = 0  # Track import depth for recursion limit
        self._local_vars: Dict[IRScope, Set[str]] = defaultdict(set)
        self._class_used_variables: Dict[IRClass, List["Variable"]] = {}
        self._class_base_variables: Dict[IRClass, Tuple["Variable", ...]] = {}
        self._class_metaclass_variables: Dict[IRClass, Tuple["Variable", ...]] = {}
        self._class_keyword_variables: Dict[
            IRClass, Tuple[Tuple[Optional[str], "Variable"], ...]
        ] = {}
        self._enum_value_variables: Dict[Tuple[IRClass, str], str] = {}
        self._import_aliases: Dict[str, str] = {}

        from pyflow.analysis.alias.kcfa._pythonstan.world import World

        self.world = World()
        if not hasattr(self.world, "scope_manager"):
            self.world.setup()
        self.scope_manager = self.world.scope_manager
        self.namespace_manager = self.world.namespace_manager

    def translate_function(self, func: IRFunc) -> List["Constraint"]:
        constraints = []

        # avoid infinite recursion
        if func in self._scope_constraints:
            return self._scope_constraints[func]

        self._current_scope = func
        locals_set = self._local_vars.setdefault(func, set())
        locals_set.update(func.get_arg_names())
        stmts = self.scope_manager.get_ir(func, "ir")
        if stmts is not None:
            binders = set()
            for stmt in stmts:
                binders.update(stmt.get_stores())
            binders.difference_update(func.get_global_vars())
            binders.difference_update(func.get_nonlocal_vars())
            locals_set.update(name for name in binders if name and name.isidentifier())
            self._translate_statements(list(stmts), constraints)

        self._scope_constraints[func] = constraints
        return constraints

    def translate_module(
        self, module: IRModule, import_stmt: Optional["IRImport"] = None
    ) -> List["Constraint"]:
        assert isinstance(module, IRModule), f"Module is not an IRModule: {type(module)}"

        # avoid infinite recursion
        if module in self._scope_constraints:
            return self._scope_constraints[module]

        constraints = []
        ir = self.scope_manager.get_ir(module, "ir")

        if ir is not None:
            self._current_scope = module
            self._current_module = module
            self._translate_statements(list(ir), constraints)

            self._scope_constraints[module] = constraints

        return constraints

    _ENUM_BASE_NAMES = {"Enum", "IntEnum", "StrEnum", "Flag", "IntFlag"}

    def _class_has_enum_base(self, cls_stmt: IRClass) -> bool:
        """Recognize ``class C(Enum)`` even when the base is a temporary."""
        module = self._enclosing_module()
        module_ir = self.scope_manager.get_ir(module, "ir") if module is not None else ()
        loads = {}
        for statement in module_ir or ():
            if isinstance(statement, IRLoadAttr):
                loads[statement.get_lval().id] = statement.get_attr()
        for base in cls_stmt.get_bases():
            name = base.id if isinstance(base, ast.Name) else getattr(base, "attr", None)
            if name in self._ENUM_BASE_NAMES:
                return True
            if name in loads and loads[name] in self._ENUM_BASE_NAMES:
                return True
        return False

    @staticmethod
    def _may_raise_implicitly(stmt: "IRStatement") -> bool:
        """Whether the operation can raise without an explicit ``raise``."""
        if isinstance(
            stmt,
            (
                IRCall,
                IRImport,
                IRDel,
                IRLoadAttr,
                IRStoreAttr,
                IRLoadSubscr,
                IRStoreSubscr,
                IRYield,
                IRAwait,
                IRRaise,
                IRFunc,
                IRClass,
            ),
        ):
            return True
        if isinstance(stmt, IRAssign):
            return isinstance(
                stmt.get_rval(),
                (ast.Attribute, ast.Subscript, ast.BinOp, ast.UnaryOp, ast.Call, ast.Await),
            )
        return False

    def _translate_statements(
        self, statements: List["IRStatement"], constraints: List["Constraint"]
    ) -> None:
        """Translate statements and connect try bodies to their handler bindings."""
        positions = {
            stmt: index for index, stmt in enumerate(statements) if isinstance(stmt, Label)
        }
        handlers = [stmt for stmt in statements if isinstance(stmt, IRCatchException)]

        for stmt in statements:
            constraints.extend(self._process_stmt(stmt))

        caught = self._make_variable("$caught_exception")
        raised = self._make_variable("$raised_exception")
        for handler in handlers:
            start = positions.get(handler.from_label)
            end = positions.get(handler.to_label)
            if start is None or end is None or end <= start:
                continue
            body = statements[start + 1 : end]
            for stmt in body:
                if isinstance(stmt, IRRaise):
                    constraints.append(CopyConstraint(source=raised, target=caught))
            implicit_operations = [stmt for stmt in body if self._may_raise_implicitly(stmt)]
            for stmt in implicit_operations:
                constraints.append(
                    AllocConstraint(
                        target=caught,
                        alloc_site=AllocSite.from_ir_node(stmt, AllocKind.UNKNOWN),
                    )
                )
            if implicit_operations:
                constraints.append(
                    SemanticGapConstraint(
                        target=caught,
                        kind="implicit_exceptions_unmodeled",
                        message="implicit exception values are not modeled for this handler",
                    )
                )

    def translate_class(self, cls_stmt: IRClass) -> Tuple[Variable, List["Constraint"]]:
        """Translate class definition: allocate class object and bind methods."""
        assert isinstance(cls_stmt, IRClass), f"Class is not an IRClass: {type(cls_stmt)}"

        if cls_stmt in self._scope_constraints:
            return self._scope_constraints[cls_stmt]

        constraints = []
        old_used_variables = getattr(self, "used_variables", [])
        self.used_variables = []
        irs = self.scope_manager.get_ir(cls_stmt, "ir")

        if irs is not None:
            old_scope = self._current_scope
            self._current_scope = cls_stmt
            is_enum = self._class_has_enum_base(cls_stmt)
            class_statements = []
            for stmt in irs:
                if is_enum and isinstance(stmt, (IRCopy, IRAssign)):
                    lval = stmt.get_lval()
                    member_name = getattr(lval, "id", None)
                    if (
                        member_name
                        and member_name.isidentifier()
                        and not member_name.startswith("_")
                    ):
                        # Enum members are created by the solver's enum
                        # model; keeping the raw class-body value in the class
                        # namespace makes ``E.A`` also point to ``1``.
                        # Translate the value into a synthetic variable so the
                        # enum model can still pass it to __init__/__new__.
                        synthetic = f"$enum_value@{stable_token(cls_stmt)}:{member_name}"
                        original = stmt.get_ast()
                        renamed = ast.Assign(
                            targets=[ast.Name(id=synthetic, ctx=ast.Store())],
                            value=original.value,
                        )
                        class_statements.append(
                            IRAssign(renamed) if isinstance(stmt, IRAssign) else IRCopy(renamed)
                        )
                        self._enum_value_variables[(cls_stmt, member_name)] = synthetic
                        continue
                class_statements.append(stmt)
            self._translate_statements(class_statements, constraints)
            self._current_scope = old_scope

            self._class_used_variables[cls_stmt] = list(self.used_variables)
            self.used_variables = old_used_variables
            self._scope_constraints[cls_stmt] = constraints

        return constraints

    def get_enum_value_variable(self, cls_stmt: IRClass, member_name: str) -> Optional[str]:
        return self._enum_value_variables.get((cls_stmt, member_name))

    def get_class_used_variables(self, cls_stmt: IRClass) -> List["Variable"]:
        return self._class_used_variables.get(cls_stmt, [])

    def get_class_base_variables(self, cls_stmt: IRClass) -> Tuple["Variable", ...]:
        return self._class_base_variables.get(cls_stmt, ())

    def get_class_metaclass_variables(self, cls_stmt: IRClass) -> Tuple["Variable", ...]:
        return self._class_metaclass_variables.get(cls_stmt, ())

    def get_class_keyword_variables(
        self, cls_stmt: IRClass
    ) -> Tuple[Tuple[Optional[str], "Variable"], ...]:
        return self._class_keyword_variables.get(cls_stmt, ())

    def _make_variable(self, name: str) -> "Variable":
        if self._current_scope is None:
            raise RuntimeError("No active scope for variable creation")

        # Check for temporary variables first (applies to all scopes)
        if name.startswith("$"):
            kind = VariableKind.TEMPORARY
        elif isinstance(self._current_scope, IRModule):
            kind = VariableKind.GLOBAL
        elif isinstance(self._current_scope, IRFunc):
            locals_in_scope = self._local_vars.get(self._current_scope, set())
            if name in self._current_scope.get_nonlocal_vars():
                kind = VariableKind.NONLOCAL
            elif name in self._current_scope.get_global_vars():
                kind = VariableKind.GLOBAL
            elif name in locals_in_scope or name in self._current_scope.arg_names:
                kind = VariableKind.LOCAL
            else:
                enclosing_kind = self._resolve_enclosing_variable_kind(name)
                if enclosing_kind is not None:
                    kind = enclosing_kind
                elif name in self._current_scope.get_cell_vars():
                    kind = VariableKind.CELL
                else:
                    # Treat unresolved names as globals (module-level)
                    kind = VariableKind.GLOBAL
        elif isinstance(self._current_scope, IRClass):
            locals_in_scope = self._local_vars.get(self._current_scope, set())
            if name in locals_in_scope:
                kind = VariableKind.LOCAL
            else:
                enclosing_kind = self._resolve_enclosing_variable_kind(name)
                if enclosing_kind is not None:
                    kind = enclosing_kind
                else:
                    kind = VariableKind.GLOBAL
        elif name in self._current_scope.get_nonlocal_vars():
            kind = VariableKind.NONLOCAL
        elif name in self._current_scope.get_global_vars():
            kind = VariableKind.GLOBAL
        else:
            kind = VariableKind.LOCAL

        """
        if name.startswith('$'):
            kind = VariableKind.TEMPORARY
        elif name in self._current_scope.get_nonlocal_vars():
            kind = VariableKind.NONLOCAL
        elif name in self._current_scope.get_cell_vars():
            kind = VariableKind.CELL
        elif name in self._current_scope.get_global_vars():
            kind = VariableKind.GLOBAL
        else:
            kind = VariableKind.LOCAL
        """

        return self._var_factory.make_variable(name=name, kind=kind)

    def _register_local_var(self, name_or_var: Optional[Union[str, "Variable"]]) -> None:
        if not name_or_var:
            return
        if not isinstance(self._current_scope, (IRFunc, IRClass)):
            return
        if isinstance(name_or_var, str):
            name = name_or_var
            is_temporary = not name.isidentifier()
        else:
            name = name_or_var.name
            is_temporary = name_or_var.is_temporary
        if not name:
            return
        if is_temporary:
            return
        locals_set = self._local_vars.setdefault(self._current_scope, set())
        locals_set.add(name)

    def _scope_binds_name(self, name: str) -> bool:
        scope = self._current_scope
        if isinstance(scope, IRFunc):
            if (
                name in scope.arg_names
                or name in scope.get_global_vars()
                or name in scope.get_nonlocal_vars()
            ):
                return True
            return name in self._local_vars.get(scope, set())
        if isinstance(scope, IRClass) and name in self._local_vars.get(scope, set()):
            return True
        if scope is not None and hasattr(self.scope_manager, "scope_ir"):
            return any(
                name in (stmt.get_stores() or ())
                for stmt in self.scope_manager.get_ir(scope, "ir") or ()
            )
        return False

    def _translate_truthiness(self, value: "Variable", site: "IRStatement") -> List["Constraint"]:
        """Use builtin bool dispatch to model __bool__/__len__ on user objects."""
        if self._scope_binds_name("bool"):
            return [
                SemanticGapConstraint(
                    kind="shadowed_truth_builtin",
                    message="truth protocol could not be resolved because bool is shadowed",
                )
            ]
        call_site = CallSite(statement=site, scope_name=self._get_current_scope_label())
        return [
            CallConstraint(
                callee=self._make_variable("bool"),
                args=(value,),
                kwargs=(),
                target=None,
                call_site=call_site,
            )
        ]

    def _process_stmt(self, stmt: IRStatement) -> List["Constraint"]:
        ret = []

        if isinstance(stmt, IRCopy):
            ret = self._translate_copy(stmt)
        elif isinstance(stmt, IRAssign):
            ret = self._translate_assign(stmt)
        elif isinstance(stmt, IRLoadAttr):
            ret = self._translate_load_attr(stmt)
        elif isinstance(stmt, IRStoreAttr):
            ret = self._translate_store_attr(stmt)
        elif isinstance(stmt, IRCall):
            ret = self._translate_call(stmt)
        elif isinstance(stmt, IRReturn):
            ret = self._translate_return(stmt)
        elif isinstance(stmt, IRRaise):
            ret = self._translate_raise(stmt)
        elif isinstance(stmt, (JumpIfTrue, JumpIfFalse)):
            test = stmt.test
            while isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
                test = test.operand
            if isinstance(test, ast.Name):
                ret.extend(self._translate_truthiness(self._make_variable(test.id), stmt))
            else:
                ret.append(
                    SemanticGapConstraint(
                        kind="truthiness_test_unmodeled",
                        message=f"branch truthiness test was not modeled: {ast.unparse(stmt.test)}",
                    )
                )
        elif isinstance(stmt, IRDel):
            ret = self._translate_delete(stmt)
        elif isinstance(stmt, IRLoadSubscr):
            ret = self._translate_load_subscr(stmt)
        elif isinstance(stmt, IRStoreSubscr):
            ret = self._translate_store_subscr(stmt)
        elif isinstance(stmt, IRFunc):
            _, ret = self._translate_function_def(stmt)
        elif isinstance(stmt, IRClass):
            _, ret = self._translate_class_def(stmt)
        elif isinstance(stmt, IRImport):
            ret = self._translate_import(stmt)
        elif isinstance(stmt, IRYield):
            ret = self._translate_yield(stmt)
        elif isinstance(stmt, IRAwait):
            ret = self._translate_await(stmt)

        for c in ret:
            assert isinstance(
                c, Constraint
            ), f"Constraint is not a constraint: {type(c)}, stmt: {stmt}"

        # Calls and descriptor-aware attribute operations already retain a
        # CallSite.  The simpler Andersen constraints historically discarded
        # their originating IR instruction, which made precise security
        # diagnostics impossible.  Attach it centrally so constraints created
        # by helpers and protocol lowering receive the same provenance.
        ret = [
            replace(c, site=stmt) if hasattr(c, "site") and getattr(c, "site") is None else c
            for c in ret
        ]

        return ret

    def _translate_delete(self, stmt: IRDel) -> List["Constraint"]:
        """Lower attribute deletion through Python's descriptor protocol."""
        target = stmt.value
        if isinstance(target, ast.Name):
            # Inclusion-based local points-to sets cannot retract prior
            # bindings.  Retaining them is the sound flow-insensitive result.
            return []
        if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
            return [
                AttrDeleteConstraint(
                    base=self._make_variable(target.value.id),
                    attr=target.attr,
                    call_site=CallSite(
                        statement=stmt,
                        scope_name=self._get_current_scope_label(),
                    ),
                )
            ]
        if isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name):
            container_var = self._make_variable(target.value.id)
            index_expr = target.slice
            constraints = []
            if hasattr(index_expr, "id"):
                index_var = self._make_variable(index_expr.id)
            else:
                index_name = f"$index_{stable_token(stmt)}"
                index_var = self._make_variable(index_name)
                if isinstance(index_expr, ast.Constant):
                    const_assign = IRAssign(
                        ast.Assign(
                            targets=[ast.Name(id=index_name, ctx=ast.Store())],
                            value=index_expr,
                        )
                    )
                    const_alloc = AllocSite.from_ir_node(const_assign, AllocKind.CONSTANT)
                    constraints.append(AllocConstraint(target=index_var, alloc_site=const_alloc))
            delitem_method_var = self._make_variable(
                f"$optional_callee@delitem:{stable_token(stmt)}"
            )
            call_site = CallSite(statement=stmt, scope_name=self._get_current_scope_label())
            constraints.append(
                AttrReadConstraint(
                    base=container_var,
                    attr="__delitem__",
                    target=delitem_method_var,
                    call_site=call_site,
                )
            )
            constraints.append(
                CallConstraint(
                    callee=delitem_method_var,
                    args=(index_var,),
                    kwargs=(),
                    target=None,
                    call_site=call_site,
                )
            )
            return constraints
        return []

    def _translate_copy(self, stmt: IRCopy) -> List["Constraint"]:
        """Translate IRCopy: target = source"""
        constraints = []

        lval = stmt.get_lval().id
        rval = stmt.get_rval().id
        self._register_local_var(lval)
        target_var = self._make_variable(lval)
        source_var = self._make_variable(rval)
        constraints.append(CopyConstraint(source=source_var, target=target_var))

        # for fields of class, we need to store the value to the class
        if (
            isinstance(self._current_scope, IRClass) and not target_var.is_temporary
        ):  # only store the field to the class if it is not a temporary variable
            self.used_variables.append(target_var)

        return constraints

    def _translate_yield(self, stmt: IRYield) -> List["Constraint"]:
        """Translate IRYield: [target =] yield value.

        Yields store values to the generator object's elem() field, enabling
        iteration via next()/for-loops. If a target is present (target = yield value),
        the sent value flows into the target from the generator's $sent field.

        Design:
        - Yielded values -> generator.$elem via StoreConstraint
        - Sent values -> target via LoadConstraint from generator.$sent (future)
        - Generator object tracked via special $generator variable in scope
        """
        constraints = []

        # Get or create the generator variable for this scope
        generator_var = self._make_variable("$generator")

        # If there's a value being yielded, store it to generator.elem()
        if stmt.value is not None:
            value_var = self._make_variable(stmt.value.id)
            constraints.append(StoreConstraint(base=generator_var, field=elem(), source=value_var))

        # If there's a target (target = yield value), it receives sent values
        # For now, we model send() conservatively by loading from a $sent field
        if stmt.target is not None and isinstance(stmt.target, ast.Name):
            target_name = stmt.target.id
            self._register_local_var(target_name)
            target_var = self._make_variable(target_name)
            # Load from generator.$sent field (populated by generator.send())
            constraints.append(
                LoadConstraint(base=generator_var, field=attr("$sent"), target=target_var)
            )

        constraints.append(
            YieldConstraint(
                value=(
                    self._make_variable(stmt.value.id) if isinstance(stmt.value, ast.Name) else None
                ),
                target=(
                    self._make_variable(stmt.target.id)
                    if isinstance(stmt.target, ast.Name)
                    else None
                ),
                generator_var=generator_var,
            )
        )

        return constraints

    def _translate_await(self, stmt: IRAwait) -> List["Constraint"]:
        """Translate IRAwait: [target =] await value.

        Awaiting loads the result from the awaitable's $await_result field.
        The async function's return statement stores to this field.

        Design:
        - await coro -> Load coro.$await_result into target
        - For soundness, also copy the awaitable directly (handles non-coroutine awaitables)
        """
        constraints = []

        # Get the awaitable variable
        awaitable_expr = stmt.get_value()
        if not isinstance(awaitable_expr, ast.Name):
            return constraints

        awaitable_var = self._make_variable(awaitable_expr.id)

        target = stmt.get_target()
        target_var = None
        if target is not None and isinstance(target, ast.Name):
            target_name = target.id
            self._register_local_var(target_name)
            target_var = self._make_variable(target_name)
        constraints.append(AwaitConstraint(awaitable=awaitable_var, target=target_var, site=stmt))

        return constraints

    def _translate_assign(self, stmt: IRAssign) -> List["Constraint"]:
        """Translate IRAssign: may allocate objects"""
        constraints = []
        lval = stmt.get_lval()
        rval = stmt.get_rval()

        self._register_local_var(lval.id)
        target_var = self._make_variable(lval.id)

        if isinstance(rval, ast.List):
            alloc_site = AllocSite.from_ir_node(stmt, AllocKind.LIST)
            constraints.append(AllocConstraint(target=target_var, alloc_site=alloc_site))
            precise_positions = self.config.index_sensitive
            if hasattr(rval, "elts"):
                for i, elt_expr in enumerate(rval.elts):
                    if isinstance(elt_expr, ast.Name):
                        elem_var = self._make_variable(elt_expr.id)
                        if self.config.index_sensitive:
                            # Store at specific position field
                            constraints.append(
                                StoreConstraint(base=target_var, field=key(i), source=elem_var)
                            )
                        # Also store at generic elem() for soundness
                        constraints.append(
                            StoreConstraint(base=target_var, field=elem(), source=elem_var)
                        )
                    elif isinstance(elt_expr, ast.Starred) and isinstance(elt_expr.value, ast.Name):
                        # ``[*source]`` contributes every element of ``source``
                        # at a statically unknown position.
                        precise_positions = False
                        source_var = self._make_variable(elt_expr.value.id)
                        elem_var = self._make_variable(f"$star_elem@{stable_token(stmt)}_{i}")
                        constraints.append(
                            LoadConstraint(base=source_var, field=elem(), target=elem_var)
                        )
                        constraints.append(
                            StoreConstraint(base=target_var, field=elem(), source=elem_var)
                        )
                    else:
                        precise_positions = False
        elif isinstance(rval, ast.Name):
            # ``@caught_except`` is an IR-only name assigned by the exception
            # lowering pass.  Map it to the per-scope exception flow variable
            # populated by ``_translate_raise`` rather than treating it as an
            # unresolved module global.
            source_var = self._make_variable(
                "$caught_exception" if rval.id == "@caught_except" else rval.id
            )
            constraints.append(CopyConstraint(source=source_var, target=target_var))

        elif isinstance(rval, ast.BinOp):
            lvar = self._make_variable(rval.left.id)
            rvar = self._make_variable(rval.right.id)
            target = self._make_variable(lval.id)
            constraints.extend(self._translate_binary_op(lvar, rvar, target, rval.op))

        elif isinstance(rval, ast.UnaryOp):
            operand = self._make_variable(rval.operand.id)
            target = self._make_variable(lval.id)
            constraints.extend(self._translate_unary_op(operand, target, rval.op, stmt))

        elif (
            isinstance(rval, ast.Compare)
            and len(rval.ops) == 1
            and isinstance(rval.left, ast.Name)
            and isinstance(rval.comparators[0], ast.Name)
        ):
            # Comparisons can return arbitrary user objects through rich
            # comparison methods, so retain both the conservative boolean
            # fallback and any result produced by the operand's dunder.
            constraints.append(
                AllocConstraint(
                    target=target_var,
                    alloc_site=AllocSite.from_ir_node(stmt, AllocKind.UNKNOWN),
                )
            )
            left = self._make_variable(rval.left.id)
            right = self._make_variable(rval.comparators[0].id)
            if isinstance(rval.ops[0], (ast.In, ast.NotIn)):
                # Python looks up ``__contains__`` on the container (right
                # operand), passing the searched value as its argument.
                left, right = right, left
            constraints.extend(
                self._translate_binary_op(
                    left,
                    right,
                    target_var,
                    rval.ops[0],
                )
            )

        elif isinstance(rval, ast.Dict):
            alloc_site = AllocSite.from_ir_node(stmt, AllocKind.DICT)
            constraints.append(AllocConstraint(target=target_var, alloc_site=alloc_site))
            precise_keys = self.config.index_sensitive
            if hasattr(rval, "keys") and hasattr(rval, "values"):
                for i, (key_expr, val_expr) in enumerate(zip(rval.keys, rval.values)):
                    if key_expr is None:
                        precise_keys = False
                        # ``{**mapping}``: copy the source mapping's values (and
                        # keys), never the mapping object itself.
                        if isinstance(val_expr, ast.Name):
                            source_var = self._make_variable(val_expr.id)
                            elem_var = self._make_variable(
                                f"$dict_merge_elem@{stable_token(stmt)}_{i}"
                            )
                            constraints.append(
                                LoadConstraint(base=source_var, field=elem(), target=elem_var)
                            )
                            constraints.append(
                                StoreConstraint(base=target_var, field=elem(), source=elem_var)
                            )
                            keys_var = self._make_variable(
                                f"$dict_merge_keys@{stable_token(stmt)}_{i}"
                            )
                            constraints.append(
                                LoadConstraint(base=source_var, field=dict_keys(), target=keys_var)
                            )
                            constraints.append(
                                StoreConstraint(base=target_var, field=dict_keys(), source=keys_var)
                            )
                        continue
                    if isinstance(val_expr, ast.Name):
                        val_var = self._make_variable(val_expr.id)
                        # Handle both constant keys and name keys (from TAC transformation)
                        if isinstance(key_expr, ast.Constant) and self.config.index_sensitive:
                            # Direct constant key
                            field = key(key_expr.value)
                            constraints.append(
                                StoreConstraint(base=target_var, field=field, source=val_var)
                            )
                            # Keep the key object itself for keys()/items().
                            key_name = f"$dict_key_{stable_token(stmt)}_{i}"
                            key_var = self._make_variable(key_name)
                            key_assign = IRAssign(
                                ast.Assign(
                                    targets=[ast.Name(id=key_name, ctx=ast.Store())],
                                    value=key_expr,
                                )
                            )
                            constraints.append(
                                AllocConstraint(
                                    target=key_var,
                                    alloc_site=AllocSite.from_ir_node(
                                        key_assign, AllocKind.CONSTANT
                                    ),
                                )
                            )
                            constraints.append(
                                StoreConstraint(base=target_var, field=dict_keys(), source=key_var)
                            )
                        elif isinstance(key_expr, ast.Name) and self.config.index_sensitive:
                            # Key is a name (e.g., from TAC: $const_1 = "a"; d = {$const_1: v})
                            # Use StoreSubscrConstraint for dynamic resolution
                            key_var = self._make_variable(key_expr.id)
                            constraints.append(
                                StoreSubscrConstraint(
                                    base=target_var, index=key_var, source=val_var
                                )
                            )
                        # Always add elem() constraint for soundness
                        constraints.append(
                            StoreConstraint(base=target_var, field=elem(), source=val_var)
                        )
                    else:
                        precise_keys = False
        # Tuple uses position-based fields for precise tracking
        elif isinstance(rval, ast.Tuple):
            alloc_site = AllocSite.from_ir_node(stmt, AllocKind.TUPLE)
            constraints.append(AllocConstraint(target=target_var, alloc_site=alloc_site))
            precise_positions = self.config.index_sensitive
            if hasattr(rval, "elts"):
                for i, elt_expr in enumerate(rval.elts):
                    if isinstance(elt_expr, ast.Name):
                        elem_var = self._make_variable(elt_expr.id)
                        if self.config.index_sensitive:
                            # Store at specific position field
                            constraints.append(
                                StoreConstraint(base=target_var, field=key(i), source=elem_var)
                            )
                        # Also store at generic elem() for soundness
                        constraints.append(
                            StoreConstraint(base=target_var, field=elem(), source=elem_var)
                        )
                    elif isinstance(elt_expr, ast.Starred) and isinstance(elt_expr.value, ast.Name):
                        precise_positions = False
                        source_var = self._make_variable(elt_expr.value.id)
                        elem_var = self._make_variable(f"$star_elem@{stable_token(stmt)}_{i}")
                        constraints.append(
                            LoadConstraint(base=source_var, field=elem(), target=elem_var)
                        )
                        constraints.append(
                            StoreConstraint(base=target_var, field=elem(), source=elem_var)
                        )
                    else:
                        precise_positions = False
        elif isinstance(rval, ast.Set):
            alloc_site = AllocSite.from_ir_node(stmt, AllocKind.SET)
            constraints.append(AllocConstraint(target=target_var, alloc_site=alloc_site))
            if hasattr(rval, "elts"):
                for i, elt_expr in enumerate(rval.elts):
                    if isinstance(elt_expr, ast.Name):
                        elem_var = self._make_variable(elt_expr.id)
                        constraints.append(
                            StoreConstraint(base=target_var, field=elem(), source=elem_var)
                        )
                    elif isinstance(elt_expr, ast.Starred) and isinstance(elt_expr.value, ast.Name):
                        source_var = self._make_variable(elt_expr.value.id)
                        elem_var = self._make_variable(f"$star_elem@{stable_token(stmt)}_{i}")
                        constraints.append(
                            LoadConstraint(base=source_var, field=elem(), target=elem_var)
                        )
                        constraints.append(
                            StoreConstraint(base=target_var, field=elem(), source=elem_var)
                        )

        elif isinstance(rval, ast.Constant):
            alloc_site = AllocSite.from_ir_node(stmt, AllocKind.CONSTANT)
            constraints.append(AllocConstraint(target=target_var, alloc_site=alloc_site))

        else:
            alloc_site = AllocSite.from_ir_node(stmt, AllocKind.UNKNOWN)
            constraints.append(AllocConstraint(target=target_var, alloc_site=alloc_site))

        # for fields of class, we need to store the value to the class
        if (
            isinstance(self._current_scope, IRClass) and not target_var.is_temporary
        ):  # only store the field to the class if it is not a temporary variable
            self.used_variables.append(target_var)

        return constraints

    def _translate_load_attr(self, stmt: IRLoadAttr) -> List["Constraint"]:
        """Translate IRLoadAttr: target = base.attr"""
        lval = stmt.get_lval().id
        obj_name = stmt.get_obj().id
        attr_name = stmt.get_attr()

        self._register_local_var(lval)
        base_var = self._make_variable(obj_name)
        target_var = self._make_variable(lval)
        attr_value = attr_name if attr_name else "<unknown>"
        call_site = CallSite(statement=stmt, scope_name=self._get_current_scope_label())

        if (
            isinstance(self._current_scope, IRClass) and not target_var.is_temporary
        ):  # only store the field to the class if it is not a temporary variable
            self.used_variables.append(target_var)

        return [
            AttrReadConstraint(
                base=base_var, attr=attr_value, target=target_var, call_site=call_site
            )
        ]

    def _translate_store_attr(self, stmt: IRStoreAttr) -> List["Constraint"]:
        """Translate IRStoreAttr: base.attr = source"""
        obj_name = stmt.get_obj().id
        attr_name = stmt.get_attr()
        value_name = stmt.get_rval().id

        base_var = self._make_variable(obj_name)
        source_var = self._make_variable(value_name)
        attr_value = attr_name if attr_name else "<unknown>"
        call_site = CallSite(statement=stmt, scope_name=self._get_current_scope_label())

        return [
            AttrWriteConstraint(
                base=base_var, attr=attr_value, source=source_var, call_site=call_site
            )
        ]

    def _translate_call(self, stmt: IRCall) -> List["Constraint"]:
        """Translate IRCall: target = callee(args...)"""
        # TODO all conditions of arguments should be translated to constraints
        constraints = []

        lval = stmt.get_target()
        callee_expr = stmt.get_func_name()
        args = stmt.get_args()

        callee_var = self._make_variable(callee_expr)
        arg_vars = []
        starred = []
        for idx, (arg, is_starred) in enumerate(args):
            if arg.startswith("<Constant: ") and arg.endswith(">"):
                value_str = arg[len("<Constant: ") : -1]
                try:
                    const_value = ast.literal_eval(value_str)
                except Exception:
                    const_value = value_str
                const_name = f"$const_{stable_token(stmt)}_{idx}"
                const_var = self._make_variable(const_name)
                const_assign = IRAssign(
                    ast.Assign(
                        targets=[ast.Name(id=const_name, ctx=ast.Store())],
                        value=ast.Constant(value=const_value),
                    )
                )
                const_alloc = AllocSite.from_ir_node(const_assign, AllocKind.CONSTANT)
                constraints.append(AllocConstraint(target=const_var, alloc_site=const_alloc))
                arg_vars.append(const_var)
            else:
                arg_vars.append(self._make_variable(arg))
            starred.append(is_starred)
        arg_vars = tuple(arg_vars)

        target_var = None
        if lval:
            self._register_local_var(lval)
            target_var = self._make_variable(lval)

        call_site_scope = self._get_current_scope_label()
        call_site = CallSite(statement=stmt, scope_name=call_site_scope)
        keyword_vars = tuple(
            (kw_name, self._make_variable(kw_val)) for kw_name, kw_val in stmt.get_keywords()
        )
        constraints.append(
            CallConstraint(
                callee=callee_var,
                args=arg_vars,
                kwargs=keyword_vars,
                target=target_var,
                call_site=call_site,
                starred=tuple(starred),
            )
        )

        # for fields of class, we need to store the value to the class
        if (
            isinstance(self._current_scope, IRClass)
            and target_var is not None
            and not target_var.is_temporary
        ):  # only store the field to the class if it is not a temporary variable
            self.used_variables.append(target_var)

        return constraints

    def _get_current_scope_label(self) -> str:
        """Return a stable string label for the current scope.

        Ensures that the entry module is always labeled '__main__' so tests
        expecting module-level calls from __main__ succeed, while other modules
        retain their qualified names.
        """
        if self._current_scope is None:
            return "<unknown>"

        try:
            entry_module = getattr(self.world, "entry_module", None)
        # except AttributeError:
        #     entry_module = None
        finally:
            ...

        if isinstance(self._current_scope, IRModule):
            if entry_module is None or self._current_scope is entry_module:
                return "__main__"
            return self._current_scope.get_qualname()

        if hasattr(self._current_scope, "get_qualname"):
            return self._current_scope.get_qualname()

        if hasattr(self._current_scope, "name"):
            return self._current_scope.name

        return str(self._current_scope)

    def _resolve_enclosing_variable_kind(self, name: str) -> Optional[VariableKind]:
        """Infer variable kind from enclosing scopes when closure metadata is missing."""
        if self._current_scope is None:
            return None

        father_map = getattr(self.scope_manager, "father", {})
        parent = father_map.get(self._current_scope)

        while parent is not None:
            locals_in_parent = self._local_vars.get(parent, set())
            if isinstance(parent, IRFunc):
                arg_names = getattr(parent, "arg_names", set())
                if name in parent.get_global_vars():
                    return VariableKind.GLOBAL
                if name in parent.get_nonlocal_vars():
                    return VariableKind.NONLOCAL
                if name in parent.get_cell_vars() or name in locals_in_parent or name in arg_names:
                    return VariableKind.CELL
            elif isinstance(parent, IRClass):
                if not isinstance(self._current_scope, IRFunc) and name in locals_in_parent:
                    return VariableKind.NONLOCAL
            elif isinstance(parent, IRModule):
                return VariableKind.GLOBAL
            parent = father_map.get(parent)

        return None

    def _translate_return(self, stmt: IRReturn) -> List["Constraint"]:
        """Translate IRReturn: return value.

        For regular functions: stores to $return variable.
        For async functions: stores to $coroutine.$await_result field.
        For generators, retain the value used by ``yield from``'s
        ``StopIteration.value`` as well as the ordinary return flow.
        """
        rval = stmt.get_value()
        constraints = []
        source_var = self._make_variable(rval) if rval else None

        is_generator = False
        if isinstance(self._current_scope, IRFunc):
            body = self.scope_manager.get_ir(self._current_scope, "ir") or ()
            is_generator = any(isinstance(item, IRYield) for item in body)
        if is_generator:
            if source_var is None:
                none_name = f"$yield_from_none@{stable_token(stmt)}"
                source_var = self._make_variable(none_name)
                none_assign = IRAssign(
                    ast.Assign(
                        targets=[ast.Name(id=none_name, ctx=ast.Store())],
                        value=ast.Constant(value=None),
                    )
                )
                constraints.append(
                    AllocConstraint(
                        target=source_var,
                        alloc_site=AllocSite.from_ir_node(none_assign, AllocKind.CONSTANT),
                    )
                )
            constraints.append(
                StoreConstraint(
                    base=self._make_variable("$generator"),
                    field=attr("$yield_from_return"),
                    source=source_var,
                )
            )

        if source_var is None:
            return constraints

        # Check if we're in an async function
        is_async = isinstance(self._current_scope, IRFunc) and self._current_scope.is_async

        if is_async:
            # For async functions, store to coroutine's $await_result field
            coroutine_var = self._make_variable("$coroutine")
            constraints.append(
                StoreConstraint(base=coroutine_var, field=attr("$await_result"), source=source_var)
            )

        # Always copy to $return for normal call handling
        return_var = self._make_variable("$return")
        constraints.append(CopyConstraint(source=source_var, target=return_var))

        return constraints

    def _translate_raise(self, stmt: IRRaise) -> List["Constraint"]:
        """Propagate raised values into the exception-handler flow variable."""
        raised_var = self._make_variable("$raised_exception")
        caught_var = self._make_variable("$caught_exception")
        constraints = []

        if isinstance(stmt.exc, ast.Name):
            exception = self._make_variable(stmt.exc.id)
            if self._is_known_exception_class(stmt.exc.id):
                constraints.append(
                    CallConstraint(
                        callee=exception,
                        args=(),
                        kwargs=(),
                        target=raised_var,
                        call_site=CallSite(
                            statement=stmt,
                            scope_name=self._get_current_scope_label(),
                        ),
                    )
                )
            elif self._raise_name_may_be_a_class(stmt.exc.id):
                constraints.append(CopyConstraint(source=exception, target=raised_var))
                constraints.append(
                    CallConstraint(
                        callee=exception,
                        args=(),
                        kwargs=(),
                        target=raised_var,
                        call_site=CallSite(
                            statement=stmt,
                            scope_name=self._get_current_scope_label(),
                        ),
                    )
                )
                constraints.append(
                    SemanticGapConstraint(
                        target=raised_var,
                        kind="ambiguous_raise_value",
                        message=(
                            f"raised name {stmt.exc.id!r} may be an exception class or instance"
                        ),
                    )
                )
            else:
                constraints.append(CopyConstraint(source=exception, target=raised_var))
        elif isinstance(stmt.exc, ast.Call) and isinstance(stmt.exc.func, ast.Name):
            # A direct ``raise ExceptionType(...)`` is not otherwise lowered
            # to an IRCall.  Route it through the usual call translator so
            # builtin and project exception constructors get their normal
            # points-to model.
            assignment = ast.Assign(
                targets=[ast.Name(id="$raised_exception_call", ctx=ast.Store())],
                value=stmt.exc,
            )
            ast.copy_location(assignment, stmt.get_ast())
            constraints.extend(self._translate_call(IRCall(assignment)))
            constraints.append(
                CopyConstraint(
                    source=self._make_variable("$raised_exception_call"), target=raised_var
                )
            )
        elif stmt.exc is None:
            # Bare ``raise`` re-raises the active handler exception.
            constraints.append(CopyConstraint(source=caught_var, target=raised_var))
        else:
            constraints.append(
                SemanticGapConstraint(
                    target=caught_var,
                    kind="unsupported_raise_expression",
                    message=(
                        "raised exception expression was not modeled: " f"{ast.unparse(stmt.exc)}"
                    ),
                )
            )

        constraints.append(CopyConstraint(source=raised_var, target=caught_var))
        cause = self._make_variable(stmt.cause.id) if isinstance(stmt.cause, ast.Name) else None
        if cause is not None:
            constraints.append(
                AttrWriteConstraint(
                    base=raised_var,
                    attr="__cause__",
                    source=cause,
                    call_site=CallSite(
                        statement=stmt,
                        scope_name=self._get_current_scope_label(),
                    ),
                )
            )
        if stmt.exc is not None:
            constraints.append(
                AttrWriteConstraint(
                    base=raised_var,
                    attr="__context__",
                    source=caught_var,
                    call_site=CallSite(
                        statement=stmt,
                        scope_name=self._get_current_scope_label(),
                    ),
                )
            )
        constraints.append(RaiseConstraint(exception=raised_var, cause=cause))
        return constraints

    def _is_known_exception_class(self, name: str, seen: Optional[Set[str]] = None) -> bool:
        """Whether a bare raised name denotes a class that must be instantiated."""
        if seen is None:
            seen = set()
        if name in seen:
            return False
        seen.add(name)
        if name in BUILTIN_EXCEPTION_NAMES:
            return True
        if name in self._import_aliases and name[:1].isupper():
            return True
        if any(
            isinstance(scope, IRClass) and scope.name == name for scope in self.scope_manager.father
        ):
            return True
        scopes = {self._current_scope, self._enclosing_module()}
        for scope in scopes:
            if scope is None:
                continue
            for stmt in self.scope_manager.get_ir(scope, "ir") or ():
                if not isinstance(stmt, (IRAssign, IRCopy)):
                    continue
                target = stmt.get_lval()
                value = stmt.get_rval()
                if (
                    isinstance(target, ast.Name)
                    and target.id == name
                    and isinstance(value, ast.Name)
                    and self._is_known_exception_class(value.id, seen)
                ):
                    return True
        return False

    def _raise_name_may_be_a_class(self, name: str, seen: Optional[Set[str]] = None) -> bool:
        """Whether name-based raise semantics depend on an unknown runtime type."""
        if seen is None:
            seen = set()
        if name in seen:
            return False
        seen.add(name)
        if name in self._import_aliases:
            return True
        if isinstance(self._current_scope, IRFunc) and name in self._current_scope.arg_names:
            return True
        for scope in {self._current_scope, self._enclosing_module()}:
            if scope is None:
                continue
            for stmt in self.scope_manager.get_ir(scope, "ir") or ():
                if (
                    isinstance(stmt, IRLoadAttr)
                    and stmt.get_lval().id == name
                    and stmt.get_attr()[:1].isupper()
                ):
                    return True
                if not isinstance(stmt, (IRAssign, IRCopy)):
                    continue
                target = stmt.get_lval()
                value = stmt.get_rval()
                if (
                    isinstance(target, ast.Name)
                    and target.id == name
                    and isinstance(value, ast.Name)
                    and self._raise_name_may_be_a_class(value.id, seen)
                ):
                    return True
        return False

    def _translate_load_subscr(self, stmt: IRLoadSubscr) -> List["Constraint"]:
        """Translate IRLoadSubscr: target = container[index]"""
        lval = stmt.get_lval().id
        container_name = stmt.get_obj().id

        subslice = stmt.get_slice()
        self._register_local_var(lval)
        container_var = self._make_variable(container_name)
        target_var = self._make_variable(lval)

        constraints = []

        if isinstance(subslice, ast.Slice):
            # A slice is a new sequence, not an element of the source.  Give
            # the target a container and copy the source's generic element
            # flow into it.  Previously the synthetic index variable stayed
            # empty, so ``x = xs[1:]`` produced an empty (but "complete")
            # points-to set.
            constraints.append(
                AllocConstraint(
                    target=target_var,
                    alloc_site=AllocSite.from_ir_node(stmt, AllocKind.LIST),
                )
            )
            elem_var = self._make_variable(f"$slice_elem@{stable_token(stmt)}")
            constraints.append(LoadConstraint(base=container_var, field=elem(), target=elem_var))
            constraints.append(StoreConstraint(base=target_var, field=elem(), source=elem_var))
            return constraints

        # Extract index variable for dynamic field resolution
        if hasattr(subslice, "id"):
            index_var = self._make_variable(subslice.id)
        else:
            # For non-name indexes (constants, etc.), create a temporary
            index_name = f"$index_{stable_token(stmt)}"
            index_var = self._make_variable(index_name)
            if isinstance(subslice, ast.Constant):
                const_assign = IRAssign(
                    ast.Assign(
                        targets=[ast.Name(id=index_name, ctx=ast.Store())],
                        value=subslice,
                    )
                )
                const_alloc = AllocSite.from_ir_node(const_assign, AllocKind.CONSTANT)
                constraints.append(AllocConstraint(target=index_var, alloc_site=const_alloc))

        # Generate LoadSubscrConstraint with index variable for dynamic resolution
        if self.config.index_sensitive:
            constraints.append(
                LoadSubscrConstraint(base=container_var, index=index_var, target=target_var)
            )
        else:
            constraints.append(LoadConstraint(base=container_var, field=elem(), target=target_var))

        # Also generate __getitem__ call for custom container types
        getitem_method_var = self._make_variable(f"$optional_callee@getitem:{stable_token(stmt)}")
        call_site = CallSite(statement=stmt, scope_name=self._get_current_scope_label())
        constraints.append(
            AttrReadConstraint(
                base=container_var,
                attr="__getitem__",
                target=getitem_method_var,
                call_site=call_site,
            )
        )

        constraints.append(
            CallConstraint(
                callee=getitem_method_var,
                args=(index_var,),
                kwargs=(),
                target=target_var,
                call_site=call_site,
            )
        )

        # for fields of class, we need to store the value to the class
        if (
            isinstance(self._current_scope, IRClass) and not target_var.is_temporary
        ):  # only store the field to the class if it is not a temporary variable
            self.used_variables.append(target_var)

        return constraints

    def _translate_store_subscr(self, stmt: IRStoreSubscr) -> List["Constraint"]:
        """Translate IRStoreSubscr: container[index] = value"""
        container_name = stmt.get_obj().id
        value_name = stmt.get_rval().id

        container_var = self._make_variable(container_name)
        value_var = self._make_variable(value_name)

        constraints = []

        # Extract index variable for dynamic field resolution
        index_expr = stmt.get_slice()
        if hasattr(index_expr, "id"):
            index_var = self._make_variable(index_expr.id)
        else:
            # For non-name indexes (constants, etc.), create a temporary
            index_name = f"$index_{stable_token(stmt)}"
            index_var = self._make_variable(index_name)
            if isinstance(index_expr, ast.Constant):
                const_assign = IRAssign(
                    ast.Assign(
                        targets=[ast.Name(id=index_name, ctx=ast.Store())],
                        value=index_expr,
                    )
                )
                const_alloc = AllocSite.from_ir_node(const_assign, AllocKind.CONSTANT)
                constraints.append(AllocConstraint(target=index_var, alloc_site=const_alloc))

        # Generate StoreSubscrConstraint with index variable for dynamic resolution
        constraints.append(
            StoreSubscrConstraint(base=container_var, index=index_var, source=value_var)
        )
        if self.config.index_sensitive:
            constraints.append(
                StoreSubscrConstraint(base=container_var, index=index_var, source=value_var)
            )
        else:
            constraints.append(StoreConstraint(base=container_var, field=elem(), source=value_var))

        # Also generate __setitem__ call for custom container types
        setitem_method_var = self._make_variable(f"$optional_callee@setitem:{stable_token(stmt)}")
        call_site = CallSite(statement=stmt, scope_name=self._get_current_scope_label())
        constraints.append(
            AttrReadConstraint(
                base=container_var,
                attr="__setitem__",
                target=setitem_method_var,
                call_site=call_site,
            )
        )

        constraints.append(
            CallConstraint(
                callee=setitem_method_var,
                args=(index_var, value_var),
                kwargs=(),
                target=None,
                call_site=call_site,
            )
        )

        return constraints

    def _translate_function_def(self, stmt: IRFunc) -> Tuple[Variable, List["Constraint"]]:
        """Translate function definition: allocate function object."""
        constraints = []
        self._local_vars.setdefault(stmt, set()).update(stmt.get_arg_names())
        if isinstance(self._current_scope, IRClass):
            self._local_vars.setdefault(self._current_scope, set()).add(stmt.name)

        if isinstance(self._current_scope, IRClass) and (not stmt.is_static_method):
            func_alloc = AllocSite.from_ir_node(stmt, AllocKind.METHOD)
        else:
            func_alloc = AllocSite.from_ir_node(stmt, AllocKind.FUNCTION)
        func_var = self._make_variable(stmt.name)
        constraints.append(AllocConstraint(target=func_var, alloc_site=func_alloc))

        type_params = getattr(getattr(stmt, "stmt", None), "type_params", ())
        if type_params:
            type_params_var = self._make_variable(f"$function_type_params@{stable_token(stmt)}")
            type_params_site = IRAssign(
                ast.Assign(
                    targets=[ast.Name(id=type_params_var.name, ctx=ast.Store())],
                    value=ast.Constant(value=None),
                )
            )
            constraints.append(
                AllocConstraint(
                    target=type_params_var,
                    alloc_site=AllocSite.from_ir_node(type_params_site, AllocKind.TUPLE),
                )
            )
            type_parameter_variables = {}

            def type_parameter_value(expression, suffix):
                if isinstance(expression, ast.Name):
                    return type_parameter_variables.get(expression.id) or self._make_variable(
                        expression.id
                    )
                variable = self._make_variable(
                    f"$function_type_metadata@{stable_token(stmt)}_{suffix}"
                )
                assign = IRAssign(
                    ast.Assign(
                        targets=[ast.Name(id=variable.name, ctx=ast.Store())],
                        value=copy.deepcopy(expression),
                    )
                )
                kind = (
                    AllocKind.CONSTANT if isinstance(expression, ast.Constant) else AllocKind.OBJECT
                )
                constraints.append(
                    AllocConstraint(
                        target=variable,
                        alloc_site=AllocSite.from_ir_node(assign, kind),
                    )
                )
                return variable

            for index, parameter in enumerate(type_params):
                parameter_var = self._make_variable(
                    f"$function_type_param@{stable_token(stmt)}_{index}"
                )
                parameter_site = IRAssign(
                    ast.Assign(
                        targets=[ast.Name(id=parameter_var.name, ctx=ast.Store())],
                        value=ast.Constant(value=None),
                    )
                )
                constraints.append(
                    AllocConstraint(
                        target=parameter_var,
                        alloc_site=AllocSite.from_ir_node(parameter_site, AllocKind.OBJECT),
                    )
                )
                type_parameter_variables[parameter.name] = parameter_var
                constraints.extend(
                    [
                        StoreConstraint(
                            base=type_params_var,
                            field=key(index),
                            source=parameter_var,
                        ),
                        StoreConstraint(
                            base=type_params_var,
                            field=elem(),
                            source=parameter_var,
                        ),
                    ]
                )
                bound = getattr(parameter, "bound", None)
                if isinstance(bound, ast.Tuple):
                    constraints_var = self._make_variable(
                        f"$function_type_constraints@{stable_token(stmt)}_{index}"
                    )
                    constraints_site = IRAssign(
                        ast.Assign(
                            targets=[ast.Name(id=constraints_var.name, ctx=ast.Store())],
                            value=ast.Constant(value=None),
                        )
                    )
                    constraints.append(
                        AllocConstraint(
                            target=constraints_var,
                            alloc_site=AllocSite.from_ir_node(constraints_site, AllocKind.TUPLE),
                        )
                    )
                    for constraint_index, expression in enumerate(bound.elts):
                        value_var = type_parameter_value(expression, f"{index}_{constraint_index}")
                        constraints.extend(
                            [
                                StoreConstraint(
                                    base=constraints_var,
                                    field=key(constraint_index),
                                    source=value_var,
                                ),
                                StoreConstraint(
                                    base=constraints_var,
                                    field=elem(),
                                    source=value_var,
                                ),
                            ]
                        )
                    constraints.append(
                        StoreConstraint(
                            base=parameter_var,
                            field=attr("__constraints__"),
                            source=constraints_var,
                        )
                    )
                elif bound is not None:
                    constraints.append(
                        StoreConstraint(
                            base=parameter_var,
                            field=attr("__bound__"),
                            source=type_parameter_value(bound, f"{index}_bound"),
                        )
                    )
                default_value = getattr(parameter, "default_value", None)
                if default_value is not None:
                    constraints.append(
                        StoreConstraint(
                            base=parameter_var,
                            field=attr("__default__"),
                            source=type_parameter_value(default_value, f"{index}_default"),
                        )
                    )
            constraints.append(
                StoreConstraint(
                    base=func_var,
                    field=attr("__type_params__"),
                    source=type_params_var,
                )
            )

        if hasattr(stmt, "decorator_list") and stmt.decorator_list:
            current_var = self._apply_decorators(
                stmt.decorator_list,
                func_var,
                stmt.name,
                stmt,
                constraints,
                skip_descriptors=True,
            )
            # Rebind function name to final decorated result
            constraints.append(CopyConstraint(source=current_var, target=func_var))

        # for fields of class, we need to store the value to the class
        if (
            isinstance(self._current_scope, IRClass) and not func_var.is_temporary
        ):  # only store the field if it is not a temporary variable
            self.used_variables.append(func_var)

        return func_var, constraints

    def _class_annotations(self, ir_cls: "IRClass", class_var: "Variable") -> List["Constraint"]:
        """Expose a class's annotated field names through ``__annotations__``.

        ``dataclasses``, ``attrs`` and friends read ``cls.__annotations__`` to
        discover fields; without it the dataclass stub generated an empty
        ``__init__`` and every user dataclass lost its attributes.
        """
        body = getattr(getattr(ir_cls, "stmt", None), "body", ()) or ()
        names = [
            node.target.id
            for node in body
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
        ]
        if not names:
            return []
        constraints: List["Constraint"] = []
        token = stable_token(ir_cls)
        annotations_var = self._make_variable(f"$class_annotations@{token}")
        constraints.append(
            AllocConstraint(
                target=annotations_var,
                alloc_site=AllocSite(stmt=ir_cls, kind=AllocKind.DICT),
            )
        )
        for index, name in enumerate(names):
            key_name = f"$annotation_key@{token}@{index}"
            key_var = self._make_variable(key_name)
            key_stmt = IRAssign(
                ast.Assign(
                    targets=[ast.Name(id=key_name, ctx=ast.Store())],
                    value=ast.Constant(value=name),
                )
            )
            constraints.append(
                AllocConstraint(
                    target=key_var,
                    alloc_site=AllocSite.from_ir_node(key_stmt, AllocKind.CONSTANT),
                )
            )
            constraints.append(
                StoreConstraint(base=annotations_var, field=dict_keys(), source=key_var)
            )
            value_name = f"$annotation_value@{token}@{index}"
            value_var = self._make_variable(value_name)
            value_stmt = IRAssign(
                ast.Assign(
                    targets=[ast.Name(id=value_name, ctx=ast.Store())],
                    value=ast.Constant(value=None),
                )
            )
            constraints.append(
                AllocConstraint(
                    target=value_var,
                    alloc_site=AllocSite.from_ir_node(value_stmt, AllocKind.UNKNOWN),
                )
            )
            constraints.append(
                StoreConstraint(base=annotations_var, field=key(name), source=value_var)
            )
            constraints.append(
                StoreConstraint(base=annotations_var, field=elem(), source=value_var)
            )
        constraints.append(
            StoreConstraint(base=class_var, field=attr("__annotations__"), source=annotations_var)
        )
        return constraints

    #: Descriptor decorators that ``IRFunc`` records explicitly.
    _DESCRIPTOR_DECORATORS = frozenset({"staticmethod", "classmethod", "property"})

    def _apply_decorators(
        self,
        decorators,
        current_var: "Variable",
        owner_name: str,
        site_stmt,
        constraints: List["Constraint"],
        *,
        skip_descriptors: bool,
    ) -> "Variable":
        """Bind ``name`` to ``decorator_n(...decorator_0(name))``.

        Handles bare decorators, attribute decorators (``@obj.hook``) and
        decorator *factories* (``@dataclass(slots=True)``, ``@app.route("/")``)
        for both functions and classes.  Keyword arguments are forwarded: they
        were previously dropped, so ``@dataclass(slots=True)`` called the
        factory with no arguments.
        """
        for index, decorator_expr in enumerate(reversed(list(decorators))):
            if isinstance(decorator_expr, ast.Attribute) and decorator_expr.attr in {
                "setter",
                "getter",
                "deleter",
            }:
                # The property object is not a first-class abstract object in
                # the heap model.  The class namespace already joins the getter
                # and setter functions under the same name; treating
                # ``@v.setter`` as a call only produced an unresolved callee.
                continue
            if (
                skip_descriptors
                and isinstance(decorator_expr, ast.Name)
                and decorator_expr.id in self._DESCRIPTOR_DECORATORS
            ):
                # IRFunc records these descriptor semantics explicitly.
                # Reapplying them as unresolved global calls loses the method.
                continue
            call = decorator_expr if isinstance(decorator_expr, ast.Call) else None
            callee_expr = call.func if call is not None else decorator_expr
            decorator_var = self._decorator_callee(callee_expr, owner_name, index, constraints)
            if call is not None:
                args = tuple(
                    self._decorator_argument(value, owner_name, index, position, constraints)
                    for position, value in enumerate(call.args)
                )
                kwargs = tuple(
                    (
                        keyword.arg,
                        self._decorator_argument(
                            keyword.value, owner_name, index, position, constraints
                        ),
                    )
                    for position, keyword in enumerate(call.keywords)
                    if keyword.arg is not None
                )
                factory_var = self._make_variable(f"$decorator_{owner_name}_{index}")
                constraints.append(
                    CallConstraint(
                        callee=decorator_var,
                        args=args,
                        kwargs=kwargs,
                        target=factory_var,
                        call_site=CallSite(
                            statement=site_stmt,
                            scope_name=self._get_current_scope_label(),
                            index=index * 2,
                        ),
                    )
                )
                decorator_var = factory_var
            result_var = self._make_variable(f"{owner_name}_decorated_{index}")
            constraints.append(
                CallConstraint(
                    callee=decorator_var,
                    args=(current_var,),
                    kwargs=(),
                    target=result_var,
                    call_site=CallSite(
                        statement=site_stmt,
                        scope_name=self._get_current_scope_label(),
                        index=index * 2 + 1,
                    ),
                )
            )
            current_var = result_var
        return current_var

    def _decorator_callee(
        self, expr, owner_name: str, index: int, constraints: List["Constraint"]
    ) -> "Variable":
        """Resolve the callable part of a decorator expression."""
        if isinstance(expr, ast.Name):
            return self._make_variable(expr.id)
        target = self._make_variable(f"$decorator_factory_{owner_name}_{index}")
        if isinstance(expr, ast.Attribute) and isinstance(expr.value, ast.Name):
            obj_var = self._make_variable(expr.value.id)
            constraints.append(LoadConstraint(base=obj_var, field=attr(expr.attr), target=target))
        return target

    def _decorator_argument(
        self, expr, owner_name: str, index: int, position: int, constraints: List["Constraint"]
    ) -> "Variable":
        """Resolve one decorator-factory argument."""
        if isinstance(expr, ast.Name):
            return self._make_variable(expr.id)
        name = f"$decorator_arg_{owner_name}_{index}_{position}"
        var = self._make_variable(name)
        if isinstance(expr, ast.Constant):
            assignment = ast.Assign(targets=[ast.Name(id=name, ctx=ast.Store())], value=expr)
            const_alloc = AllocSite.from_ir_node(IRAssign(assignment), AllocKind.CONSTANT)
            constraints.append(AllocConstraint(target=var, alloc_site=const_alloc))
        return var

    def _is_dataclass_decorator(self, expr: ast.expr) -> bool:
        """Recognize the class-preserving ``dataclasses.dataclass`` decorator."""
        if isinstance(expr, ast.Call):
            expr = expr.func
        if isinstance(expr, ast.Name):
            return (
                expr.id == "dataclass"
                or self._import_aliases.get(expr.id) == "dataclasses.dataclass"
            )
        if isinstance(expr, ast.Attribute):
            return expr.attr == "dataclass"
        return False

    def _translate_class_def(self, ir_cls: IRClass) -> Tuple[Variable, List["Constraint"]]:
        """Translate class definition: allocate class object and bind methods."""
        constraints = []

        # A class statement binds its name in the surrounding lexical scope.
        # Register it before resolving the class variable so nested classes use
        # local/cell bindings rather than being forced into module globals.
        self._register_local_var(ir_cls.name)

        base_variables = []
        for base in ir_cls.get_bases():
            if isinstance(base, ast.Name):
                base_variables.append(self._make_variable(base.id))
            elif isinstance(base, ast.Starred):
                constraints.append(
                    SemanticGapConstraint(
                        kind="starred_class_base",
                        message=("starred class base was not expanded: " f"{ast.unparse(base)}"),
                    )
                )
        self._class_base_variables[ir_cls] = tuple(base_variables)

        metaclass_variables = []
        class_keyword_variables = []
        for keyword in ir_cls.keywords:
            if isinstance(keyword.value, ast.Name):
                keyword_var = self._make_variable(keyword.value.id)
            elif isinstance(keyword.value, ast.Constant):
                keyword_name = f"$class_keyword@{stable_token(ir_cls)}@{keyword.arg}"
                keyword_var = self._make_variable(keyword_name)
                assignment = ast.Assign(
                    targets=[ast.Name(id=keyword_name, ctx=ast.Store())],
                    value=keyword.value,
                )
                constraints.append(
                    AllocConstraint(
                        target=keyword_var,
                        alloc_site=AllocSite.from_ir_node(IRAssign(assignment), AllocKind.CONSTANT),
                    )
                )
            else:
                continue
            if keyword.arg == "metaclass":
                metaclass_variables.append(keyword_var)
            else:
                class_keyword_variables.append((keyword.arg, keyword_var))
        self._class_metaclass_variables[ir_cls] = tuple(metaclass_variables)
        self._class_keyword_variables[ir_cls] = tuple(class_keyword_variables)

        class_alloc = AllocSite.from_ir_node(ir_cls, AllocKind.CLASS)
        class_var = self._make_variable(ir_cls.name)
        raw_class_var = self._make_variable(f"$class_result@{stable_token(ir_cls)}")
        constraints.append(AllocConstraint(target=raw_class_var, alloc_site=class_alloc))

        # ``@dataclass`` is a class-preserving decorator.  The stub models it
        # with a conditional return (``wrap(cls) if cls is not None else wrap``),
        # and the flow-insensitive IR merges both branches.  The class binding
        # therefore also acquired the ``wrap`` function, so ``D(a)`` could call
        # ``wrap`` and leak constructor arguments into the class-call result.
        # Run the decorator for its side effects on the class object, but keep
        # the original class as the bound value.
        decorators = list(ir_cls.decorator_list)
        dataclass_decorators = [d for d in decorators if self._is_dataclass_decorator(d)]
        other_decorators = [d for d in decorators if d not in dataclass_decorators]
        current_var = raw_class_var
        for decorator in dataclass_decorators:
            self._apply_decorators(
                [decorator],
                current_var,
                ir_cls.name,
                ir_cls,
                constraints,
                skip_descriptors=False,
            )
        current_var = self._apply_decorators(
            other_decorators,
            current_var,
            ir_cls.name,
            ir_cls,
            constraints,
            skip_descriptors=False,
        )
        constraints.append(CopyConstraint(source=current_var, target=class_var))
        constraints.extend(self._class_annotations(ir_cls, class_var))

        # TODO [CRITICAL] the method of treating inheritances is totally wrong, we should use the class hierarchy manager to handle this.
        """
        for base_name in ir_cls.get_bases():
            if not isinstance(base_name, ast.Name):
                continue # TODO resolve the base name in detail
            
            base_var = self._make_variable(base_name.id)
            constraints.append(StoreConstraint(
                base=class_var,
                field=attr("__bases__"),
                source=base_var
            ))
        """

        # for fields of class, we need to store the value to the class
        if (
            isinstance(self._current_scope, IRClass) and not class_var.is_temporary
        ):  # only store the field if it is not a temporary variable
            self.used_variables.append(class_var)

        return class_var, constraints

    def _enclosing_module(self) -> Optional["IRModule"]:
        """Return the module containing the scope currently being translated."""
        scope = self._current_scope
        seen = set()
        while scope is not None and not isinstance(scope, IRModule):
            if scope in seen:
                return None
            seen.add(scope)
            scope = getattr(self.scope_manager, "father", {}).get(scope)
        return scope

    def _translate_import(self, stmt: IRImport) -> List["Constraint"]:
        """Translate import statement with transitive analysis."""
        constraints = []
        import_node = stmt.stmt
        if isinstance(import_node, ast.ImportFrom):
            prefix = import_node.module or ""
            for alias in import_node.names:
                local = alias.asname or alias.name
                self._import_aliases[local] = f"{prefix}.{alias.name}".lstrip(".")
        elif isinstance(import_node, ast.Import):
            for alias in import_node.names:
                local = alias.asname or alias.name.split(".", 1)[0]
                self._import_aliases[local] = alias.name

        # Import resolution always happens in the namespace of the containing
        # module, even when the statement itself appears inside a function or
        # class body.
        module_scope = self._enclosing_module() or self._current_scope
        module_ir = self.scope_manager.get_module_graph().get_succ_module(module_scope, stmt)
        if module_ir is None:
            # Preserve the import's canonical identity even when source is not
            # available. Anonymous UNKNOWN objects make external APIs vanish
            # after aliases and field loads.
            alloc_site = AllocSite.from_ir_node(stmt, AllocKind.NATIVE)
        else:
            alloc_site = AllocSite.from_ir_node(stmt, AllocKind.MODULE)

        if isinstance(stmt.stmt, ast.ImportFrom) and stmt.name == "*":
            module_var = self._make_variable(f"$import_module@{stable_token(stmt)}")
            constraints.append(AllocConstraint(target=module_var, alloc_site=alloc_site))
            if module_ir is None:
                constraints.append(
                    SemanticGapConstraint(
                        kind="import_star",
                        message=(
                            "star import from an unresolved module was not expanded: "
                            f"{stmt.module or ''}"
                        ),
                    )
                )
            else:
                exported = set()
                for statement in self.scope_manager.get_ir(module_ir, "ir") or ():
                    if isinstance(statement, (IRClass, IRFunc)):
                        exported.add(statement.name)
                    else:
                        exported.update(statement.get_stores())
                exported = {
                    name for name in exported if name.isidentifier() and not name.startswith("_")
                }
                for exported_name in sorted(exported):
                    local_var = self._make_variable(exported_name)
                    constraints.append(
                        LoadConstraint(
                            base=module_var,
                            field=attr(exported_name),
                            target=local_var,
                        )
                    )
            return constraints

        # ``from pkg import submodule`` and ``from . import views`` resolve to
        # the submodule itself.  Binding that module directly avoids looking
        # up an attribute that only exists as a file on disk.
        if (
            module_ir is not None
            and isinstance(stmt.stmt, ast.ImportFrom)
            and stmt.name
            and module_ir.get_qualname() != (stmt.module or "")
            and module_ir.get_qualname().rsplit(".", 1)[-1] == stmt.name
        ):
            local_var = self._make_variable(stmt.asname or stmt.name)
            constraints.append(AllocConstraint(target=local_var, alloc_site=alloc_site))
            if (
                isinstance(self._current_scope, IRClass) and not local_var.is_temporary
            ):  # only store the field to the class if it is not a temporary variable
                self.used_variables.append(local_var)
            return constraints

        # allocate the module variable
        if stmt.module is None:
            if stmt.asname is None:
                local_var = self._make_variable(stmt.name)
            else:
                local_var = self._make_variable(stmt.asname)
            constraints.append(AllocConstraint(target=local_var, alloc_site=alloc_site))
        elif stmt.asname is None:
            module_name = stmt.module or ""
            # ``from pkg import pkg`` (and relative forms such as
            # ``from ._impl import _impl``) otherwise bind the module object to
            # the very variable used as the attribute-load base.  Every load
            # then feeds its own result back into the base, and unresolved
            # native access paths grow without bound.  Use a synthetic base so
            # the imported name cannot alias the module binding.
            if not module_name or module_name == stmt.name:
                module_var = self._make_variable(f"$import_module@{stable_token(stmt)}")
            else:
                module_var = self._make_variable(module_name)
            constraints.append(AllocConstraint(target=module_var, alloc_site=alloc_site))
            local_var = self._make_variable(stmt.name)
            constraints.append(
                LoadConstraint(base=module_var, field=attr(stmt.name), target=local_var)
            )
        else:
            module_var = self._make_variable(stmt.module)
            constraints.append(AllocConstraint(target=module_var, alloc_site=alloc_site))
            local_var = self._make_variable(stmt.asname)
            constraints.append(
                LoadConstraint(base=module_var, field=attr(stmt.name), target=local_var)
            )

        # for fields of class, we need to store the value to the class
        if (
            isinstance(self._current_scope, IRClass) and not local_var.is_temporary
        ):  # only store the field to the class if it is not a temporary variable
            self.used_variables.append(local_var)

        return constraints

    def _translate_with_enter(
        self, context_manager_var: "Variable", target_var: "Variable"
    ) -> List["Constraint"]:
        """Generate constraints for context manager __enter__.
        Used for: with obj as target: ...
        Generates: temp = obj.__enter__; target = temp()
        """
        constraints = []

        enter_method_var = self._make_variable(
            f"$optional_callee@enter:{stable_token(context_manager_var)}"
        )
        call_stmt = IRCall(ast.parse(f"[{target_var}] = {context_manager_var}.__enter__()").body[0])
        call_site = CallSite(statement=call_stmt, scope_name=self._get_current_scope_label())
        constraints.append(
            AttrReadConstraint(
                base=context_manager_var,
                attr="__enter__",
                target=enter_method_var,
                call_site=call_site,
            )
        )

        constraints.append(
            CallConstraint(
                callee=enter_method_var, args=(), kwargs=(), target=target_var, call_site=call_site
            )
        )

        return constraints

    def _translate_with_exit(self, context_manager_var: "Variable") -> List["Constraint"]:
        """Generate constraints for context manager __exit__.
        Used for: with obj: ... (at exit)
        Generates: temp = obj.__exit__; temp(None, None, None)
        """
        constraints = []

        exit_method_var = self._make_variable(
            f"$optional_callee@exit:{stable_token(context_manager_var)}"
        )
        call_stmt = IRCall(
            ast.parse(f"{context_manager_var}.__exit__(None, None, None)").body[0].value
        )
        call_site = CallSite(statement=call_stmt, scope_name=self._get_current_scope_label())
        constraints.append(
            AttrReadConstraint(
                base=context_manager_var,
                attr="__exit__",
                target=exit_method_var,
                call_site=call_site,
            )
        )

        constraints.append(
            CallConstraint(
                callee=exit_method_var, args=(), kwargs=(), target=None, call_site=call_site
            )
        )

        return constraints

    def _translate_iter(
        self, iterable_var: "Variable", target_var: "Variable"
    ) -> List["Constraint"]:
        """Generate constraints for iterator creation.
        Used for: for item in obj: ...
        Generates: iter_temp = obj.__iter__; target = iter_temp()
        """
        constraints = []

        iter_method_var = self._make_variable(f"$optional_callee@iter:{stable_token(iterable_var)}")
        call_stmt = IRCall(ast.parse(f"[{target_var}] = {iterable_var}.__iter__()").body[0])
        call_site = CallSite(statement=call_stmt, scope_name=self._get_current_scope_label())
        constraints.append(
            AttrReadConstraint(
                base=iterable_var,
                attr="__iter__",
                target=iter_method_var,
                call_site=call_site,
            )
        )

        constraints.append(
            CallConstraint(
                callee=iter_method_var, args=(), kwargs=(), target=target_var, call_site=call_site
            )
        )

        return constraints

    def _translate_next(
        self, iterator_var: "Variable", target_var: "Variable"
    ) -> List["Constraint"]:
        """Generate constraints for iterator next."""
        constraints = []

        next_method_var = self._make_variable(f"$optional_callee@next:{stable_token(iterator_var)}")
        call_stmt = IRCall(ast.parse(f"[{target_var}] = {iterator_var}.__next__()").body[0])
        call_site = CallSite(statement=call_stmt, scope_name=self._get_current_scope_label())
        constraints.append(
            AttrReadConstraint(
                base=iterator_var,
                attr="__next__",
                target=next_method_var,
                call_site=call_site,
            )
        )

        constraints.append(
            CallConstraint(
                callee=next_method_var, args=(), kwargs=(), target=target_var, call_site=call_site
            )
        )

        return constraints

    def _translate_binary_op(
        self, left_var: "Variable", right_var: "Variable", target_var: "Variable", op: ast.operator
    ) -> List["Constraint"]:
        constraints = []

        # ``BINOP_TABLE`` is keyed by AST *classes*; look up with ``type(op)``
        # (previously this compared a class against an instance and therefore
        # never matched, so ``a / b`` and friends were never modelled as dunder
        # calls -- which silently broke e.g. ``Path(a) / b``).
        op_name = BINOP_TABLE.get(type(op), None)
        if not op_name:
            return constraints

        # Optional protocol hook: an operand without this dunder (``int + int``)
        # is not an analysis gap, so do not emit unknown-callee diagnostics.
        token = stable_token(left_var)
        method_var = self._make_variable(f"$optional_callee@binop:{op_name}@{token}")

        # Syntactic placeholder only: three-address temporaries such as
        # ``$tmp_0`` are not valid Python identifiers, and IRCall requires a
        # bare-name callee, so the rendered call uses neutral names.
        call_stmt = IRCall(
            ast.Call(
                func=ast.Name(id=op_name, ctx=ast.Load()),
                args=[ast.Name(id="_right", ctx=ast.Load())],
                keywords=[],
            )
        )
        call_site = CallSite(statement=call_stmt, scope_name=self._get_current_scope_label())
        constraints.append(
            AttrReadConstraint(
                base=left_var,
                attr=op_name,
                target=method_var,
                call_site=call_site,
            )
        )
        constraints.append(
            CallConstraint(
                callee=method_var,
                args=(right_var,),
                kwargs=(),
                target=target_var,
                call_site=call_site,
            )
        )

        if (
            isinstance(self._current_scope, IRClass) and not target_var.is_temporary
        ):  # only store the field to the class if it is not a temporary variable
            self.used_variables.append(target_var)

        return constraints

    def _translate_unary_op(
        self,
        operand_var: "Variable",
        target_var: "Variable",
        op: ast.unaryop,
        stmt: "IRAssign",
    ) -> List["Constraint"]:
        constraints = []

        if isinstance(op, ast.Not):
            constraints.extend(self._translate_truthiness(operand_var, stmt))
            rval = stmt.get_rval()
            if isinstance(rval, ast.UnaryOp) and isinstance(rval.operand, ast.Constant):
                outcomes = (not bool(rval.operand.value),)
            else:
                outcomes = (False, True)
            for outcome in outcomes:
                bool_assign = IRAssign(
                    ast.Assign(
                        targets=[ast.Name(id=target_var.name, ctx=ast.Store())],
                        value=ast.Constant(value=outcome),
                    )
                )
                constraints.append(
                    AllocConstraint(
                        target=target_var,
                        alloc_site=AllocSite.from_ir_node(bool_assign, AllocKind.CONSTANT),
                    )
                )
            return constraints

        op_name = UNARYOP_TABLE.get(type(op), None)
        if not op_name:
            return constraints

        token = stable_token(operand_var)
        method_var = self._make_variable(f"$optional_callee@unaryop:{op_name}@{token}")
        call_stmt = IRCall(
            ast.Call(func=ast.Name(id=op_name, ctx=ast.Load()), args=[], keywords=[])
        )
        call_site = CallSite(statement=call_stmt, scope_name=self._get_current_scope_label())
        constraints.append(
            AttrReadConstraint(
                base=operand_var,
                attr=op_name,
                target=method_var,
                call_site=call_site,
            )
        )
        constraints.append(
            CallConstraint(
                callee=method_var, args=(), kwargs=(), target=target_var, call_site=call_site
            )
        )

        if (
            isinstance(self._current_scope, IRClass) and not target_var.is_temporary
        ):  # only store the field to the class if it is not a temporary variable
            self.used_variables.append(target_var)

        return constraints
