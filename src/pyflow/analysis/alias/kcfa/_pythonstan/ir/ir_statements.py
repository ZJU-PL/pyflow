from abc import ABC, abstractmethod
from typing import Set, Union, List, Optional, Tuple, Type
import ast
from ast import stmt as Statement
from ast import Module, ClassDef, Name

from pyflow.analysis.alias.kcfa._pythonstan.utils.var_collector import VarCollector
from pyflow.analysis.alias.kcfa._pythonstan.utils.ast_rename import RenameTransformer


__all__ = [
    'IRStatement',
    'IRAbstractStmt',
    'IRAstStmt',
    'Label',
    'IRCatchException',
    'Goto',
    'JumpIfFalse',
    'JumpIfTrue',
    'IRYield',
    'IRReturn',
    'IRRaise',
    'IRPass',
    'IRAwait',
    'IRDel',
    'IRImport',
    'IRCall',
    'IRAnno',
    'AbstractIRAssign',
    'IRAssign',
    'IRCopy',
    'IRStoreAttr',
    'IRLoadAttr',
    'IRStoreSubscr',
    'IRLoadSubscr',
    'IRPhi',
    'IRScope',
    'IRModule',
    'IRFunc',
    'IRClass'
]


class IRStatement(ABC):
    """Abstract base for every normalized IR node emitted after TAC lowering."""
    @abstractmethod
    def __str__(self) -> str:
        """Returns the SSA friendly textual form used by downstream analyses."""

    def __repr__(self):
        """Delegates to ``__str__`` to keep logging consistent with IR dumps."""
        return self.__str__()

    @abstractmethod
    def get_stores(self) -> Set[str]:
        """Returns variable names that receive a value within this statement."""

    @abstractmethod
    def get_loads(self) -> Set[str]:
        """Returns variable names whose current value is read by this statement."""

    @abstractmethod
    def get_dels(self) -> Set[str]:
        """Returns variable names removed from scope by this statement."""

    def get_nostores(self) -> Set[str]:
        """Returns identifiers referenced without being redefined."""
        return self.get_loads().union(self.get_dels())

    @abstractmethod
    def get_ast(self) -> ast.AST:
        """Exposes the backing AST node produced by ``IRTransformer``."""

    def rename(
        self,
        old_name: str,
        new_name: str,
        ctxs: Tuple[Type[ast.AST], ...],
    ) -> None:
        """Renames inbound/outbound symbols matching ``old_name``."""

    def __lt__(self, other: 'IRStatement') -> bool:
        """Enables deterministic sorting when serialising IR streams."""
        return str(self) < str(other)


class IRAbstractStmt(IRStatement, ABC):
    """Convenience base for IR nodes that have no intrinsic var effects."""

    def get_stores(self) -> Set[str]:
        """Defaults to an empty def-set for structural statements."""
        return {*()}

    def get_loads(self) -> Set[str]:
        """Defaults to an empty use-set for structural statements."""
        return {*()}

    def get_dels(self) -> Set[str]:
        """Defaults to an empty delete-set for structural statements."""
        return {*()}

    def rename(
        self,
        old_name: str,
        new_name: str,
        ctxs: Tuple[Type[ast.AST], ...],
    ) -> None:
        """Provides a no-op rename hook for subclasses without symbols."""
        pass


class IRAstStmt(IRAbstractStmt):
    """Wraps a raw AST statement while exposing VarCollector metadata."""

    stmt: Statement
    #: Backing AST node emitted by ``ThreeAddressTransformer``.
    store_collector: VarCollector
    #: Tracks write contexts discovered when scanning ``stmt``.
    load_collector: VarCollector
    #: Tracks read contexts discovered when scanning ``stmt``.
    del_collector: VarCollector
    #: Tracks delete contexts discovered when scanning ``stmt``.

    def __init__(self, stmt: Statement):
        """Initialises the wrapper with a freshly normalised AST node."""
        self.set_stmt(stmt)

    def __str__(self):
        """Reconstructs the Python source for logging/debugging."""
        return ast.unparse(self.stmt)

    def set_stmt(self, stmt: Statement):
        """Updates the wrapped AST node and rebuilds all collectors. [side effects: mutates ``stmt`` and resets collector caches]"""
        self.stmt = stmt
        ast.fix_missing_locations(self.stmt)
        self.collector_reset()
        self.collect_from_stmt(stmt)

    def get_ast(self) -> Statement:
        """Returns the current AST node backing this IR leaf."""
        return self.stmt

    def collector_reset(self):
        """Initialises per-effect collectors before rescanning a statement."""
        self.store_collector = VarCollector("store")
        self.load_collector = VarCollector("load")
        self.del_collector = VarCollector("del")

    def collect_from_stmt(self, stmt: Statement):
        """Populates collectors by visiting ``stmt``."""
        self.store_collector.visit(stmt)
        self.load_collector.visit(stmt)
        self.del_collector.visit(stmt)

    def get_stores(self) -> Set[str]:
        """Returns variables bound by ``stmt``."""
        return self.store_collector.get_vars()

    def get_loads(self) -> Set[str]:
        """Returns variables read by ``stmt``."""
        return self.load_collector.get_vars()

    def get_dels(self) -> Set[str]:
        """Returns variables deleted by ``stmt``."""
        return self.del_collector.get_vars()

    def rename(
        self,
        old_name: str,
        new_name: str,
        ctxs: Tuple[Type[ast.AST], ...],
    ) -> None:
        """Applies ``RenameTransformer`` to the underlying AST."""
        renamer = RenameTransformer(old_name, new_name, ctxs)
        self.stmt = renamer.visit(self.stmt)


class Label(IRAbstractStmt):
    """Control-flow anchor generated by ``LabelGenerator``."""

    idx: int
    #: Sequential identifier unique within the current IR stream.

    def __init__(self, idx: int):
        """Creates a label placeholder with the provided unique index."""
        self.idx = idx

    def __str__(self):
        """Formats the label in the ``label_N:`` form used by dumps."""
        return f"label_{self.idx}:"

    def to_s(self) -> str:
        """Returns the label head without a trailing colon."""
        return f"label_{self.idx}"

    def get_ast(self) -> None:
        """Labels are synthetic, so no underlying AST node exists."""
        return None


'''
  catch exp from Label_1 to Label_2 goto Label_3
'''
class IRCatchException(IRAbstractStmt):
    """Metadata emitted for each ``try`` handler in the IR stream."""

    exception: List[str]
    #: Qualified exception names handled by this clause.
    from_label: Label
    #: Label pointing to the try body entry.
    to_label: Label
    #: Label covering the handler dispatch region.
    goto_label: Label
    #: Label executed when this handler is selected.
    exception_ast: Optional[ast.ExceptHandler]
    #: Original AST handler, retained for diagnostics.

    def __init__(
        self,
        exception: List[str],
        from_label: Label,
        to_label: Label,
        goto_label: Label,
        exception_ast: Optional[ast.ExceptHandler] = None,
    ):
        """Captures the structural relationship between try/except blocks."""
        self.exception = exception
        self.from_label = from_label
        self.to_label = to_label
        self.goto_label = goto_label
        self.exception_ast = exception_ast

    def __str__(self):
        """Describes the protected region and handler label."""
        return f"catch {self.exception} from {self.from_label} to {self.to_label} with {self.goto_label}"

    def get_ast(self):
        """Returns the original ``ast.ExceptHandler`` if one existed."""
        return self.exception_ast


# goto label
class Goto(IRAbstractStmt):
    """Explicit control-transfer edge inserted when lowering loops."""

    label: Optional[Label]
    #: Destination label patched in a later pass.

    def __init__(self, label: Optional[Label] = None):
        """Initialises a dangling ``goto`` to be patched once labels exist."""
        self.label = label

    def __str__(self):
        """Renders the jump target used in CFG visualisations."""
        return f"goto {self.label.to_s()}"

    def set_label(self, label: Label) -> None:
        """Sets the eventual destination after the enclosing scope is parsed."""
        self.label = label

    def get_ast(self):
        """Synthetic jump nodes have no direct AST representation."""
        return None


# if not test goto label
class JumpIfFalse(IRAbstractStmt):
    """Conditional branch emitted for ``if`` and loop guards."""

    test: ast.expr
    #: Boolean guard evaluated using the TAC-normalised AST.
    label: Label
    #: Destination label executed when ``test`` evaluates to ``False``.
    stmt_ast: Optional[ast.stmt]
    #: Original AST statement that owns the guard.
    load_collector: VarCollector
    #: Tracks free variables referenced by ``test``.

    def __init__(
        self,
        test: ast.expr,
        label: Optional[Label] = None,
        stmt_ast: Optional[ast.stmt] = None,
    ):
        """Captures guard metadata for control-flow reconstruction."""
        self.test = test
        ast.fix_missing_locations(self.test)
        self.load_collector = VarCollector("load")
        self.load_collector.visit(self.test)
        if label is None:
            self.label = Label(-1)
        else:
            self.label = label
        self.stmt_ast = stmt_ast

    def set_label(self, label: Label) -> None:
        """Updates the false successor once the label exists."""
        self.label = label

    def __str__(self):
        """Human-readable ``if not test goto label`` form."""
        test_str = ast.unparse(self.test)
        return f"if not ({test_str}) goto {self.label.to_s()}"

    def get_loads(self) -> Set[str]:
        """Returns variables read solely by the guard expression."""
        return self.load_collector.get_vars()

    def rename(
        self,
        old_name: str,
        new_name: str,
        ctxs: Tuple[Type[ast.AST], ...],
    ) -> None:
        """Renames symbols referenced by ``test``."""
        renamer = RenameTransformer(old_name, new_name, ctxs)
        self.test = renamer.visit(self.test)

    def get_ast(self):
        """Provides the AST node that originated this conditional."""
        return self.stmt_ast


# if test goto label
class JumpIfTrue(IRAbstractStmt):
    """Conditional branch used when the true branch is non-fallthrough."""

    test: ast.expr
    label: Label
    load_collector: VarCollector
    stmt_ast: Optional[ast.stmt]

    def __init__(
        self,
        test: ast.expr,
        label: Label,
        stmt_ast: Optional[ast.stmt] = None,
    ):
        """Captures jump metadata for short-circuiting ``if`` constructs."""
        self.test = test
        ast.fix_missing_locations(self.test)
        self.load_collector = VarCollector("load")
        self.load_collector.visit(self.test)
        self.label = label
        self.stmt_ast = stmt_ast

    def __str__(self):
        """Human-readable ``if test goto label`` form (true edge)."""
        test_str = ast.unparse(self.test)
        return f"if not ({test_str}) goto {self.label.to_s()}"

    def set_label(self, label: Label):
        """Patches the successor once CFG layout is known."""
        self.label = label

    def get_loads(self) -> Set[str]:
        """Returns guard dependencies for use-def chains."""
        return self.load_collector.get_vars()

    def rename(
        self,
        old_name: str,
        new_name: str,
        ctxs: Tuple[Type[ast.AST], ...],
    ) -> None:
        """Renames identifiers referenced by the guard expression."""
        renamer = RenameTransformer(old_name, new_name, ctxs)
        self.test = renamer.visit(self.test)

    def get_ast(self):
        """Returns the AST node that produced this positive jump."""
        return self.stmt_ast


# [target] = yield value
class IRYield(IRAbstractStmt):
    """Represents ``yield`` lowered from generator bodies."""

    stmt: Statement
    #: Either ``ast.Expr`` or ``ast.Assign`` containing the yield.
    value: Optional[ast.Name]
    #: The yielded symbol, normalised by ``ThreeAddressTransformer``.
    load_collector: VarCollector
    #: Records reads pulled in by the awaitable/value expression.
    store_collector: VarCollector
    #: Records names bound by ``target = yield`` forms.
    target: Optional[ast.expr]
    #: Assignment target when the yield appears on RHS.
    _is_yield_from: bool
    #: Flag indicating ``yield from`` semantics.

    def __init__(self, stmt: Statement):
        """Captures generator semantics for downstream CFG consumers."""
        self.stmt = stmt
        assert isinstance(stmt.value, (ast.Yield, ast.YieldFrom))
        self.target = stmt.targets[0] if isinstance(stmt, ast.Assign) else None
        yield_value = stmt.value.value
        assert isinstance(yield_value, ast.Name) or yield_value is None
        self.value = yield_value
        self._is_yield_from = isinstance(self.value, ast.YieldFrom)
        ast.fix_missing_locations(self.stmt)
        self.load_collector = VarCollector("load")
        self.load_collector.visit(self.stmt)
        self.store_collector = VarCollector("store")
        self.store_collector.visit(self.stmt)

    def __str__(self):
        """Displays ``yield`` or ``yield <name>`` for IR dumps."""
        if self.value is not None:
            val_str = ast.unparse(self.value)
            return f"yield {val_str}"
        else:
            return "yield"

    def is_yield_from(self) -> bool:
        """Returns ``True`` when representing ``yield from``."""
        return self._is_yield_from

    def get_loads(self) -> Set[str]:
        """Returns referenced variables within the yield expression."""
        return self.load_collector.get_vars()

    def get_stores(self) -> Set[str]:
        """Returns assignment targets updated by the yield."""
        return self.store_collector.get_vars()

    def rename(
        self,
        old_name: str,
        new_name: str,
        ctxs: Tuple[Type[ast.AST], ...],
    ) -> None:
        """Renames load operands participating in the yield."""
        renamer = RenameTransformer(old_name, new_name, ctxs)
        self.value = renamer.visit(self.value)

    def get_ast(self):
        """Exposes the normalised AST statement for this yield."""
        return self.stmt


# return [value]
class IRReturn(IRAbstractStmt):
    """Represents canonicalised ``return`` statements."""

    value: Optional[ast.Name]
    #: Symbol returned to the caller, or ``None`` for bare ``return``.
    stmt: ast.stmt
    #: Underlying ``ast.Return`` node.
    load_collector: VarCollector
    #: Tracks upstream values needed to produce the return value.

    def __init__(self, stmt: ast.Return):
        """Normalises return value into a plain ``ast.Name`` when present."""
        ast.fix_missing_locations(stmt)
        if stmt.value is not None:
            assert isinstance(stmt.value, ast.Name), "Return value of IR should be ast.Name or None!"
            self.value = stmt.value.id
        else:
            self.value = None
        self.stmt = stmt
        self.load_collector = VarCollector("load")
        self.load_collector.visit(self.stmt)

    def __str__(self):
        """Pretty-prints the ``return`` statement."""
        return ast.unparse(self.stmt)

    def get_loads(self) -> Set[str]:
        """Returns identifiers whose value feeds into the return."""
        return self.load_collector.get_vars()

    def get_value(self) -> Optional[str]:
        """Returns the symbolic name returned to the caller."""
        return self.value

    def rename(
        self,
        old_name: str,
        new_name: str,
        ctxs: Tuple[Type[ast.AST], ...],
    ) -> None:
        """Renames the returned identifier if it matches ``old_name``."""
        renamer = RenameTransformer(old_name, new_name, ctxs)
        self.value = renamer.visit(self.stmt)

    def get_ast(self):
        """Returns the AST representation of this return statement."""
        return self.stmt


# raise exc from cause
class IRRaise(IRAbstractStmt):
    """Normalised ``raise`` statements, preserving optional causes."""

    exc: Optional[ast.expr]
    #: Exception instance being raised.
    cause: Optional[ast.expr]
    #: Optional ``from`` cause to preserve chaining semantics.
    stmt: ast.Raise
    #: Original AST node tracked for location/diagnostics.
    load_collector: VarCollector
    #: Records evaluated expressions required to raise.

    def __init__(self, stmt: ast.Raise):
        """Extracts operands for ``raise`` so SCCP can reason about them."""
        self.stmt = stmt
        ast.fix_missing_locations(self.stmt)
        self.exc = stmt.exc
        self.cause = stmt.cause
        self.load_collector = VarCollector("load")
        self.load_collector.visit(self.stmt)

    def __str__(self):
        """Reconstructs the ``raise`` expression text."""
        return ast.unparse(self.stmt)

    def get_loads(self) -> Set[str]:
        """Returns variable dependencies for the exception and cause."""
        return self.load_collector.get_vars()

    def rename(
        self,
        old_name: str,
        new_name: str,
        ctxs: Tuple[Type[ast.AST], ...],
    ) -> None:
        """Renames identifiers appearing in ``raise`` operands."""
        renamer = RenameTransformer(old_name, new_name, ctxs)
        self.stmt = renamer.visit(self.stmt)
        if self.exc is not None:
            self.exc = renamer.visit(self.exc)
        if self.cause is not None:
            self.cause = renamer.visit(self.cause)

    def get_ast(self):
        """Returns the wrapped ``ast.Raise``."""
        return self.stmt


# pass
class IRPass(IRAbstractStmt):
    """Represents structural ``pass`` placeholders introduced post-lowering."""

    pass_ast: ast.Pass
    #: Real AST node kept for positional fidelity.

    def __init__(self, pass_ast: Optional[ast.Pass] = None):
        """Creates a pass placeholder when synthesising block padding."""
        if pass_ast is None:
            self.pass_ast = ast.Pass()
        else:
            self.pass_ast = pass_ast

    def __str__(self):
        """Always returns ``pass`` for textual dumps."""
        return "pass"

    def get_ast(self):
        """Returns the ``ast.Pass`` used to stand in for missing bodies."""
        return self.pass_ast


# [target] = await value
class IRAwait(IRAbstractStmt):
    """Encodes ``await`` expressions after coroutine lowering."""

    stmt: Statement
    #: AST statement containing the await expression.
    value: ast.expr
    #: Await operand extracted from the statement.
    load_collector: VarCollector
    #: Names read while evaluating the await.
    store_collector: VarCollector
    #: Names written when assigning the awaited value.
    target: Optional[ast.Name]
    #: Assignment target if ``await`` is part of an ``Assign``.

    def __init__(self, stmt: Statement):
        """Normalises await statements for async function IR."""
        self.stmt = stmt
        if isinstance(stmt, ast.Assign):
            assert isinstance(stmt.value, ast.Await)
            self.value = stmt.value.value
            self.target = stmt.targets[0]
        else:
            assert isinstance(stmt.value, ast.Await)
            self.value = stmt.value.value
            self.target = None
        ast.fix_missing_locations(self.stmt)
        self.load_collector = VarCollector("load")
        self.load_collector.visit(self.stmt)
        self.store_collector = VarCollector("store")
        self.store_collector.visit(self.stmt)

    def __str__(self):
        """Returns ``await`` expression text."""
        return ast.unparse(self.stmt)

    def get_target(self) -> Optional[ast.Name]:
        """Returns the assignment target receiving the awaited value."""
        return self.target

    def get_value(self) -> ast.expr:
        """Returns the await operand (already normalised)."""
        return self.value

    def get_loads(self) -> Set[str]:
        """Returns identifiers read while preparing the await."""
        return self.load_collector.get_vars()

    def get_stores(self) -> Set[str]:
        """Returns identifiers written by assigning the await result."""
        return self.store_collector.get_vars()

    def rename(
        self,
        old_name: str,
        new_name: str,
        ctxs: Tuple[Type[ast.AST], ...],
    ) -> None:
        """Renames operands captured by the await expression."""
        renamer = RenameTransformer(old_name, new_name, ctxs)
        self.value = renamer.visit(self.value)

    def get_ast(self):
        """Returns the AST statement representing this await."""
        return self.stmt


# delete value
class IRDel(IRAbstractStmt):
    """Represents single-target ``del`` statements."""

    value: ast.expr
    #: The identifier being deleted.
    del_collector: VarCollector
    #: Collector reused to expose delete-set semantics.

    def __init__(self, stmt: ast.Delete):
        """Records the symbol removed from the current scope."""
        assert len(stmt.targets) == 1
        ast.fix_missing_locations(stmt)
        self.value = stmt.targets[0]
        self.del_collector = VarCollector("del")
        self.del_collector.visit(self.value)

    def __str__(self):
        """Displays ``del`` with the associated symbol."""
        val_str = ast.unparse(self.value)
        return f"del {val_str}"

    def get_dels(self) -> Set[str]:
        """Returns the identifier removed from scope."""
        return self.del_collector.get_vars()

    def get_ast(self):
        return ast.Delete(targets=[self.value])

    def rename(
        self,
        old_name: str,
        new_name: str,
        ctxs: Tuple[Type[ast.AST], ...],
    ) -> None:
        """Renames the deleted target when applicable."""
        renamer = RenameTransformer(old_name, new_name, ctxs)
        self.value = renamer.visit(self.value)

    def get_ast(self):
        """Returns the ``ast.Name`` representing the deleted target."""
        return self.value


# import [module.]name as [asname]
class IRImport(IRAbstractStmt):
    """Represents ``import``/``from`` statements with alias tracking."""

    stmt: Union[ast.Import, ast.ImportFrom]
    #: Backing AST import node in normalised form.
    module: Optional[str]
    #: Module path when handling ``from ... import``.
    name: str
    #: First imported symbol (others handled via ``stmt.names``).
    asname: Optional[str]
    #: Alias applied to the first imported name (if any).
    level: int
    #: Relative import level for ``from`` statements.

    def __init__(self, stmt: Union[ast.Import, ast.ImportFrom]):
        """Captures import metadata for scope bookkeeping."""
        self.stmt = stmt
        if isinstance(stmt, ast.ImportFrom):
            if stmt.module is not None:
                self.module = stmt.module
            else:
                self.module = ""
            self.level = stmt.level
        else:
            self.module = None
            self.level = 0
        self.name = stmt.names[0].name
        self.asname = stmt.names[0].asname

    def __str__(self):
        """Returns the canonical source representation."""
        return ast.unparse(self.stmt)

    def __repr__(self):
        """Keeps debugger output consistent with ``__str__``."""
        return ast.unparse(self.stmt)

    def get_stores(self) -> Set[str]:
        """Returns symbols introduced into the current namespace."""
        stores = {*()}
        for name in self.stmt.names:
            if name.asname is None:
                stores.add(name.name)
            else:
                stores.add(name.asname)
        return stores

    def rename(
        self,
        old_name: str,
        new_name: str,
        ctxs: Tuple[Type[ast.AST], ...],
    ) -> None:
        """Renames alias targets when allowed for ``ast.Store`` contexts."""
        if ast.Store not in ctxs:
            return
        renamer = RenameTransformer(old_name, new_name, ctxs)
        self.stmt = renamer.visit(self.stmt)

    def get_ast(self) -> Union[ast.Import, ast.ImportFrom]:
        """Returns the ``ast`` import node."""
        return self.stmt


# [target] = func_name( args, keywords )
class IRCall(IRAbstractStmt):
    """Captures function call sites in their three-address form."""

    stmt: Union[ast.Assign, ast.Call]
    #: Either the enclosing assignment or the call expression itself.
    call: ast.Call
    #: Normalised call node referenced by helper APIs.
    target: Optional[str]
    #: SSA identifier that stores the result, if present.
    func_name: str
    #: Direct callee name.
    args: List[Tuple[str, bool]]
    #: Positional arguments represented as ``(arg_name, is_starred)``.
    keywords: List[Tuple[Optional[str], str]]
    #: Keyword arguments represented as ``(keyword_name, arg_name)``.
    load_collector: VarCollector
    #: Tracks names read during call evaluation.

    def __init__(self, stmt: Union[ast.Assign, ast.Call]):
        """Stores callee metadata for call graph construction."""
        self.stmt = stmt
        if isinstance(stmt, ast.Assign):
            assert isinstance(stmt.targets[0], ast.Name)
            assert isinstance(stmt.value, ast.Call)
            self.call = stmt.value
            self.target = stmt.targets[0].id
        else:
            assert isinstance(stmt, ast.Call), f"stmt must be an ast.Call, but got {ast.dump(stmt, indent=4)}"
            self.call = stmt
            self.target = None

        assert isinstance(self.call.func, ast.Name), ast.dump(self.call, indent=4)

        self.func_name = self.call.func.id
        self.args = []
        for arg in self.call.args:
            if isinstance(arg, ast.Name):
                self.args.append((arg.id, False))
            elif isinstance(arg, ast.Starred) and isinstance(arg.value, ast.Name):
                self.args.append((arg.value.id, True))
            elif isinstance(arg, ast.Constant):
                self.args.append((f'<Constant: {str(arg.value)}>', False))
            else:
                raise AssertionError("Args in function call should be Name or Starred[Name]")
        self.keywords = []
        for kw in self.call.keywords:
            assert isinstance(kw.value, ast.Name), "Keywords in function call should be Name"
            if kw.arg is None:
                self.keywords.append((None, kw.value.id))
            else:
                self.keywords.append((kw.arg, kw.value.id))
        self.load_collector = VarCollector("load")
        self.load_collector.visit(self.stmt)

    def __str__(self):
        """Returns the reconstructed call text."""
        return ast.unparse(self.stmt)

    def get_func_name(self) -> str:
        """Returns the direct callee name."""
        return self.func_name

    def get_args(self) -> List[Tuple[str, bool]]:
        """Returns (name, is_starred) pairs for positional args."""
        return self.args

    def get_keywords(self) -> List[Tuple[Optional[str], str]]:
        """Returns keyword bindings represented in the call."""
        return self.keywords

    def get_loads(self) -> Set[str]:
        """Returns all symbols referenced by the call expression."""
        return self.load_collector.get_vars()

    def get_target(self) -> Optional[str]:
        """Returns the SSA target receiving the call result, if any."""
        return self.target

    def get_stores(self) -> Set[str]:
        """Returns the single assignment target or an empty set."""
        if self.target is not None:
            return {self.target}
        else:
            return {*()}

    def rename(
        self,
        old_name: str,
        new_name: str,
        ctxs: Tuple[Type[ast.AST], ...],
    ) -> None:
        """Renames operands across the full call expression."""
        renamer = RenameTransformer(old_name, new_name, ctxs)
        self.stmt = renamer.visit(self.stmt)

    def get_ast(self) -> ast.Call:
        """Returns the ``ast`` node representing the call."""
        return self.stmt


# target: anno
class IRAnno(IRAbstractStmt):
    """Represents annotated assignments maintained for type hints."""

    target: ast.expr
    #: The assignment target receiving the annotation.
    anno: ast.expr
    #: The annotation expression.
    stmt: Statement
    #: Underlying ``ast.AnnAssign`` node.
    store_collector: VarCollector
    #: Tracks definitions introduced by the target.
    load_collector: VarCollector
    #: Tracks references required by the annotation expression.

    def __init__(self, stmt: ast.AnnAssign):
        """Initialises collector state for the provided annotation."""
        self.set_stmt(stmt)

    def __str__(self):
        """Returns ``target : annotation`` for readability."""
        tgt_str = ast.unparse(self.target)
        ann_str = ast.unparse(self.anno)
        return f"{tgt_str} : {ann_str}"

    def set_stmt(self, stmt: ast.AnnAssign):
        """Rebinds to a new ``AnnAssign`` node. [side effects: resets collectors and cached AST nodes]"""
        self.target = stmt.target
        self.anno = stmt.annotation
        self.stmt = stmt
        ast.fix_missing_locations(self.stmt)
        self.collector_reset()
        self.collect_from_stmt(stmt)

    def get_ast(self) -> Statement:
        """Returns the annotation AST."""
        return self.stmt

    def get_target(self) -> ast.expr:
        """Returns the annotated target expression."""
        return self.target

    def get_anno(self) -> ast.expr:
        """Returns the annotation payload."""
        return self.anno

    def collector_reset(self):
        """Initialises collectors before visiting a new statement."""
        self.store_collector = VarCollector("store")
        self.load_collector = VarCollector("load")

    def collect_from_stmt(self, stmt: Statement):
        """Collects store/load effects from the target/annotation."""
        self.store_collector.visit(self.target)
        self.load_collector.visit(self.anno)

    def get_stores(self) -> Set[str]:
        """Returns identifiers introduced by the annotation's target."""
        return self.store_collector.get_vars()

    def get_loads(self) -> Set[str]:
        """Returns identifiers referenced by the annotation expression."""
        return self.load_collector.get_vars()

    def rename(
        self,
        old_name: str,
        new_name: str,
        ctxs: Tuple[Type[ast.AST], ...],
    ) -> None:
        """Renames either the target or the annotation based on ctx."""
        renamer = RenameTransformer(old_name, new_name, ctxs)
        self.stmt = renamer.visit(self.stmt)
        if isinstance(ast.Load(), ctxs):
            self.anno = renamer.visit(self.anno)
        if isinstance(ast.Store(), ctxs):
            self.target = renamer.visit(self.target)


class AbstractIRAssign(IRAbstractStmt):
    """Common scaffolding for single-target assignments emitted by TAC."""

    lval: ast.expr
    #: Left-hand side produced by ``resolve_single_Assign``.
    rval: ast.expr
    #: Right-hand side expression after TAC lowering.
    stmt: Statement
    #: Backing ``ast.Assign`` node.
    store_collector: VarCollector
    #: Tracks bound identifiers.
    load_collector: VarCollector
    #: Tracks referenced identifiers.

    @abstractmethod
    def __init__(self, stmt: ast.Assign):
        """Ensures assignments are already simplified by ThreeAddress."""
        assert len(stmt.targets) == 1, "IRAssign only supports single target assignment"
        self.set_stmt(stmt)

    def __str__(self):
        """Returns ``lval = rval`` textual form."""
        lstr = ast.unparse(self.lval)
        rstr = ast.unparse(self.rval)
        return f"{lstr} = {rstr}"

    def set_stmt(self, stmt: ast.Assign):
        """Rebinds the assignment operands. [side effects: resets collectors and rewrites cached AST]"""
        self.lval = stmt.targets[0]
        self.rval = stmt.value
        self.stmt = stmt
        ast.fix_missing_locations(self.stmt)
        self.collector_reset()
        self.collect_from_stmt(stmt)

    def get_ast(self) -> Statement:
        """Returns the ``ast.Assign`` associated with this IR node."""
        return self.stmt

    def get_lval(self) -> ast.expr:
        """Returns the left-hand side expression."""
        return self.lval

    def get_rval(self) -> ast.expr:
        """Returns the right-hand side expression."""
        return self.rval

    def collector_reset(self):
        """Initialises collectors before rescanning operands."""
        self.store_collector = VarCollector("store")
        self.load_collector = VarCollector("load")

    def collect_from_stmt(self, stmt: Statement):
        """Recomputes the store/load sets."""
        self.store_collector.visit(self.lval)
        self.load_collector.visit(self.rval)

    def get_stores(self) -> Set[str]:
        """Returns identifiers defined by the assignment."""
        return self.store_collector.get_vars()

    def get_loads(self) -> Set[str]:
        """Returns identifiers referenced by the RHS."""
        return self.load_collector.get_vars()

    def rename(
        self,
        old_name: str,
        new_name: str,
        ctxs: Tuple[Type[ast.AST], ...],
    ) -> None:
        """Renames operands based on the contexts provided."""
        renamer = RenameTransformer(old_name, new_name, ctxs)
        self.stmt = renamer.visit(self.stmt)
        if isinstance(ast.Load(), ctxs):
            self.rval = renamer.visit(self.rval)
        if isinstance(ast.Store(), ctxs):
            self.lval = renamer.visit(self.lval)


# lval = ...
class IRAssign(AbstractIRAssign):
    """Generic SSA assignment ``name = expr``."""

    lval: ast.Name
    stmt: Statement
    store_collector: VarCollector
    load_collector: VarCollector

    def __init__(self, stmt: ast.Assign):
        """Validates that TAC already reduced the LHS to ``ast.Name``."""
        assert isinstance(stmt.targets[0], ast.Name)
        self.set_stmt(stmt)

    def get_lval(self) -> ast.Name:
        """Returns the SSA target."""
        return self.lval


# lval = rval
class IRCopy(AbstractIRAssign):
    """Represents ``x = y`` copies used during SSA phi placement."""

    lval: ast.Name
    rval: ast.Name
    stmt: Statement
    store_collector: VarCollector
    load_collector: VarCollector

    def __init__(self, stmt: ast.Assign):
        """Ensures both operands are already ``ast.Name`` values."""
        assert isinstance(stmt.targets[0], ast.Name)
        assert isinstance(stmt.value, ast.Name)
        self.set_stmt(stmt)

    def get_lval(self) -> ast.Name:
        """Returns the copy destination."""
        return self.lval

    def get_rval(self) -> ast.Name:
        """Returns the copy source."""
        return self.rval


# lval (obj.attr) = rval
class IRStoreAttr(AbstractIRAssign):
    """Represents attribute stores ``obj.attr = name``."""

    rval: ast.Name
    #: Value assigned into the attribute.
    obj: ast.Name
    #: Object receiving the attribute update.
    attr: str
    #: Attribute name being written.

    def __init__(self, stmt: ast.Assign):
        """Captures object/attribute metadata for store statements."""
        super().__init__(stmt)

        target = stmt.targets[0]
        assert isinstance(target, ast.Attribute)
        assert isinstance(target.value, ast.Name)
        assert isinstance(stmt.value, ast.Name)
        self.obj = target.value
        self.attr = target.attr

    def get_rval(self) -> ast.Name:
        """Returns the assigned name."""
        return self.rval

    def get_obj(self) -> ast.Name:
        """Returns the receiver object."""
        return self.obj

    def get_attr(self) -> str:
        """Returns the attribute name."""
        return self.attr


# lval = rval( obj.attr )
class IRLoadAttr(AbstractIRAssign):
    """Represents attribute loads ``tmp = obj.attr``."""

    lval: ast.Name
    #: SSA temp capturing the attribute value.
    obj: ast.Name
    #: Object whose attribute is being read.
    attr: str
    #: Attribute name.

    def __init__(self, stmt: ast.Assign):
        """Captures object/attribute metadata for load statements."""
        super().__init__(stmt)

        assert isinstance(stmt.targets[0], ast.Name)
        assert isinstance(stmt.value, ast.Attribute)
        assert isinstance(stmt.value.value, ast.Name)
        self.obj = stmt.value.value
        self.attr = stmt.value.attr

    def get_lval(self) -> ast.Name:
        """Returns the SSA temp receiving the attribute."""
        return self.lval

    def get_obj(self) -> ast.Name:
        """Returns the object whose attribute is read."""
        return self.obj

    def get_attr(self) -> str:
        """Returns the attribute accessed."""
        return self.attr


# lval< obj[slice] > = rval
class IRStoreSubscr(AbstractIRAssign):
    """Represents ``obj[idx] = name`` stores."""

    lval: ast.Subscript
    #: Subscript expression present on the LHS.
    rval: ast.Name
    #: Value stored into the container.
    obj: ast.Name
    #: Container name.
    subslice: Union[ast.Slice, ast.Name]
    #: Slice/index used on the container.

    def __init__(self, stmt: ast.Assign):
        """Captures subscription metadata for store statements."""
        super().__init__(stmt)

        target = stmt.targets[0]
        assert isinstance(target, ast.Subscript)
        assert isinstance(target.value, ast.Name)
        assert isinstance(target.slice, ast.Slice) or isinstance(target.slice, ast.Name)
        assert isinstance(stmt.value, ast.Name)
        self.obj = target.value
        self.subslice = target.slice

    def get_rval(self) -> ast.Name:
        """Returns the value stored into the subscription."""
        return self.rval

    def get_obj(self) -> ast.Name:
        """Returns the container being mutated."""
        return self.obj

    def get_slice(self) -> Union[ast.Slice, ast.Name]:
        """Returns the index/slice expression."""
        return self.subslice

    def has_slice(self) -> bool:
        """Returns ``True`` if the subscript uses a slice expression."""
        return isinstance(self.subslice, ast.Slice) or isinstance(self.subslice, ast.Name)


# lval = rval< obj[slice] >
class IRLoadSubscr(AbstractIRAssign):
    """Represents ``tmp = obj[idx]`` loads."""

    lval: ast.Name
    #: SSA temp capturing the load result.
    rval: ast.Subscript
    #: Subscript expression moved to the RHS.
    obj: ast.Name
    #: Container name.
    subslice: Union[ast.Slice, ast.Name]
    #: Slice/index used for the lookup.

    def __init__(self, stmt: ast.Assign):
        """Captures subscription metadata for load statements."""
        super().__init__(stmt)

        assert isinstance(stmt.targets[0], ast.Name)
        value = stmt.value
        assert isinstance(value, ast.Subscript)
        assert isinstance(value.value, ast.Name)
        assert isinstance(value.slice, ast.Slice) or isinstance(value.slice, ast.Name)
        self.obj = value.value
        self.slice = value.slice

    def get_lval(self) -> ast.Name:
        """Returns the SSA temp capturing the subscript result."""
        return self.lval

    def get_obj(self) -> ast.expr:
        """Returns the container whose element is read."""
        return self.obj

    def get_slice(self) -> ast.expr:
        """Returns the index or slice expression."""
        return self.slice

    def has_slice(self) -> bool:
        """Returns ``True`` if ``slice`` is an ``ast.Slice``."""
        return isinstance(self.slice, ast.Slice) or isinstance(self.slice, ast.Name)


# lval = Phi( items )
class IRPhi(AbstractIRAssign):
    """SSA phi node tying together predecessors' values."""

    lval: ast.Name
    #: Variable defined by the phi node.
    items: List[Optional[ast.Name]]
    #: Incoming candidate values ordered per predecessor.
    store_collector: VarCollector
    #: Tracks the phi's definition site.
    load_collector: VarCollector
    #: Tracks the phi's inbound operands.

    def __init__(self, lval: ast.Name, items: List[Optional[ast.Name]]):
        """Synthesises an ``ast.Assign`` that encodes Phi semantics."""
        stmt = self._get_phi_expr(lval, items)
        super().__init__(stmt)

    def get_lval(self) -> ast.Name:
        """Returns the SSA name defined by the phi."""
        return self.lval

    def get_items(self) -> List[Optional[ast.Name]]:
        """Returns candidate incoming values (one per predecessor)."""
        return self.items

    def __str__(self):
        """Shows ``x = Phi(a, b, ...)`` in dumps."""
        item_str = ", ".join([f"{item.id}" if item is not None else "None" for item in self.items])
        return f"{self.lval} = Phi({item_str})"

    def _get_phi_expr(self, lval: ast.Name, items: List[Optional[ast.Name]]) -> ast.Assign:
        """Constructs a fake AST call ``Phi([...])`` for compatibility."""
        args = ast.List(elts=[ast.Name(id=item.id) if item is not None else ast.Name(id="None") for item in items], ctx=ast.Load())
        phi_expr = ast.Call(func=ast.Name(id="Phi", ctx=ast.Load()), args=args, keywords=[])
        stmt = ast.Assign(targets=[lval], value=phi_expr)
        ast.set_location(stmt, lval.lineno, lval.col_offset)
        ast.fix_missing_locations(stmt)
        return stmt

    def rename(
        self,
        old_name: str,
        new_name: str,
        ctxs: Tuple[Type[ast.AST], ...],
    ) -> None:
        """Renames both the phi target and its incoming operands."""
        renamer = RenameTransformer(old_name, new_name, ctxs)
        self.stmt = renamer.visit(self.stmt)
        if isinstance(ast.Load(), ctxs):
            self.rval = renamer.visit(self.rval)
            for idx in range(len(self.items)):
                if self.items[idx] is not None:
                    self.items[idx] = renamer.visit(self.items[idx])
        if isinstance(ast.Store(), ctxs):
            self.lval = renamer.visit(self.lval)


class IRScope(ABC):
    """Base scope metadata shared by modules, classes, and functions."""

    qualname: str
    #: Dotted path identifying the scope (e.g. ``pkg.mod.Class.fn``).
    global_vars: Set[str]
    #: Names declared with ``global`` in this scope.
    nonlocal_vars: Set[str]
    #: Names declared ``nonlocal`` to reach outer but non-global scopes.
    cell_vars: Set[str]
    #: Names lifted into closure cells for nested functions.

    @abstractmethod
    def __init__(self, qualname: str):
        """Initialises bookkeeping sets shared by scope implementations."""
        self.qualname = qualname
        self.global_vars = set()
        self.nonlocal_vars = set()
        self.cell_vars = set()

    def get_qualname(self) -> str:
        """Returns the fully-qualified scope name."""
        return self.qualname

    def add_global_var(self, var: str):
        """Registers a ``global`` declaration visible in this scope."""
        self.global_vars.add(var)

    def add_nonlocal_var(self, var: str):
        """Registers a ``nonlocal`` declaration for closure analysis."""
        self.nonlocal_vars.add(var)

    def add_cell_var(self, var: str):
        """Marks a variable as lifted into a closure cell."""
        self.cell_vars.add(var)

    def get_global_vars(self) -> Set[str]:
        """Returns names declared ``global``."""
        return self.global_vars

    def get_nonlocal_vars(self) -> Set[str]:
        """Returns names declared ``nonlocal``."""
        return self.nonlocal_vars

    def get_cell_vars(self) -> Set[str]:
        """Returns names captured into closure cells."""
        return self.cell_vars


class IRModule(IRScope, IRStatement):
    """Top-level scope representing a parsed Python module."""

    name: str
    #: Importable module name (``pkg.mod``).
    filename: str
    #: Filesystem path for diagnostics.
    stmt: Module
    #: Parsed module AST.

    def __init__(self, qualname: str, module: Module, name: str = "", filename: Optional[str] = None):
        """Stores parsed module metadata for later IR passes."""
        super().__init__(qualname)
        self.name = name
        if filename is None:
            self.filename = "None"
        else:
            self.filename = filename
        self.stmt = module

    def get_name(self) -> str:
        """Returns the import-style string shown in dumps."""
        return f'<module \'{self.name}\' from \'{self.filename}\'>'

    def get_filename(self) -> str:
        """Returns the module's filesystem path when available."""
        return self.filename

    def get_ast(self) -> Module:
        """Returns the module AST."""
        return self.stmt

    def get_stores(self) -> Set[str]:
        """Modules do not directly report stores at this layer."""
        return {*()}

    def get_loads(self) -> Set[str]:
        """Modules do not directly report loads at this layer."""
        return {*()}

    def get_dels(self) -> Set[str]:
        """Modules do not have delete semantics at this layer."""
        return {*()}

    def __str__(self) -> str:
        return self.get_name()

    def __repr__(self) -> str:
        return self.get_name()

    @classmethod
    def load_module(cls, name: str, filename: str, content: Optional[str] = None) -> 'IRModule':
        """Parses raw source and wraps it in an ``IRModule``."""
        if content is None:
            with open(filename, 'r') as f:
                content = f.read()
        mod_ast = ast.parse(content, filename)
        mod = cls(mod_ast, name=name, filename=filename)
        return mod


class IRFunc(IRScope, IRStatement):
    """Scope wrapper for ``FunctionDef`` / ``AsyncFunctionDef`` nodes."""

    name: str
    #: Function identifier.
    args: ast.arguments
    #: Canonical argument signature.
    arg_names: Set[str]
    #: Convenience set of parameter names.
    decorator_list: List[ast.expr]
    #: Applied decorators (order preserved).
    returns: ast.expr
    #: Return annotation.
    type_comment: str
    #: Optional type comment string.
    stmt: ast.stmt
    #: Underlying AST node.
    is_async: bool
    #: Indicates ``async def``.
    is_getter: bool
    #: Indicates ``@property``.
    is_setter: bool
    #: Indicates ``@x.setter``.
    is_static_method: bool
    #: Indicates ``@staticmethod``.
    is_class_method: bool
    #: Indicates ``@classmethod``.
    is_instance_method: bool
    #: True when representing a bound instance method.

    cell_vars: Set[str]
    #: Variables captured by nested scopes.
    nonlocal_vars: Set[str]
    #: ``nonlocal`` declarations inside the function.
    global_vars: Set[str]
    #: ``global`` declarations inside the function.

    def __init__(
        self,
        qualname: str,
        fn: Union[ast.FunctionDef, ast.AsyncFunctionDef],
        cell_vars: Optional[Set[str]] = None,
        is_method: bool = False,
    ):
        super().__init__(qualname)
        self.name = fn.name
        self.args = fn.args
        self.arg_names = set()
        for arg in fn.args.args:
            self.arg_names.add(arg.arg)
        for arg in fn.args.kwonlyargs:
            self.arg_names.add(arg.arg)
        if fn.args.vararg:
            self.arg_names.add(fn.args.vararg.arg)
        if fn.args.kwarg:
            self.arg_names.add(fn.args.kwarg.arg)

        self.decorator_list = fn.decorator_list
        self.is_static_method = self.is_class_method = self.is_setter = self.is_getter = False
        for decr in fn.decorator_list:
            if isinstance(decr, ast.Name):
                if decr.id == 'staticmethod':
                    self.is_static_method = True
                elif decr.id == 'classmethod':
                    self.is_class_method = True
                elif decr.id == 'property':
                    self.is_getter = True
            elif isinstance(decr, ast.Attribute):
                if decr.attr == 'setter':
                    self.is_setter = True
        self.is_instance_method = (is_method and not self.is_static_method and not self.is_class_method)
        self.returns = fn.returns
        self.type_comment = fn.type_comment
        self.stmt = fn
        self.is_async = isinstance(fn, ast.AsyncFunctionDef)
        if cell_vars:
            self.cell_vars = cell_vars

    def get_ast(self) -> ast.stmt:
        """Returns the ``ast.FunctionDef`` / ``AsyncFunctionDef``."""
        return self.stmt

    def set_cell_vars(self, cell_vars: Set[str]) -> None:
        """Replaces the captured cell-var set when closure info updates."""
        self.cell_vars = cell_vars

    def add_cell_var(self, cell_var: str) -> None:
        """Adds a variable to the closure cell set."""
        self.cell_vars.add(cell_var)

    def get_stores(self) -> Set[str]:
        """Functions do not emit stores at the scope node level."""
        return {*()}

    def get_loads(self) -> Set[str]:
        """Returns captured cell vars consumed by inner scopes."""
        return self.cell_vars

    def get_dels(self) -> Set[str]:
        """Functions do not emit deletes at the scope node level."""
        return {*()}

    def get_name(self) -> str:
        """Returns a descriptive function/async-function label."""
        if self.is_async:
            return f'<async function {self.name}>'
        else:
            return f'<function {self.name}>'

    def get_arg_names(self) -> Set[str]:
        """Returns the set of argument names for var liveness tracking."""
        return self.arg_names

    def __repr__(self) -> str:
        """Detailed signature string used in debugging output."""
        decrs = ', '.join([ast.unparse(decr) for decr in self.decorator_list])
        args = ast.unparse(self.args)
        if self.returns is not None:
            rets = f' -> {ast.unparse(self.returns)}'
        else:
            rets = ''
        if len(decrs) > 0:
            fn_repr = f'fn [{decrs}] {self.name}({args}){rets}'
        else:
            fn_repr = f'fn {self.name}({args}){rets}'
        if self.is_async:
            fn_repr = f'async {fn_repr}'
        return fn_repr

    def __str__(self):
        """Uses ``__repr__`` for consistency."""
        return self.__repr__()


class IRClass(IRScope, IRStatement):
    """Scope wrapper for ``ClassDef`` nodes used by IRTransformer."""

    name: str
    #: Class identifier.
    bases: List[ast.expr]
    #: Base expressions supplied to the class definition.
    keywords: List[ast.keyword]
    #: Keyword arguments used in the class definition call.
    decorator_list: List[ast.expr]
    #: Decorators applied to the class.
    stmt: ast.ClassDef
    #: Underlying AST node.

    cell_vars: Set[str]
    #: Variables shared with nested scopes via closure cells.

    def __init__(self, qualname: str, cls: ClassDef, cell_vars: Optional[Set[str]] = None):
        """Captures base/keyword/decorator metadata for this class."""
        super().__init__(qualname)
        self.name = cls.name
        assert all(isinstance(i, ast.Name) for i in cls.bases), f"Base of the class should be ast.Name, {cls.bases} got!"
        self.bases = cls.bases
        self.keywords = cls.keywords
        self.decorator_list = cls.decorator_list
        self.stmt = cls
        if cell_vars is None:
            self.cell_vars = {*()}
        else:
            self.cell_vars = cell_vars

    def set_cell_vars(self, cell_vars: Set[str]) -> None:
        """Replaces the set of closure cell vars for nested scopes."""
        self.cell_vars = cell_vars

    def add_cell_var(self, cell_var: str) -> None:
        """Adds a class-scoped variable captured by nested functions."""
        self.cell_vars.add(cell_var)

    def get_ast(self) -> ClassDef:
        """Returns the ``ast.ClassDef`` backing this IR node."""
        return self.stmt

    def get_stores(self) -> Set[str]:
        """Classes do not expose direct store info at this node."""
        return {*()}

    def get_loads(self) -> Set[str]:
        """Classes do not expose direct load info at this node."""
        return {*()}

    def get_dels(self) -> Set[str]:
        """Classes do not expose delete info at this node."""
        return {*()}

    def get_bases(self) -> List[ast.Name]:
        """Returns the base expressions declared on the class."""
        return self.bases

    def get_definitely_declared_names(self) -> Set[str]:
        """Return names present on every normal exit from the class body."""

        def target_names(target: ast.expr) -> Set[str]:
            if isinstance(target, ast.Name):
                return {target.id}
            if isinstance(target, (ast.Tuple, ast.List)):
                return set().union(*(target_names(item) for item in target.elts))
            return set()

        def analyze_block(
            statements: list[ast.stmt], incoming: Set[str]
        ) -> Set[str]:
            present = set(incoming)
            for statement in statements:
                if isinstance(
                    statement,
                    (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
                ):
                    present.add(statement.name)
                elif isinstance(statement, ast.Assign):
                    for target in statement.targets:
                        present.update(target_names(target))
                elif isinstance(statement, ast.AnnAssign):
                    if statement.value is not None:
                        present.update(target_names(statement.target))
                elif isinstance(statement, ast.AugAssign):
                    present.update(target_names(statement.target))
                elif isinstance(statement, ast.Delete):
                    for target in statement.targets:
                        present.difference_update(target_names(target))
                elif isinstance(statement, ast.If):
                    body = analyze_block(statement.body, present)
                    alternative = analyze_block(statement.orelse, present)
                    present = body & alternative
                elif isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
                    body = analyze_block(statement.body, present)
                    alternative = analyze_block(statement.orelse, present)
                    present &= body & alternative
                elif isinstance(statement, (ast.With, ast.AsyncWith)):
                    body = analyze_block(statement.body, present)
                    # An arbitrary __exit__ may suppress an exception raised
                    # before a later binding in the body.  Such a binding is
                    # therefore not guaranteed after the with statement.
                    present &= body
                elif isinstance(statement, ast.Try):
                    exits = [analyze_block(statement.body, present)]
                    exits.extend(
                        analyze_block(handler.body, present)
                        for handler in statement.handlers
                    )
                    if statement.orelse:
                        exits[0] = analyze_block(statement.orelse, exits[0])
                    present = set.intersection(*exits) if exits else present
                    present = analyze_block(statement.finalbody, present)
                elif isinstance(statement, ast.Match):
                    exits = [
                        analyze_block(case.body, present)
                        for case in statement.cases
                    ]
                    # A match need not select a case.
                    exits.append(present)
                    present = set.intersection(*exits)
            return present

        return analyze_block(self.stmt.body, set())

    def __repr__(self) -> str:
        """Displays decorators, bases, and keywords for the class."""
        decrs = ', '.join([ast.unparse(decr) for decr in self.decorator_list])
        bases = ', '.join([ast.unparse(base) for base in self.bases])
        kws = ', '.join([ast.unparse(kw) for kw in self.keywords])
        if len(decrs) > 0:
            cls_repr = f'class [{decrs}] {self.name}'
        else:
            cls_repr = f'class {self.name}'
        if len(bases) > 0:
            if len(kws) > 0:
                cls_repr = f'{cls_repr}({bases}, {kws})'
            else:
                cls_repr = f'{cls_repr}({bases})'
        elif len(kws) > 0:
            cls_repr = f'{cls_repr}({kws})'
        return cls_repr

    def __str__(self) -> str:
        """Uses ``__repr__`` for debugger-friendly dumps."""
        return self.__repr__()

    def get_name(self) -> str:
        """Returns ``<class X>`` for readability."""
        return f'<class {self.name}>'
