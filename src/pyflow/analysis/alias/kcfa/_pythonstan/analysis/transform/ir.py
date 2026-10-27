from ast import *
import ast
from typing import List, Dict, Optional, Any, Union

from ..analysis import AnalysisConfig
from .transform import Transform
from pyflow.analysis.alias.kcfa._pythonstan.world import World
from pyflow.analysis.alias.kcfa._pythonstan.ir import *

__all__ = ["STAGE_NAME", "IR", "IRTransformer"]
STAGE_NAME = "ir"


class IR(Transform):
    transformer: "IRTransformer"

    def __init__(self, config: AnalysisConfig):
        super().__init__(config)

    def transform(self, module: IRModule):
        three_address_form = World().scope_manager.get_ir(module, "three address form")
        self.transformer = IRTransformer(module)
        self.transformer.process_stmts(three_address_form.body)
        ir = self.transformer.stmts
        World().scope_manager.set_ir(module, STAGE_NAME, ir)
        World().scope_manager.set_ir(module, "imports", self.transformer.get_imports())
        # self.results = imports


class LabelGenerator:
    next_idx: int

    def __init__(self):
        self.next_idx = 0

    def gen(self) -> Label:
        label = Label(self.next_idx)
        self.next_idx += 1
        return label


class IRTransformer(NodeVisitor):
    imports: List[IRImport]
    stmts: List[IRStatement]
    funcs: List[IRFunc]
    classes: List[IRClass]
    breaks_stack: List[List[Goto]]
    continues_stack: List[List[Goto]]
    next_idx: int
    scope: IRScope
    label_gen: LabelGenerator

    def __init__(self, scope: IRScope):
        self.scope = scope
        self.reset()

    def reset(self):
        self.breaks_stack = []
        self.continues_stack = []
        self.imports = []
        self.classes = []
        self.stmts = []
        self.funcs = []
        self.label_gen = LabelGenerator()
        self.tmp_idx = 0

    def _new_temporary(self, prefix: str) -> str:
        """Return a fresh ``$``-prefixed temporary for lowering helpers."""
        self.tmp_idx += 1
        return f"${prefix}_{self.tmp_idx}"

    def _emit_assign(self, target, value, location) -> None:
        """Emit ``target = value`` through the normal assignment dispatch."""
        assign = ast.Assign(targets=[target], value=value)
        ast.copy_location(assign, location)
        self.visit_Assign(assign)

    def visit_stmts(self, stmts: List[stmt]):
        for stmt in stmts:
            self.visit(stmt)

    def get_imports(self) -> List[IRImport]:
        return self.imports

    def get_stmts(self) -> List[IRStatement]:
        return self.stmts

    def postprocess(self):
        self.dedumplicate_nop()

    def dedumplicate_nop(self):
        del_list = []
        for stmt, next_stmt in zip(self.stmts, self.stmts[1:]):
            if isinstance(stmt, IRPass) and not isinstance(next_stmt, Label):
                del_list.append(stmt)
        for stmt in del_list:
            self.stmts.remove(stmt)

    def process_stmts(self, stmts: List[stmt]):
        self.orig_stmts = stmts

        self.reset()
        self.visit_stmts(stmts)
        self.postprocess()

    def visit_FunctionDef(self, func_def: Union[FunctionDef, AsyncFunctionDef]):
        qualname = f"{self.scope.get_qualname()}.{func_def.name}"
        func = IRFunc(qualname, func_def, is_method=isinstance(self.scope, IRClass))
        trans = IRTransformer(func)
        trans.process_stmts(func_def.body)
        World().scope_manager.add_class(self.scope, func)
        World().scope_manager.set_ir(func, "ir", trans.get_stmts())
        # Import statements inside a function still resolve relative to the
        # module namespace and must be part of the module's import graph.
        self.imports.extend(trans.get_imports())
        self.stmts.append(func)

    def visit_ClassDef(self, cls_def: ClassDef):
        qualname = f"{self.scope.get_qualname()}.{cls_def.name}"
        cls = IRClass(qualname, cls_def)
        trans = IRTransformer(cls)
        trans.process_stmts(cls_def.body)
        World().scope_manager.add_class(self.scope, cls)
        World().scope_manager.set_ir(cls, "ir", trans.get_stmts())
        self.imports.extend(trans.get_imports())
        self.stmts.append(cls)

    def visit_AsyncFunctionDef(self, node: AsyncFunctionDef):
        self.visit_FunctionDef(node)

    def visit_Break(self, node: Break):
        assert len(self.breaks_stack) > 0
        stmt = Goto()
        self.breaks_stack[-1].append(stmt)
        self.stmts.append(stmt)

    def visit_Continue(self, node: Continue):
        assert len(self.continues_stack) > 0
        stmt = Goto()
        self.continues_stack[-1].append(stmt)
        self.stmts.append(stmt)

    def visit_Return(self, node: Return):
        stmt = IRReturn(node)
        self.stmts.append(stmt)

    def visit_Import(self, node: Import):
        stmt = IRImport(node)
        self.imports.append(stmt)
        self.stmts.append(stmt)

    def visit_ImportFrom(self, node: ImportFrom):
        stmt = IRImport(node)
        self.imports.append(stmt)
        self.stmts.append(stmt)

    def visit_Global(self, node: Global):
        for name in node.names:
            self.scope.add_global_var(name)

    def visit_Nonlocal(self, node: Nonlocal):
        for name in node.names:
            self.scope.add_nonlocal_var(name)

    def visit_While(self, node: While):
        self.breaks_stack.append([])
        self.continues_stack.append([])

        label_begin = self.label_gen.gen()
        self.stmts.append(label_begin)
        self.stmts.append(IRPass())
        cond_jmp = JumpIfFalse(test=node.test, stmt_ast=node)
        self.stmts.append(cond_jmp)
        self.visit_stmts(node.body)
        loop_breaks = self.breaks_stack.pop()
        loop_continues = self.continues_stack.pop()
        absolute_jmp = Goto()
        absolute_jmp.set_label(label_begin)
        self.stmts.append(absolute_jmp)

        if node.orelse is not None and len(node.orelse) > 0:
            label_orelse = self.label_gen.gen()
            self.stmts.append(label_orelse)
            self.stmts.append(IRPass())
            cond_jmp.set_label(label_orelse)
            self.visit_stmts(node.orelse)
            label_end = self.label_gen.gen()
            self.stmts.append(label_end)
            self.stmts.append(IRPass())
        else:
            label_end = self.label_gen.gen()
            self.stmts.append(label_end)
            self.stmts.append(IRPass())
            cond_jmp.set_label(label_end)

        for stmt in loop_breaks:
            stmt.set_label(label_end)
        for stmt in loop_continues:
            stmt.set_label(label_begin)

    def visit_If(self, node: If):
        cond_jmp = JumpIfFalse(test=node.test, stmt_ast=node)
        self.visit_stmts(node.body)
        if len(node.orelse) > 0:
            true_end_jmp = Goto()
            self.stmts.append(true_end_jmp)
            label_else = self.label_gen.gen()
            self.stmts.append(label_else)
            self.stmts.append(IRPass())
            self.visit_stmts(node.orelse)
            label_end = self.label_gen.gen()
            self.stmts.append(label_end)
            self.stmts.append(IRPass())
            cond_jmp.set_label(label_else)
            true_end_jmp.set_label(label_end)
        else:
            label_end = self.label_gen.gen()
            self.stmts.append(label_end)
            self.stmts.append(IRPass())
            cond_jmp.set_label(label_end)

    def visit_Raise(self, node: Raise):
        stmt = IRRaise(node)
        self.stmts.append(stmt)

    """
    try:
  exec()
except E1 as e:
  e1()
excpet E2 as e:
  e2()
else:
  els()
finally: 
  fin()


label_try:
  exec()
  goto else
label_catch:
   catch E1 from label_try to label_catch with label_E1
   catch E2 from label_try to label_catch with label_E2

label_E1:
  e = @exception

  e1()

  del e
  goto fin
label_E2:
  e = @exception

  e2()

  del e
  goto fin
label_else:
  els()
  goto fin

catch Exception from to label_try with label_catch with label_fin
label_fin:
   fin()

    """

    # TODO refine the handling of the exception expression, eg., try a.b.E: ...
    def visit_Try(self, node: Try):
        label_try = self.label_gen.gen()
        self.stmts.append(label_try)
        self.stmts.append(IRPass())
        self.visit_stmts(node.body)
        try_goto = Goto()
        self.stmts.append(try_goto)
        goto_fin_list = [try_goto]
        label_catch = self.label_gen.gen()
        self.stmts.append(label_catch)
        self.stmts.append(IRPass())

        catch_idx = len(self.stmts)
        for expt in node.handlers:
            label_e = self.label_gen.gen()
            self.stmts.append(label_e)
            self.stmts.append(IRPass())
            if expt.name is not None:
                e_ass_stmt = Assign(
                    targets=[Name(id=expt.name, ctx=Store())],
                    value=Name(id="@caught_except", ctx=Load()),
                )
                copy_location(e_ass_stmt, expt)
                e_ass = IRAssign(e_ass_stmt)
                self.stmts.append(e_ass)
            self.visit_stmts(expt.body)
            if expt.name is not None:
                e_del_stmt = Delete(targets=[Name(id=expt.name, ctx=Del())])
                copy_location(e_del_stmt, expt)
                e_del = IRDel(e_del_stmt)
                self.stmts.append(e_del)
            goto_fin = Goto()
            self.stmts.append(goto_fin)
            goto_fin_list.append(goto_fin)
            assert (
                isinstance(expt.type, (Name, Tuple)) or expt.type is None
            ), f"Type of Exception should be Name or None or [Name], but got {dump(expt.type)}!"
            expt_types = []
            if isinstance(expt.type, Name):
                expt_types.append(expt.type.id)
            elif isinstance(expt.type, Tuple):
                for e in expt.type.elts:
                    assert isinstance(
                        e, Name
                    ), "Type of Exception should be Name or None or [Name]!"
                    expt_types.append(e.id)
            catch_stmt = IRCatchException(expt_types, label_try, label_catch, label_e, expt)
            self.stmts.insert(catch_idx, catch_stmt)
            catch_idx += 1

        if len(node.orelse) > 0:
            label_else = self.label_gen.gen()
            self.stmts.append(label_else)
            self.stmts.append(IRPass())
            try_goto.set_label(label_else)
            goto_fin_list.remove(try_goto)
            self.visit_stmts(node.orelse)
            goto_fin = Goto()
            self.stmts.append(goto_fin)
            goto_fin_list.append(goto_fin)

        if len(node.finalbody) > 0:
            label_fin = self.label_gen.gen()
            catch_fin = IRCatchException(None, label_try, label_catch, label_fin)
            self.stmts.append(catch_fin)
            self.stmts.append(label_fin)
            for goto in goto_fin_list:
                goto.set_label(label_fin)
            self.visit_stmts(node.finalbody)
        else:
            label_fin = self.label_gen.gen()
            self.stmts.append(label_fin)
            self.stmts.append(IRPass())
            for goto in goto_fin_list:
                goto.set_label(label_fin)

    def visit_With(self, node: With):
        self._visit_with_items(node.items, node.body, node, "__enter__", "__exit__")

    def visit_AsyncWith(self, node: AsyncWith):
        self._visit_with_items(node.items, node.body, node, "__aenter__", "__aexit__")

    def _visit_with_items(self, items, body, node, enter_name: str, exit_name: str) -> None:
        """Lower ``with`` into explicit context-manager calls.

        Three-address lowering leaves ``with`` statements in place but hoists
        the context expression into a temporary name.  Without this handler the
        body is wrapped in ``IRAstStmt`` and silently ignored by the pointer
        analysis, so capabilities exercised inside a ``with`` block disappear.
        """
        if not items:
            self.visit_stmts(body)
            return
        item, rest = items[0], items[1:]
        context_expr = item.context_expr
        if not isinstance(context_expr, ast.Name):
            # Not lowered to three-address form: still analyse the body so its
            # capabilities are not lost wholesale.
            self._visit_with_items(rest, body, node, enter_name, exit_name)
            return

        manager = ast.Name(id=context_expr.id, ctx=ast.Load())
        method_var = self._new_temporary("with_method")
        self._emit_assign(
            ast.Name(id=method_var, ctx=ast.Store()),
            ast.Attribute(value=manager, attr=enter_name, ctx=ast.Load()),
            node,
        )
        result_var = self._new_temporary("with_enter")
        self._emit_assign(
            ast.Name(id=result_var, ctx=ast.Store()),
            ast.Call(func=ast.Name(id=method_var, ctx=ast.Load()), args=[], keywords=[]),
            node,
        )
        if isinstance(item.optional_vars, ast.Name):
            self._emit_assign(
                item.optional_vars,
                ast.Name(id=result_var, ctx=ast.Load()),
                node,
            )

        self._visit_with_items(rest, body, node, enter_name, exit_name)

        exit_method_var = self._new_temporary("with_exit_method")
        self._emit_assign(
            ast.Name(id=exit_method_var, ctx=ast.Store()),
            ast.Attribute(
                value=ast.Name(id=context_expr.id, ctx=ast.Load()),
                attr=exit_name,
                ctx=ast.Load(),
            ),
            node,
        )
        self._emit_assign(
            ast.Name(id=self._new_temporary("with_exit"), ctx=ast.Store()),
            ast.Call(
                func=ast.Name(id=exit_method_var, ctx=ast.Load()),
                args=[ast.Constant(None), ast.Constant(None), ast.Constant(None)],
                keywords=[],
            ),
            node,
        )

    def visit_Assign(self, stmt: Assign):
        if isinstance(stmt.value, (Yield, YieldFrom)):
            self.stmts.append(IRYield(stmt))
        elif isinstance(stmt.value, Call):
            self.stmts.append(IRCall(stmt))
        elif isinstance(stmt.targets[0], Subscript):
            self.stmts.append(IRStoreSubscr(stmt))
        elif isinstance(stmt.value, Subscript):
            self.stmts.append(IRLoadSubscr(stmt))
        elif isinstance(stmt.targets[0], Attribute):
            self.stmts.append(IRStoreAttr(stmt))
        elif isinstance(stmt.value, Attribute):
            self.stmts.append(IRLoadAttr(stmt))
        elif isinstance(stmt.value, Name):
            self.stmts.append(IRCopy(stmt))
        else:
            self.stmts.append(IRAssign(stmt))

    def visit_AnnAssign(self, node: AnnAssign):
        self.stmts.append(IRAnno(node))

    def visit_Delete(self, node: Delete):
        self.stmts.append(IRDel(node))

    def generic_visit(self, node):
        if isinstance(node, stmt):
            self.stmts.append(IRAstStmt(node))
        else:
            super().generic_visit(node)
