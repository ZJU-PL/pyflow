import ast
from ast import NodeTransformer, Store, Load
import copy
from typing import *
from .transform import Transform

from pyflow.analysis.alias.kcfa._pythonstan.utils import update_ctx, destructable, TempVarGenerator
from pyflow.analysis.alias.kcfa._pythonstan.ir import IRModule
from pyflow.analysis.alias.kcfa._pythonstan.world import World
from ..analysis import AnalysisConfig


__all__ = ["ThreeAddress", "ThreeAddressTransformer"]
FUNC_TEMPLATE = "$func_%d"
CONST_TEMPLATE = "$const_%d"
VAR_TEMPLATE = "$tmp_%d"


class ThreeAddress(Transform):
    transformer: 'ThreeAddressTransformer'

    def __init__(self, config: AnalysisConfig):
        super().__init__(config)
        self.transformer = ThreeAddressTransformer()

    def transform(self, module: IRModule):
        tac = module.stmt
        for _ in range(1):
           tac = self.transformer.visit(tac)
        #three_address_form = self.transformer.visit(module.ast)
        World().scope_manager.set_ir(module, "three address form", tac)


class ConstCollector:
    next_idx: int
    consts: Dict[Any, int]

    @staticmethod
    def to_name(idx: int) -> str:
        return CONST_TEMPLATE % idx

    def __init__(self, init_idx: int = 0):
        self.next_idx = init_idx
        self.consts = {}

    def load(self, c) -> ast.Name:
        if c in self.consts:
            idx = self.consts[c]
        else:
            c_idx = self.next_idx
            self.next_idx += 1
            self.consts[c] = c_idx
            idx = c_idx
        return ast.Name(id=self.to_name(idx), ctx=ast.Load())

    def dump(self) -> List[Tuple[str, Any]]:
        ret = [(v, k) for k, v in self.consts.items()]
        ret.sort(key=lambda x: x[0])
        return [(self.to_name(k), v) for k, v in ret]


class ThreeAddressTransformer(NodeTransformer):
    tmp_gen: TempVarGenerator
    tmp_func_gen: TempVarGenerator
    const_colle: ConstCollector
    import_stmts: Set[ast.stmt]

    def __init__(self):
        self.reset()

    def not_temp(self, exp):
        if isinstance(exp, ast.Name) and '$' in exp.id:
            return False
        return True

    def reset(self, v_tmpl=VAR_TEMPLATE,
              fn_tmpl=FUNC_TEMPLATE, c_tmpl=CONST_TEMPLATE):
        self.tmp_gen = TempVarGenerator(template=v_tmpl)
        self.tmp_func_gen = TempVarGenerator(template=fn_tmpl)
        self.const_colle = ConstCollector()
        self.import_stmts = {*()}

    def resolve_single_Assign(self, tgt, value, stmt):
        """
        Converts a Python assignment statement to three-address code form.
        
        This method handles various assignment patterns including:
        - Simple assignments (x = y)
        - Tuple/list unpacking (a, b = x, y)
        - Starred expressions (a, *b, c = some_list)
        - Complex RHS expressions requiring temporary variables
        
        Parameters:
        ----------
        tgt : ast.AST
            The target of the assignment (LHS), which can be a Name, Tuple, List, etc.
        value : ast.AST
            The value being assigned (RHS)
        stmt : ast.AST
            The original assignment statement (for source location information)
            
        Returns:
        -------
        list[ast.stmt]
            A list of AST statements that implement the assignment in three-address form
            
        Examples:
        --------
        Input:  a = b + c
        Output: $tmp_1 = b + c
                a = $tmp_1
                
        Input:  a, b = x, y
        Output: a = x
                b = y
                
        Input:  a, *b, c = some_list
        Output: $tmp_1 = list(some_list)
                a = $tmp_1[0]
                b = $tmp_1[1:-1]
                c = $tmp_1[-1]
        """

        def has_star(ls):
            return any(elt for elt in ls.elts if isinstance(elt, ast.Starred))

        tblk, texp = self.visit(tgt)
        ass_blk = []
        if isinstance(texp, ast.Name):
            ins = ast.Assign(
                targets=[texp],
                value=value)
            ast.copy_location(ins, stmt)
            ass_blk.append(ins)
        # unpacking cannot be desugarred in semantic level (because of the existence of iterator)
        # only the situation that both sides has equal length can be splitted
        elif destructable(texp) and destructable(value) \
                and len(texp.elts) == len(value.elts) \
                and not has_star(value):
            for t, v in zip(texp.elts, value.elts):
                if isinstance(t, ast.Name):
                    ins = ast.Assign(targets=[t], value=v)
                    ast.copy_location(ins, stmt)
                    ass_blk.append(ins)
                elif isinstance(t, ast.Starred):
                    v = ast.List(elts=[update_ctx(v, Load())], ctx=Load())
                    ins = ast.Assign(targets=[t.value], value=v)
                    ast.copy_location(ins, stmt)
                    ass_blk.append(ins)
                else:
                    tmp_l, tmp_s = self.tmp_gen()
                    ins1 = ast.Assign(targets=[tmp_s], value=v)
                    ast.copy_location(ins1, stmt)
                    ins2 = ast.Assign(targets=[t], value=tmp_l)
                    ast.copy_location(ins2, stmt)
                    ass_blk.extend([ins1, ins2])
        elif destructable(texp):
            if not isinstance(value, ast.Name):
                v_blk, v_elt = self.split_expr(value)
                ass_blk.extend(v_blk)
                value = v_elt
            tmp_l, tmp_s = self.tmp_gen()
            ins1 = ast.Assign(targets=[tmp_s], value=ast.Call(
                func=ast.Name(id='list', ctx=Load()),
                args=[value],
                keywords=[]))
            ast.copy_location(ins1, stmt)
            ass_blk.append(ins1)
            unpack_blk = []
            if has_star(texp):
                l_idx, r_idx = 0, 1
                t_star = None
                for t in texp.elts:
                    if isinstance(t, ast.Starred):
                        break
                    ins = ast.Assign(targets=[t], value=ast.Subscript(
                        value=tmp_l,
                        slice=self.const_colle.load(l_idx),
                        ctx=ast.Load()))
                    ast.copy_location(ins, stmt)
                    unpack_blk.append(ins)
                    l_idx += 1
                for t in texp.elts[::-1]:
                    if isinstance(t, ast.Starred):
                        t_star = t
                        break
                    ins = ast.Assign(targets=[t], value=ast.Subscript(
                        value=tmp_l,
                        slice=ast.UnaryOp(op=ast.USub(),
                                          operand=self.const_colle.load(r_idx)),
                        ctx=ast.Load()))
                    ast.copy_location(ins, stmt)
                    unpack_blk.append(ins)
                    r_idx += 1
                if t_star is not None:
                    lower_idx = self.const_colle.load(l_idx)
                    if r_idx == 1:
                        upper_idx = None
                    else:
                        upper_idx = ast.UnaryOp(
                            op=ast.USub(),
                            operand=self.const_colle.load(r_idx - 1))
                    slc = ast.Slice(lower=lower_idx, upper=upper_idx,
                                    ctx=Load())
                    ins = ast.Assign(targets=[t_star.value],
                                     value=ast.Subscript(
                                         value=tmp_l, slice=slc, ctx=Load()))
                    ast.copy_location(ins, stmt)
                    unpack_blk.append(ins)
            else:
                for idx, t in enumerate(texp.elts):
                    ins = ast.Assign(targets=[t], value=ast.Subscript(
                        value=tmp_l,
                        slice=self.const_colle.load(idx),
                        ctx=ast.Load()))
                    ast.copy_location(ins, stmt)
                    unpack_blk.append(ins)
            ass_blk.extend(self.visit_stmt_list(unpack_blk))
        else:
            tmp_l, tmp_s = self.tmp_gen()
            ins1 = ast.Assign(targets=[tmp_s], value=value)
            ast.copy_location(ins1, stmt)
            ins2 = ast.Assign(targets=[texp], value=tmp_l)
            ast.copy_location(ins2, stmt)
            ass_blk.extend((ins1, ins2))
        tblk = ass_blk + tblk
        return tblk

    def split_expr(self, exp):
        blk, e = self.visit(exp)
        if not isinstance(e, (ast.Name, ast.Starred)):
            tmp_l, tmp_s = self.tmp_gen()
            if hasattr(exp, 'ctx') and isinstance(exp.ctx, Store):
                # tmp = do(...); e = tmp; visit(exp)=e
                ins = ast.Assign(targets=[e], value=tmp_l)
                ast.copy_location(ins, exp)
                if isinstance(e, ast.Tuple) or isinstance(e, ast.List):
                    blk.insert(0, ins)  # assign after unpack
                else:
                    blk.append(ins)  # load object and then assign
                e = tmp_s
            else:
                # e=visit(exp); tmp=e; do(..., tmp, ...)
                ins = ast.Assign(targets=[tmp_s], value=e)
                ast.copy_location(ins, exp)
                blk.append(ins)
                e = tmp_l
        return self.visit_stmt_list(blk), e

    def visit_BinOp(self, node):
        lblk, lval = self.split_expr(node.left)
        rblk, rval = self.split_expr(node.right)
        ins = ast.BinOp(left=lval, op=node.op, right=rval)
        ast.copy_location(ins, node)
        return lblk + rblk, ins

    def visit_UnaryOp(self, node):
        if isinstance(node.op, ast.USub) and \
                isinstance(node.operand, ast.Constant):
            value = self.const_colle.load(-node.operand.value)
            ast.copy_location(value, node)
            return [], value
        else:
            blk, val = self.split_expr(node.operand)
            ins = ast.UnaryOp(operand=val, op=node.op)
            ast.copy_location(ins, node)
            return blk, ins

    def visit_BoolOp(self, node):
        blk, elts = None, []
        test_list = [self.visit(val) for val in node.values]
        tmp_l, tmp_s = self.tmp_gen()
        for tmp_blk, tmp_elt in test_list[::-1]:
            ass_ins = ast.Assign(targets=[tmp_s], value=tmp_elt)
            ast.copy_location(ass_ins, node)
            tmp_blk.append(ass_ins)
            if blk is not None:
                if isinstance(node.op, ast.And):
                    tmp_test = tmp_l
                elif isinstance(node.op, ast.Or):
                    tmp_test = ast.UnaryOp(op=ast.Not(), operand=tmp_l)
                else:
                    raise NotImplementedError("The op is not a bool op!")
                e = tmp_test
                tmp_blk.append(ast.If(test=tmp_test, body=blk, orelse=[]))
            blk = tmp_blk
            elts.insert(0, tmp_elt)
        return blk, tmp_l

    def visit_IfExp(self, node):
        t_blk, t_val = self.split_expr(node.test)
        b_blk, b_val = self.split_expr(node.body)
        o_blk, o_val = self.split_expr(node.orelse)
        tmp_l, tmp_s = self.tmp_gen()
        b_ass = ast.Assign(targets=[tmp_s], value=b_val)
        ast.copy_location(b_ass, node.body)
        b_blk.append(b_ass)
        o_ass = ast.Assign(targets=[tmp_s], value=o_val)
        ast.copy_location(o_ass, node.orelse)
        o_blk.append(o_ass)
        ins = ast.If(test=t_val, body=b_blk, orelse=o_blk)
        ast.copy_location(ins, node)
        t_blk.append(ins)
        return t_blk, tmp_l

    def visit_Lambda(self, node):
        (f_load,) = self.tmp_func_gen(ctxs=[Load()])
        f_name = f_load.id
        blk = []
        new_func = ast.FunctionDef(
            name=f_name,
            args=node.args,
            body=[ast.Return(value=node.body)],
            returns=None,
            type_comment=None,
            decorator_list=[])
        ast.copy_location(new_func, node)
        blk.extend(self.visit_FunctionDef(new_func))
        return blk, f_load

    def visit_NamedExpr(self, node):
        AGGRESSIVE = True
        if AGGRESSIVE:
            v_blk, v_elt = self.visit(node.value)
            t_blk, t_elt = self.visit(node.target)
            ins = ast.Assign(targets=[t_elt], value=v_elt)
            ast.copy_location(ins, node)
            return v_blk + t_blk + [ins], v_elt
        else:
            v_blk, v_elt = self.split_expr(node.value)
            t_blk, t_elt = self.visit(node.target)
            ins = ast.NamedExpr(target=t_elt, value=v_elt)
            ast.copy_location(ins, node)
            return v_blk + t_blk, ins

    def visit_Tuple(self, node):
        blk, elts = [], []
        for old_elt in node.elts:
            tmp_blk, tmp_elt = self.split_expr(old_elt)
            blk.extend(tmp_blk)
            elts.append(tmp_elt)
        exp = ast.Tuple(elts=elts, ctx=node.ctx)
        ast.copy_location(exp, node)
        return blk, exp

    def visit_List(self, node):
        blk, elts = [], []
        for old_elt in node.elts:
            tmp_blk, tmp_elt = self.split_expr(old_elt)
            blk.extend(tmp_blk)
            elts.append(tmp_elt)
        exp = ast.List(elts=elts, ctx=node.ctx)
        ast.copy_location(exp, node)
        return blk, exp

    def visit_Set(self, node):
        blk, elts = [], []
        for old_elt in node.elts:
            tmp_blk, tmp_elt = self.split_expr(old_elt)
            blk.extend(tmp_blk)
            elts.append(tmp_elt)
        exp = ast.Set(elts=elts)
        ast.copy_location(exp, node)
        return blk, exp

    def visit_Dict(self, node):
        blk, keys, values = [], [], []
        for k, v in zip(node.keys, node.values):
            if k is not None:
                k_blk, k_elt = self.split_expr(k)
                blk.extend(k_blk)
                keys.append(k_elt)
            else:
                keys.append(None)
            v_blk, v_elt = self.split_expr(v)
            blk.extend(v_blk)
            values.append(v_elt)
        exp = ast.Dict(keys=keys, values=values)
        ast.copy_location(exp, node)
        return blk, exp

    def trans_comp(self, comp, body):
        for idx in range(len(comp.ifs) - 1, -1, -1):
            cond = comp.ifs[idx]
            ins = ast.If(test=cond,
                         body=body,
                         orelse=[])
            body = [ins]
        if comp.is_async == 0:
            ins = ast.For(target=comp.target,
                          iter=comp.iter,
                          body=body,
                          orelse=[])
        else:
            ins = ast.AsyncFor(target=comp.target,
                               iter=comp.iter,
                               body=body,
                               orelse=[])
        return ins

    def visit_ListComp(self, node):
        list_l, list_s = self.tmp_gen()
        list_init = ast.Assign(targets=[list_s],
                               value=ast.List(elts=[], ctx=Load()))
        ast.copy_location(list_init, node)
        body = [
            ast.Expr(value=ast.Call(
                func=ast.Attribute(value=list_l, attr='append', ctx=Load()),
                args=[node.elt],
                keywords=[]))
        ]
        for idx in range(len(node.generators) - 1, -1, -1):
            comp = node.generators[idx]
            ins = self.trans_comp(comp, body)
            body = [ins]
        blk = self.visit_stmt_list(body)
        for ins in blk:
            ast.copy_location(ins, node)
            ast.fix_missing_locations(ins)
        blk.insert(0, list_init)
        return blk, list_l

    def visit_SetComp(self, node):
        set_l, set_s = self.tmp_gen()
        set_init = ast.Assign(targets=[set_s],
                              value=ast.Set(elts=[], ctx=Load()))
        ast.copy_location(set_init, node)
        body = [
            ast.Expr(value=ast.Call(
                func=ast.Attribute(value=set_l, attr='add', ctx=Load()),
                args=[node.elt],
                keywords=[]))
        ]
        for idx in range(len(node.generators) - 1, -1, -1):
            comp = node.generators[idx]
            ins = self.trans_comp(comp, body)
            body = [ins]
        blk = self.visit_stmt_list(body)
        for ins in blk:
            ast.copy_location(ins, node)
            ast.fix_missing_locations(ins)
        blk.insert(0, set_init)
        return blk, set_l

    def visit_GeneratorExp(self, node):
        fn_name, = self.tmp_func_gen(ctxs=[Load()])

        body = [
            ast.Expr(value=ast.Yield(value=node.elt))
        ]
        for idx in range(len(node.generators) - 1, -1, -1):
            comp = node.generators[idx]
            ins = self.trans_comp(comp, body)
            body = [ins]
        blk = self.visit_stmt_list(body)
        for ins in blk:
            ast.copy_location(ins, node)
            ast.fix_missing_locations(ins)
        fn = ast.FunctionDef(name=fn_name.id,
                             args=ast.arguments(
                                 posonlyargs=[],
                                 args=[],
                                 kwonlyargs=[],
                                 kw_defaults=[],
                                 defaults=[]
                             ),
                             body=blk,
                             decorator_list=[],
                             returns=None,
                             type_comment=None)
        call_elt = ast.Call(func=fn_name, args=[], keywords=[])
        ast.copy_location(call_elt, node)
        return [fn], call_elt

    def visit_DictComp(self, node):
        dict_l, dict_s = self.tmp_gen()
        dict_init = ast.Assign(targets=[dict_s],
                               value=ast.Dict(keys=[], values=[]))
        ast.copy_location(dict_init, node)
        body = [
            ast.Expr(value=ast.Call(
                func=ast.Attribute(value=dict_l,
                                   attr='setdefault',
                                   ctx=Load()),
                args=[node.key, node.value],
                keywords=[]))
        ]
        for idx in range(len(node.generators) - 1, -1, -1):
            comp = node.generators[idx]
            ins = self.trans_comp(comp, body)
            body = [ins]
        blk = self.visit_stmt_list(body)
        for ins in blk:
            ast.copy_location(ins, node)
            ast.fix_missing_locations(ins)
        blk.insert(0, dict_init)
        return blk, dict_l

    def visit_Await(self, node):
        blk, elt = self.visit(node.value)
        tmp_l, tmp_s = self.tmp_gen()
        ins = ast.Assign(targets=[tmp_s], value=elt)
        ast.copy_location(ins, node)
        blk.append(ins)
        exp = ast.Await(value=tmp_l)
        ast.copy_location(exp, node)
        return blk, exp

    def visit_Yield(self, node):
        blk, elt = [], None
        if node.value is not None:
            blk, elt = self.visit(node.value)
            tmp_l, tmp_s = self.tmp_gen()
            ins = ast.Assign(targets=[tmp_s], value=elt)
            ast.copy_location(ins, node)
            blk.append(ins)
            exp = ast.Yield(value=tmp_l)
            ast.copy_location(exp, node)
        else:
            blk, exp = [], node
        return blk, exp

    def visit_YieldFrom(self, node):
        blk, elt = self.visit(node.value)
        tmp_l, tmp_s = self.tmp_gen()
        ins = ast.Assign(targets=[tmp_s], value=elt)
        ast.copy_location(ins, node)
        blk.append(ins)
        exp = ast.YieldFrom(value=tmp_l)
        ast.copy_location(exp, node)
        return blk, exp

    def visit_BoolOp(self, node):
        blk, elts = None, []
        test_list = [self.visit(val) for val in node.values]
        tmp_l, tmp_s = self.tmp_gen()
        for tmp_blk, tmp_elt in test_list[::-1]:
            ass_ins = ast.Assign(targets=[tmp_s], value=tmp_elt)
            ast.copy_location(ass_ins, node)
            tmp_blk.append(ass_ins)
            if blk is not None:
                if isinstance(node.op, ast.And):
                    tmp_test = tmp_l
                elif isinstance(node.op, ast.Or):
                    tmp_test = ast.UnaryOp(op=ast.Not(), operand=tmp_l)
                else:
                    raise NotImplementedError("The op is not a bool op!")
                tmp_blk.append(ast.If(test=tmp_test, body=blk, orelse=[]))
            blk = tmp_blk
            elts.insert(0, tmp_elt)
        return blk, tmp_l

    def visit_Compare(self, node):
        blk, elts = None, []
        values = [node.left] + node.comparators
        test_list = [self.split_expr(val) for val in values]
        tmp_l, tmp_s = self.tmp_gen()
        for i in range(len(test_list) - 1, -1, -1):
            tmp_blk, tmp_elt = test_list[i]
            if i > 0:
                _, lhs_elt = test_list[i - 1]
                tmp_test = ast.Compare(left=lhs_elt,
                                       ops=[node.ops[i - 1]],
                                       comparators=[tmp_elt])
                ass_ins = ast.Assign(targets=[tmp_s], value=tmp_test)
                ast.copy_location(ass_ins, node)
                tmp_blk.append(ass_ins)
                if blk is not None:
                    tmp_blk.append(ast.If(test=tmp_l, body=blk, orelse=[]))
            else:
                tmp_blk.extend(blk)
            blk = tmp_blk
            elts.insert(0, tmp_elt)
        return blk, tmp_l

    def visit_Call(self, node):
        # Save the original location before recursively lowering children.
        # Some generated temporary names are shared and later receive fallback
        # locations from ``fix_missing_locations``; explicitly stamping the
        # call instruction prevents all capability reports collapsing to line 1.
        origin = {
            name: getattr(node, name, None)
            for name in ("lineno", "col_offset", "end_lineno", "end_col_offset")
        }
        blk, args, keywords = [], [], []
        func_blk, func_elt = self.visit(node.func)
        if not (isinstance(func_elt, ast.Name)):
                # or isinstance(func_elt, ast.Attribute)):
            func_blk, func_elt = self.split_expr(node.func)
        blk.extend(func_blk)
        for arg in node.args:
            arg_blk, arg_elt = self.split_expr(arg)
            blk.extend(arg_blk)
            args.append(arg_elt)
        for kw in node.keywords:
            v_blk, v_elt = self.split_expr(kw.value)
            new_kw = ast.keyword(arg=kw.arg, value=v_elt)
            blk.extend(v_blk)
            keywords.append(new_kw)
        tmp_l, tmp_s = self.tmp_gen()
        ins = ast.Assign(
            targets=[tmp_s],
            value=ast.Call(func=func_elt, args=args, keywords=keywords))
        for created in (ins, ins.value, tmp_s):
            for name, value in origin.items():
                if value is not None:
                    setattr(created, name, value)
        blk.append(ins)
        return blk, tmp_l

    def visit_FormattedValue(self, node):
        blk, v = self.split_expr(node.value)
        fv = ast.FormattedValue(value=v,
                                conversion=node.conversion,
                                format_spec=node.format_spec)
        ast.copy_location(fv, node)
        return blk, fv

    def visit_JoinedStr(self, node):
        blk, values = [], []
        for v in node.values:
            if isinstance(v, ast.Constant):
                tmp_blk, tmp_v = self.visit(v)
                fvalue = ast.FormattedValue(value=tmp_v, conversion=-1)
                ast.copy_location(fvalue, v)
                values.append(fvalue)
                blk.extend(tmp_blk)
            elif isinstance(v, ast.FormattedValue):
                tmp_blk, tmp_v = self.visit(v.value)
                fvalue = ast.FormattedValue(value=tmp_v, conversion=v.conversion)
                ast.copy_location(fvalue, v)
                values.append(fvalue)
                blk.extend(tmp_blk)
        jstr = ast.JoinedStr(values=values)
        ast.copy_location(jstr, node)
        return blk, jstr

    def visit_Name(self, node):
        return [], node

    def visit_Constant(self, node):
        return [], self.const_colle.load(node.value)

        '''
        const_l, const_s = self.tmp_const_gen()
        ins = ast.Assign(targets=[const_s], value=node)
        ast.copy_location(ins, node)
        return [ins], const_l
        '''

    def visit_Starred(self, node):
        blk, elt = self.split_expr(node.value)
        exp = ast.Starred(value=elt, ctx=node.ctx)
        ast.copy_location(exp, node)
        return blk, exp

    def visit_Attribute(self, node):
        blk, elt = self.split_expr(node.value)
        exp = ast.Attribute(value=elt, attr=node.attr, ctx=node.ctx)
        ast.copy_location(exp, node)
        return blk, exp

    def visit_Subscript(self, node):
        if isinstance(node.slice, ast.Slice):
            s_blk, s_elt = self.visit(node.slice)
        else:
            s_blk, s_elt = self.split_expr(node.slice)
        v_blk, v_elt = self.split_expr(node.value)
        exp = ast.Subscript(value=v_elt, slice=s_elt, ctx=node.ctx)
        ast.copy_location(exp, node)
        return v_blk + s_blk, exp

    def visit_Slice(self, node):
        blk = []
        lower, upper, step = None, None, None
        if node.lower is not None:
            l_blk, lower = self.split_expr(node.lower)
            blk.extend(l_blk)
        if node.upper is not None:
            u_blk, upper = self.split_expr(node.upper)
            blk.extend(u_blk)
        if node.step is not None:
            s_blk, step = self.split_expr(node.step)
            blk.extend(s_blk)
        exp = ast.Slice(lower=lower, upper=upper, step=step)
        ast.copy_location(exp, node)
        return blk, exp

    def visit_Return(self, node):
        blk, v = [], None
        if node.value is not None:
            blk, v = self.split_expr(node.value)
        stmt = ast.Return(value=v)
        ast.copy_location(stmt, node)
        blk.append(stmt)
        return blk

    def visit_Delete(self, node):
        blk = []
        for tgt in node.targets:
            tmp_blk, tmp_elt = self.split_expr(tgt)
            stmt = ast.Delete(targets=[tmp_elt])
            ast.copy_location(stmt, tgt)
            blk.extend(tmp_blk)
            blk.append(stmt)
        return blk

    def visit_AugAssign(self, node):
        expand_stmt = ast.Assign(
            targets=[node.target],
            value=ast.BinOp(
                left=update_ctx(node.target, Load()),
                op=node.op,
                right=node.value))
        ast.copy_location(expand_stmt, node)
        return self.visit(expand_stmt)

    def visit_Assign(self, node):
        tgts = node.targets
        blk, exp = self.visit(node.value)
        for tgt in tgts[::-1]:
            tblk = self.resolve_single_Assign(tgt, exp, node)
            blk.extend(tblk)
        return blk

    def visit_AnnAssign(self, node):
        if node.value is None:
            if node.simple == 1:
                blk = [node]
            else:
                blk, tmp_t = self.split_expr(node.target)
                ins = ast.AnnAssign(target=tmp_t,
                                    annotation=node.annotation,
                                    simple=1)
                ast.copy_location(ins, node)
                blk.insert(0, ins)
        else:
            blk, v_elt = self.visit(node.value)
            if node.simple == 1:
                ins1 = ast.AnnAssign(target=node.target,
                                     annotation=node.annotation,
                                     simple=1)
                ast.copy_location(ins1, node)
                ins2 = ast.Assign(targets=[node.target],
                                  value=v_elt)
                ast.copy_location(ins2, node)
                blk.extend([ins1, ins2])
            else:
                tmp_blk, tmp_t = self.split_expr(node.target)
                ins1 = ast.AnnAssign(target=tmp_t,
                                     annotation=node.annotation,
                                     simple=1)
                ast.copy_location(ins1, node)
                ins2 = ast.Assign(targets=[tmp_t],
                                  value=v_elt)
                ast.copy_location(ins2, node)
                blk.extend([ins1, ins2])
                blk.extend(tmp_blk)
        return blk

    '''
    For(expr target, expr iter, stmt* body, stmt* orelse, string? type_comment)

    ==> temp1 = iter(iter)
        temp2 = next(temp1, None)
        temp3 = temp2 is not None
        while temp3:
          target = temp2
          ...
          temp2 = next(temp1, None)
          temp3 = temp2 is not None
    '''

    def visit_For(self, node):
        body = []
        iter_blk, iter_val = self.split_expr(node.iter)
        body.extend(iter_blk)
        iter_l, iter_s = self.tmp_gen()
        iter_stmt = ast.Assign(targets=[iter_s], value=ast.Call(
            func=ast.Name(id='iter', ctx=Load()),
            args=[iter_val],
            keywords=[]))
        ast.copy_location(iter_stmt, node.iter)
        body.append(iter_stmt)
        tmp_l, tmp_s = self.tmp_gen()
        next_stmt = ast.Assign(targets=[tmp_s], value=ast.Call(
            func=ast.Name(id='next', ctx=Load()),
            args=[iter_l, self.const_colle.load(None)],
            keywords=[]))
        ast.copy_location(next_stmt, node.iter)
        body.append(next_stmt)
        tmp_test_l, tmp_test_s = self.tmp_gen()
        test_stmt = ast.Assign(targets=[tmp_test_s], value=ast.Compare(
            left=tmp_l,
            ops=[ast.IsNot()],
            comparators=[self.const_colle.load(None)]))
        ast.copy_location(test_stmt, node.target)
        body.append(test_stmt)
        ass_blk = self.resolve_single_Assign(node.target, tmp_l, node.iter)
        b_blk = self.visit_stmt_list(node.body)
        ass_blk.extend(b_blk)
        ass_blk.append(copy.deepcopy(next_stmt))
        ass_blk.append(copy.deepcopy(test_stmt))
        o_blk = self.visit_stmt_list(node.orelse)
        while_stmt = ast.While(test=tmp_test_l, body=ass_blk, orelse=o_blk)
        ast.copy_location(while_stmt, node)
        body.append(while_stmt)
        return body

    def visit_AsyncFor(self, node):
        body = []
        iter_blk, iter_val = self.split_expr(node.iter)
        body.extend(iter_blk)
        iter_l, iter_s = self.tmp_gen()
        iter_stmt = ast.Assign(targets=[iter_s], value=ast.Call(
            func=ast.Name(id='iter', ctx=Load()),
            args=[iter_val],
            keywords=[]))
        ast.copy_location(iter_stmt, node.iter)
        body.append(iter_stmt)
        tmp_l, tmp_s = self.tmp_gen()
        next_stmt = ast.Assign(targets=[tmp_s], value=ast.Call(
            func=ast.Name(id='next', ctx=Load()),
            args=[iter_l, self.const_colle.load(None)],
            keywords=[]))
        ast.copy_location(next_stmt, node.iter)

        body.append(next_stmt)
        tmp_test_l, tmp_test_s = self.tmp_gen()
        test_stmt = ast.Assign(targets=[tmp_test_s], value=ast.Compare(
            left=tmp_l,
            ops=[ast.IsNot()],
            comparators=[self.const_colle.load(None)]))
        ast.copy_location(test_stmt, node.target)
        body.append(test_stmt)
        ass_blk = self.resolve_single_Assign(node.target, tmp_l, node.iter)
        b_blk = self.visit_stmt_list(node.body)
        ass_blk.extend(b_blk)
        ass_blk.append(copy.deepcopy(next_stmt))
        ass_blk.append(copy.deepcopy(test_stmt))
        o_blk = self.visit_stmt_list(node.orelse)
        while_stmt = ast.While(test=tmp_test_l, body=ass_blk, orelse=o_blk)
        ast.copy_location(while_stmt, node)
        body.append(while_stmt)
        return body

    def visit_While(self, node):
        t_blk, test_elt = self.split_expr(node.test)
        b_blk = self.visit_stmt_list(node.body)
        o_blk = self.visit_stmt_list(node.orelse)
        ins = ast.While(test=test_elt, body=b_blk, orelse=o_blk)
        ast.copy_location(ins, node)
        t_blk.append(ins)
        return t_blk

    def visit_If(self, node):
        t_blk, t_val = self.split_expr(node.test)
        b_blk = self.visit_stmt_list(node.body)
        o_blk = self.visit_stmt_list(node.orelse)
        ins = ast.If(test=t_val, body=b_blk, orelse=o_blk)
        ast.copy_location(ins, node)
        t_blk.append(ins)
        return t_blk

    def visit_With(self, node):
        items = []
        for item in node.items:
            ctx_blk, ctx_e = self.split_expr(item.context_expr)
            tmp_l, tmp_s = self.tmp_gen()
            if item.optional_vars is not None:
                with_blk = self.resolve_single_Assign(
                    item.optional_vars, tmp_l, item)
                items.append((ctx_blk, ctx_e, tmp_s, with_blk))
            else:
                items.append((ctx_blk, ctx_e, tmp_s, None))
        blk = self.visit_stmt_list(node.body)

        for idx in range(len(items) - 1, -1, -1):
            ctx_blk, ctx_e, tmp_s, with_blk = items[idx]
            if with_blk is not None:
                with_blk.extend(blk)
            else:
                with_blk = blk
            with_stmt = ast.With(
                items=[ast.withitem(
                    context_expr=ctx_e, optional_vars=tmp_s)],
                body=with_blk)
            ast.copy_location(with_stmt, node)
            blk = ctx_blk
            blk.append(with_stmt)
        return blk

    def visit_AsyncWith(self, node):
        items = []
        for item in node.items:
            ctx_blk, ctx_e = self.split_expr(item.context_expr)
            tmp_l, tmp_s = self.tmp_gen()
            if item.optional_vars is not None:
                with_blk = self.resolve_single_Assign(
                    item.optional_vars, tmp_l, item)
                items.append((ctx_blk, ctx_e, tmp_s, with_blk))
            else:
                items.append((ctx_blk, ctx_e, tmp_s, None))
        blk = self.visit_stmt_list(node.body)

        for idx in range(len(items) - 1, -1, -1):
            ctx_blk, ctx_e, tmp_s, with_blk = items[idx]
            if with_blk is not None:
                with_blk.extend(blk)
            else:
                with_blk = blk
            with_stmt = ast.AsyncWith(
                items=[ast.withitem(
                    context_expr=ctx_e, optional_vars=tmp_s)],
                body=with_blk)
            ast.copy_location(with_stmt, node)
            blk = ctx_blk
            blk.append(with_stmt)
        return blk

    def visit_Raise(self, node):
        blk = []
        e_elt, c_elt = None, None
        if node.exc is not None:
            e_blk, e_elt = self.split_expr(node.exc)
            blk.append(e_blk)
        if node.cause is not None:
            c_blk, c_elt = self.split_expr(node.cause)
            blk.append(c_blk)
        ins = ast.Raise(exc=e_elt, cause=c_elt)
        ast.copy_location(ins, node)
        return ins

    def visit_Try(self, node):
        handlers = []
        body_stmts = self.visit_stmt_list(node.body)
        stmts = []
        for old_handler in node.handlers:
            if old_handler.type is not None:
                t_blk, t_elt = self.visit(old_handler.type)
                if not isinstance(t_elt, ast.Name):
                    tmp_l, tmp_s = self.tmp_gen()
                    ins = ast.Assign(targets=[tmp_s], value=t_elt)
                    ast.copy_location(ins, old_handler.type)
                    t_blk.append(ins)
                    t_elt = tmp_l
                stmts.extend(t_blk)
            else:
                t_elt = None
            handler = ast.ExceptHandler(
                type=t_elt,
                name=old_handler.name,
                body=self.visit_stmt_list(old_handler.body))
            ast.copy_location(handler, old_handler)
            handlers.append(handler)
        ins = ast.Try(
            body=body_stmts,
            handlers=handlers,
            orelse=self.visit_stmt_list(node.orelse),
            finalbody=self.visit_stmt_list(node.finalbody))
        ast.copy_location(ins, node)
        stmt = ast.Try(body=stmts + [ins], handlers=[], orelse=[], finalbody=[])
        ast.copy_location(stmt, node)
        return stmt

    def visit_Assert(self, node):
        blk = []
        t_blk, t_elt = self.split_expr(node.test)
        m_blk, m_elt = [], None
        if node.msg is not None:
            m_blk, m_elt = self.split_expr(node.msg)
        m_args = [m_elt] if m_elt is not None else []
        blk.extend(t_blk)
        blk.extend(m_blk)
        tmp_l, tmp_s = self.tmp_gen()
        ins1 = ast.Assign(targets=[tmp_s],
                          value=ast.UnaryOp(op=ast.Not(), operand=t_elt))
        ast.copy_location(ins1, node.test)
        blk.append(ins1)
        err_l, err_s = self.tmp_gen()
        exc_l, exc_s = self.tmp_gen()
        ins2 = ast.If(
            test=tmp_l,
            body=[
                ast.Assign(targets=[err_s],
                           value=ast.Name(id="AssertionError", ctx=Load())),
                ast.Assign(targets=[exc_s],
                           value=ast.Call(func=err_l, args=m_args, keywords=[])),
                ast.Raise(exc=exc_l)],
            orelse=[])
        ast.copy_location(ins2, node)
        blk.append(ins2)
        return blk

    def visit_stmt_list(self, stmts):
        blk = []
        if stmts is None:
            return blk
        for stmt in stmts:
            if isinstance(stmt, ast.expr):
                cur_blk, _ = self.split_expr(stmt)
                blk.extend(cur_blk)
            else:
                cur_blk = self.visit(stmt)
                if isinstance(cur_blk, list):
                    blk.extend(cur_blk)
                else:
                    blk.append(cur_blk)
        return blk

    def visit_Match(self, node):
        # TODO: add support for pattern matching
        return node

    def visit_ClassDef(self, node):
        blk, bases, keywords = [], [], []
        for base in node.bases:
            if base is None or isinstance(base, ast.Name):
                bases.append(base)
            else:
                base_blk, base_elt = self.split_expr(base)
                blk.extend(base_blk)
                bases.append(base_elt)
        for keyword in node.keywords:
            keyword_blk, keyword_value = self.split_expr(keyword.value)
            blk.extend(keyword_blk)
            keywords.append(ast.keyword(arg=keyword.arg, value=keyword_value))
        ins = ast.ClassDef(
            name=node.name,
            bases=bases,
            keywords=keywords,
            body=self.visit_stmt_list(node.body),
            decorator_list=node.decorator_list)
        ast.copy_location(ins, node)
        blk.append(ins)
        return blk

    def visit_FunctionDef(self, node):
        ast.fix_missing_locations(node)
        blk, args = self.visit_arguments(node.args)
        ins = ast.FunctionDef(
            name=node.name,
            args=args,
            body=self.visit_stmt_list(node.body),
            decorator_list=node.decorator_list,
            returns=node.returns,
            type_comment=node.type_comment
        )
        ast.copy_location(ins, node)
        blk.append(ins)
        return blk

    def visit_AsyncFunctionDef(self, node):
        blk, args = self.visit_arguments(node.args)
        ins = ast.AsyncFunctionDef(
            name=node.name,
            args=args,
            body=self.visit_stmt_list(node.body),
            decorator_list=node.decorator_list,
            returns=node.returns,
            type_comment=node.type_comment
        )
        ast.copy_location(ins, node)
        blk.append(ins)
        return blk

    def visit_arguments(self, node):
        blk = []
        defaults = []
        for val in node.defaults:
            if val is None or isinstance(val, ast.Name):
                defaults.append(val)
            else:
                val_blk, val_elt = self.split_expr(val)
                blk.extend(val_blk)
                defaults.append(val_elt)
        kw_defaults = []
        for val in node.kw_defaults:
            if val is None or isinstance(val, ast.Name):
                kw_defaults.append(val)
            else:
                val_blk, val_elt = self.split_expr(val)
                blk.extend(val_blk)
                kw_defaults.append(val_elt)
        arguments = ast.arguments(
            posonlyargs=node.posonlyargs,
            args=node.args,
            vararg=node.vararg,
            kwonlyargs=node.kwonlyargs,
            kw_defaults=kw_defaults,
            kwarg=node.kwarg,
            defaults=defaults)
        ast.copy_location(arguments, node)
        return blk, arguments

    def visit_Import(self, node):
        blk = []
        for alias in node.names:
            ins = ast.Import(names=[alias])
            ast.copy_location(ins, alias)
            blk.append(ins)
            self.import_stmts.add(ins)
        return blk

    def visit_ImportFrom(self, node):
        blk = []
        for alias in node.names:
            ins = ast.ImportFrom(
                module=node.module,
                names=[alias],
                level=node.level)
            ast.copy_location(ins, alias)
            blk.append(ins)
            self.import_stmts.add(ins)
        return blk

    def visit_Expr(self, node):
        blk, elt = self.split_expr(node.value)
        if self.not_temp(elt):
            _, tmp_s = self.tmp_gen()
            ins = ast.Assign(targets=[tmp_s], value=elt)
            ast.copy_location(ins, node)
            blk.append(ins)
        return blk

    def visit_Global(self, node):
        blk = []
        for name in node.names:
            ins = ast.Global(names=[name])
            ast.copy_location(ins, node)
            blk.append(ins)
        return blk

    def visit_Nonlocal(self, node):
        blk = []
        for name in node.names:
            ins = ast.Nonlocal(names=[name])
            ast.copy_location(ins, node)
            blk.append(ins)
        return blk

    def visit_Pass(self, node):
        return node

    def visit_Break(self, node):
        return node

    def visit_Continue(self, node):
        return node

    def visit_Expression(self, node):
        self.reset()
        expr = ast.Expression(body=self.visit_Expr(node.body))
        ast.copy_location(expr, node)
        ast.fix_missing_locations(expr)
        return expr

    def visit_Module(self, node):
        self.reset()
        stmts = self.visit_stmt_list(node.body)
        const_stmts = [ast.Assign(targets=[ast.Name(id=n, ctx=ast.Store())],
                                  value=ast.Constant(value=v))
                       for n, v in self.const_colle.dump()]
        stmts = const_stmts + stmts
        mod = ast.Module(body=stmts,
                         type_ignores=node.type_ignores)
        ast.copy_location(mod, node)
        ast.fix_missing_locations(mod)
        return mod

    def visit_Interactive(self, node):
        self.reset()
        inter = ast.Interactive(body=self.visit_stmt_list(node.body))
        ast.copy_location(inter, node)
        ast.fix_missing_locations(inter)
        return inter
