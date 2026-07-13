from typing import List, Any
import ast

from pyflow.analysis.pointer._pythonstan.utils.persistent_rb_tree import PersistentMap

IR = "cfg"
EnvType: PersistentMap[str, List[Any]]


class ICFGTransformBase:
    def __init__(self):
        ...

    def resolve_node(self, env: PersistentMap, node: ast.expr) -> List:
        if isinstance(node, ast.Name):
            return env.get(node.id)
        elif isinstance(node, ast.Tuple):
            ret = []
            for elt in node.elts:
                if isinstance(elt, ast.Starred):
                    sub_lists = self.resolve_node(env, elt.value)
                    new_ret = []
                    for sub_list in sub_lists:
                        for cur_list in ret:
                            new_ret.append(cur_list + list(sub_list))
                    ret = new_ret
                else:
                    v_elt = self.resolve_node(env, elt)
                    ret.append(v_elt)
            return [tuple(t) for t in ret]
        elif isinstance(node, ast.List):
            ret = []
            for elt in node.elts:
                if isinstance(elt, ast.Starred):
                    sub_lists = self.resolve_node(env, elt.value)
                    new_ret = []
                    for sub_list in sub_lists:
                        for cur_list in ret:
                            new_ret.append(cur_list + list(sub_list))
                    ret = new_ret
                else:
                    v_elt = self.resolve_node(env, elt)
                    ret.append(v_elt)
            return ret
        elif isinstance(node, ast.Set):
            ret = []
            for elt in node.elts:
                if isinstance(elt, ast.Starred):
                    sub_lists = self.resolve_node(env, elt.value)
                    new_ret = []
                    for sub_list in sub_lists:
                        for cur_list in ret:
                            new_ret.append(cur_list + list(sub_list))
                    ret = new_ret
                else:
                    v_elt = self.resolve_node(env, elt)
                    ret.append(v_elt)
            return [set(s) for s in ret]
        elif isinstance(node, ast.Dict):
            ret = []
            for k, v in zip(node.keys, node.values):
                if k is None:
                    new_ret = []
                    for v_dict in self.resolve_node(env, v):
                        for ret_lst in ret:
                            new_ret.append(ret_lst + list(v_dict.items()))
                    ret = new_ret
                else:
                    new_ret = []
                    for res_k in self.resolve_node(env, k):
                        for res_v in self.resolve_node(env, v):
                            for ret_lst in ret:
                                new_ret.append(ret_lst + [(res_k, res_v)])
                    ret = new_ret
            return [dict(dic) for dic in ret]
        elif isinstance(node, ast.BinOp):
            # TODO this resolution is not accurate, prefer to be covered
            ret = []
            for l in self.resolve_node(env, node.left):
                for r in self.resolve_node(env, node.right):
                    if isinstance(l, ast.Constant) and isinstance(r, ast.Constant):
                        expr = ast.BinOp(op=node.op, left=l, right=r)
                        ret.append(eval(ast.unparse(expr)))
                    else:
                        ret.append(l)
                        ret.append(r)
            return list(set(ret))
        elif isinstance(node, ast.UnaryOp):
            # TODO this resolution is not accurate, prefer to be covered
            ret = []
            for v in self.resolve_node(env, node.operand):
                if isinstance(v, ast.Constant):
                    expr = ast.UnaryOp(op=node.op, operand=v)
                    ret.append(eval(ast.unparse(expr)))
                else:
                    ret.append(v)
            return list(set(ret))

    def resolve_attribute(self, cls, attr: str) -> List:
        ...

    def resolve_subscript(self, env: PersistentMap, expr: ast.expr) -> List:
        ...

    def _const(self, v) -> ast.Constant:
        return ast.Constant(value=v)

    def analysis_stmt(self, stmt: ast.stmt, env: PersistentMap):
        if isinstance(stmt, ast.Assign):
            ...
        elif isinstance(stmt, ):
            ...
