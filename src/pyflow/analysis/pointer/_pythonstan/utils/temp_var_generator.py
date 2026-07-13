import copy
import ast
from typing import Dict

TEMP_VAR_TEMPLATE = "$tmp_%d"

def destructable(node):
    return isinstance(node, ast.Tuple) or isinstance(node, ast.List)


def update_ctx(node, ctx):
    new_node = copy.deepcopy(node)
    if hasattr(node, 'ctx'):
        new_node.ctx = ctx
    return new_node


class TempVarGenerator:
    next_idx: int
    template: str
    var_dict: Dict[str, Dict[str, ast.Name]]

    @staticmethod
    def get_ctx_name(ctx):
        return ctx.__class__.__name__

    def __init__(self, next_idx=0, template=TEMP_VAR_TEMPLATE):
        self.reset(next_idx, template)
    
    def reset(self, next_idx=0, template=TEMP_VAR_TEMPLATE):
        self.next_idx = next_idx
        self.template = template
        self.var_dict = {
            'Store': {},
            'Load': {},
            'Del': {}
        }

    def gen(self, idx=None, ctxs=None):
        if ctxs is None:
            ctxs = [ast.Load(), ast.Store()]
        if idx is None:
            idx = self.gen_idx()
        var_name = self.template % (idx,)
        ret = []
        for ctx in ctxs:
            cname = self.get_ctx_name(ctx)
            var = ast.Name(id=var_name, ctx=ctx)
            self.var_dict[cname][var_name] = var
            ret.append(var)
        return ret
    
    def __call__(self, *args, **kwargs):
        return self.gen(*args, **kwargs)
    
    def gen_idx(self):
        idx = self.next_idx
        self.next_idx += 1
        return idx

    def get(self, var, ctx):
        if isinstance(var.ctx, ctx.__class__):
            return var
        id = var.id
        cname = self.get_ctx_name(ctx)
        if id not in self.var_dict[cname]:
            self.var_dict[cname][id] = ast.Name(id=id, ctx=ctx)
        return self.var_dict[cname][id]
