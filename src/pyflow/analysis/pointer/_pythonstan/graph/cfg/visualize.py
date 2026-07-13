import graphviz
from graphviz import Digraph
from typing import Dict

from pyflow.analysis.pointer._pythonstan.ir import IRScope, IRModule, IRClass, IRFunc
from .cfg import ControlFlowGraph


def new_digraph(name, filename, node_attr={}, edge_attr={}, graph_attr={}
                ) -> Digraph:
    n_attr = {'shape': 'record', 'fontsize': '8pt'}
    n_attr.update(node_attr)
    e_attr = {'fontsize': '7pt'}
    e_attr.update(edge_attr)
    g_attr = {'fontsize': '10pt', 'fontcolor': "blue"}
    g_attr.update(graph_attr)
    return graphviz.Digraph(name,
                            filename=filename,
                            node_attr=n_attr,
                            edge_attr=e_attr,
                            graph_attr=g_attr)


def draw_cfg(scope: IRScope, s: Digraph, info: Dict = {}):
    cfg = scope.cfg
    gen_id = lambda blk: f'{subg_name}_{blk.idx}'

    def gen_lab(blk):
        label = str(blk)
        if blk == cfg.entry_blk:
            label = "ENTRY"
        if blk == cfg.super_exit_blk:
            label = "EXIT"
        if blk in info:
            return f"{label} | {info[blk]}"
        else:
            return label

    subg_name = scope.get_name()
    for blk in cfg.blks:
        if blk == cfg.entry_blk:
            s.node(gen_id(blk), gen_lab(blk),
                   style='filled', fillcolor='honeydew2')
        elif blk == cfg.super_exit_blk:
            s.node(gen_id(blk), gen_lab(blk),
                   style='filled', fillcolor='honeydew2')
        elif blk in cfg.exit_blks:
            s.node(gen_id(blk), gen_lab(blk), style='filled', fillcolor='powderblue')
        else:
            s.node(gen_id(blk), gen_lab(blk), style='filled', fillcolor='ivory')
    for blk in cfg.blks:
        for e in cfg.out_edges_of(blk):
            src = gen_id(e.src)
            tgt = gen_id(e.tgt)
            s.edge(src, tgt, label=e.get_name())


def draw_module(mod: IRModule, s: Digraph, info: Dict = {}):
    with s.subgraph(name=mod.get_name(),
                    graph_attr={'label': mod.get_name(),
                                'cluster': 'true',
                                'bgcolor': 'gray50'}
                    ) as subs:
        draw_cfg(mod, subs, info)
        for cls in mod.classes:
            if cls in info:
                draw_class(cls, subs, info[cls])
            else:
                draw_class(cls, subs)
        for fn in mod.funcs:
            if fn in info:
                draw_function(fn, subs, info[fn])
            else:
                draw_function(fn, subs)


def draw_class(cls: IRClass, s: Digraph, info: Dict = {}):
    with s.subgraph(name=cls.get_name(),
                    graph_attr={'label': cls.get_name(),
                                'cluster': 'true',
                                'bgcolor': 'gray64'}
                    ) as subs:
        draw_cfg(cls, subs, info)
        for sub_cls in cls.classes:
            if sub_cls in info:
                draw_class(sub_cls, subs, info[sub_cls])
            else:
                draw_class(sub_cls, subs)
        for fn in cls.funcs:
            if fn in info:
                draw_function(fn, subs, info[fn])
            else:
                draw_function(fn, subs)


def draw_function(fn: IRFunc, s: Digraph, info: Dict = {}):
    with s.subgraph(name=fn.get_name(),
                    graph_attr={'label': fn.get_name(),
                                'cluster': 'true',
                                'bgcolor': 'gray78'}
                    ) as subs:
        draw_cfg(fn, subs, info)
        for cls in fn.classes:
            if cls in info:
                draw_class(cls, subs, info[cls])
            else:
                draw_class(cls, subs)
        for sub_fn in fn.funcs:
            if sub_fn in info:
                draw_function(sub_fn, subs, info[sub_fn])
            else:
                draw_function(sub_fn, subs)
