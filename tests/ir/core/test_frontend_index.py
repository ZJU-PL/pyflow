import os
import re
import subprocess
import sys

from pyflow.application import context
from pyflow.frontend.extractor import Extractor
from pyflow.ir.cfg import transform
from pyflow.ir.core import (
    RebuildProvenanceSeed,
    SymbolKind,
    SyntheticOrigin,
    TransformationFrame,
    index_cfg,
    rebuild_program_ir,
    verify_catalog,
)
from pyflow.language.python import ast


def _walk(node):
    if node is None or isinstance(node, ast.leafTypes):
        return
    if isinstance(node, (list, tuple)):
        for item in node:
            yield from _walk(item)
        return
    yield node
    if isinstance(node, ast.Code):
        return
    for child in node.children():
        yield from _walk(child)


def test_frontend_indexes_source_bindings_and_occurrences():
    compiler = context.CompilerContext(None)
    extractor = Extractor(compiler, verbose=False)
    program = extractor.extract_from_source(
        "def main(box):\n    other = box\n    return other\n",
        "example.py",
    )
    code = next(code for code in program.liveCode if code.codeName() == "main")

    locals_ = [node for node in _walk(code.ast) if isinstance(node, ast.Local)]
    by_name = {}
    for local in locals_:
        by_name.setdefault(local.name, set()).add(program.ir.symbol_id(local))

    assert len(by_name["box"]) == 1
    assert len(by_name["other"]) == 1
    box_symbol = program.ir.symbol_for(code.codeparameters.params[0])
    assert box_symbol.kind is SymbolKind.PARAMETER
    assert by_name["box"] == {box_symbol.id}
    verify_catalog(program.ir)


def test_frontend_ir_ids_are_deterministic_across_extractions():
    def extract_ids():
        compiler = context.CompilerContext(None)
        program = Extractor(compiler, verbose=False).extract_from_source(
            "def main(value):\n    result = value\n    return result\n",
            "same.py",
        )
        return (
            tuple(procedure.code_id for procedure in program.ir.procedures()),
            tuple(symbol.id for symbol in program.ir.symbols),
            tuple(node_id for node_id, _node in program.ir.nodes()),
        )

    assert extract_ids() == extract_ids()


def test_cfg_index_assigns_deterministic_block_and_edge_ids():
    def extract_graph_ids():
        compiler = context.CompilerContext(None)
        program = Extractor(compiler, verbose=False).extract_from_source(
            "def main(flag):\n    if flag:\n        return 1\n    return 2\n",
            "same.py",
        )
        code = next(code for code in program.liveCode if code.codeName() == "main")
        cfg = transform.evaluate(compiler, code)
        index_cfg(program.ir, cfg)
        code_id = program.ir.procedure(code).code_id
        blocks = tuple(
            identity for identity, _block in program.ir.blocks()
            if identity.code == code_id
        )
        edges = tuple(
            identity for identity, _edge in program.ir.edges()
            if identity.source.code == code_id
        )
        return blocks, edges

    assert extract_graph_ids() == extract_graph_ids()


def test_catalog_rebuild_preserves_source_and_records_transform_provenance():
    compiler = context.CompilerContext(None)
    program = Extractor(compiler, verbose=False).extract_from_source(
        "def main(value):\n    result = value\n    return result\n",
        "same.py",
    )
    code = next(code for code in program.liveCode if code.codeName() == "main")
    operation = code.ast.blocks[0]
    old_id = program.ir.node_id(operation, code)
    old_origin = program.ir.source_of(old_id)
    program.ir.source_map.append_provenance(
        old_id, TransformationFrame("frontend-test")
    )
    generated_origin = SyntheticOrigin("rewritten for test")

    rebuilt = rebuild_program_ir(
        program,
        provenance_seeds=(
            RebuildProvenanceSeed(
                operation,
                code,
                generated_origin,
                (old_id,),
                "test-rewrite",
                "preserve metadata",
            ),
        ),
    )
    rebuilt_id = rebuilt.node_id(operation, code)

    assert old_origin is not None
    assert rebuilt.source_of(rebuilt_id) == generated_origin
    assert rebuilt.provenance_of(rebuilt_id)[0].kind == "frontend-test"
    assert rebuilt.provenance_of(rebuilt_id)[-1] == TransformationFrame(
        "test-rewrite",
        inputs=(old_id,),
        source=generated_origin,
        detail="preserve metadata",
    )


def test_ir_and_graph_snapshots_are_cross_process_deterministic():
    script = r'''
import json
from pyflow.application import context
from pyflow.frontend.extractor import Extractor
from pyflow.ir.cfg import transform
from pyflow.ir.core import index_cfg
from pyflow.ir.cdg import construct_cdg
from pyflow.ir.dataflow import convert
from pyflow.ir.ddg import construct_ddg

compiler = context.CompilerContext(None)
compiler.extractor = Extractor(compiler, verbose=False)
program = compiler.extractor.extract_from_source(
    "def main(flag, value):\n"
    "    if flag:\n"
    "        result = value\n"
    "    else:\n"
    "        result = 0\n"
    "    return result\n",
    "stable.py",
)
code = next(code for code in program.liveCode if code.codeName() == "main")
cfg = transform.evaluate(compiler, code)
index_cfg(program.ir, cfg)
cdg = construct_cdg(cfg)
ddg = construct_ddg(convert.evaluateCode(compiler, code))
payload = {
    "codes": [str(item.code_id) for item in program.ir.procedures()],
    "nodes": [str(identity) for identity, _node in program.ir.nodes()],
    "blocks": [str(identity) for identity, _block in program.ir.blocks()],
    "edges": [str(identity) for identity, _edge in program.ir.edges()],
    "cdg_nodes": sorted(str(node.block_id) for node in cdg.get_all_nodes()),
    "cdg_edges": [
        [str(edge.source.block_id), str(edge.target.block_id), edge.label]
        for edge in cdg.get_all_edges()
    ],
    "ddg_nodes": [
        [node.stable_id, node.category, repr(node.ir_node)] for node in ddg.nodes
    ],
    "ddg_edges": [
        [edge.source.stable_id, edge.target.stable_id, edge.kind, edge.label]
        for edge in ddg.all_edges()
    ],
}
print("SNAPSHOT=" + json.dumps(payload, sort_keys=True))
'''

    def snapshot(seed: str) -> str:
        environment = dict(os.environ)
        environment["PYTHONHASHSEED"] = seed
        environment["PYTHONPATH"] = os.path.abspath("src")
        completed = subprocess.run(
            [sys.executable, "-c", script],
            check=True,
            capture_output=True,
            text=True,
            env=environment,
        )
        return next(
            line.removeprefix("SNAPSHOT=")
            for line in completed.stdout.splitlines()
            if line.startswith("SNAPSHOT=")
        )

    first = snapshot("1")
    second = snapshot("987654")

    assert first == second
    assert re.search(r"0x[0-9a-fA-F]{6,}", first) is None
    assert re.search(r"Local\([^)]*/[0-9]{6,}\)", first) is None
