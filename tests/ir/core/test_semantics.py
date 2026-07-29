from pyflow.application import context
from pyflow.frontend.extractor import Extractor
from pyflow.ir.core import LocalStorage, UnknownStorage
from pyflow.language.python import ast


def _program(source):
    compiler = context.CompilerContext(None)
    return Extractor(compiler, verbose=False).extract_from_source(source, "facts.py")


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


def test_baseline_semantics_use_shared_symbols_for_def_use():
    program = _program("def main(box):\n    other = box\n    return other\n")
    code = next(code for code in program.liveCode if code.codeName() == "main")
    assignment = next(node for node in _walk(code.ast) if isinstance(node, ast.Assign))
    facts = program.ir.semantics.operation(program.ir.node_id(assignment))

    box = program.ir.symbol_id(assignment.expr)
    other = program.ir.symbol_id(assignment.lcls[0])
    assert facts.uses == (box,)
    assert facts.definitions == (other,)
    assert facts.reads == (LocalStorage(box),)
    assert facts.writes == (LocalStorage(other),)


def test_call_sites_are_explicit_and_conservatively_incomplete():
    program = _program("def main(value):\n    return sink(value)\n")
    code = next(code for code in program.liveCode if code.codeName() == "main")
    call = next(node for node in _walk(code.ast) if isinstance(node, ast.Call))
    facts = program.ir.semantics.operation(program.ir.node_id(call))

    assert len(facts.calls) == 1
    assert facts.complete is False
    assert UnknownStorage("call-write") in facts.writes
    site = program.ir.semantics.call_site(facts.calls[0])
    assert site.operation == program.ir.node_id(call)
    assert len(site.positional_arguments) == 1
