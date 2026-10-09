"""Unproven variadic argument shapes cannot justify a signature rewrite."""

import io

from pyflow.application.context import CompilerContext
from pyflow.application.program import Program
from pyflow.ir.core import index_program
from pyflow.language.python import ast
from pyflow.optimization import argumentnormalization
from pyflow.util.application.console import Console


def test_missing_reference_facts_skip_optional_normalization_without_mutating_code():
    args = ast.Local("args")
    parameters = ast.CodeParameters(None, [], [], [], [], [], args, None, [], None)
    code = ast.Code("variadic", parameters, ast.Suite([ast.Return([args])]))
    program = Program()
    program.liveCode = {code}
    index_program(program)
    output = io.StringIO()
    compiler = CompilerContext(Console(out=output))
    assert argumentnormalization.evaluate(compiler, program) is False
    assert code.codeparameters is parameters
    assert code.codeparameters.vparam is args
    assert "incomplete analysis facts" in output.getvalue()
