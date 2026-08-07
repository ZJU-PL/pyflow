from pyflow.analysis.astcollector import getOps
from pyflow.language.python import ast


def test_get_ops_handles_deeply_nested_control_flow_iteratively():
    body = ast.Suite()
    for index in range(1500):
        condition = ast.Condition(ast.Suite(), ast.Local(f"condition_{index}"))
        body = ast.Suite([ast.Switch(condition, ast.Suite(), body)])

    operations, locals_ = getOps(body)

    assert operations == []
    assert len(locals_) == 1500
