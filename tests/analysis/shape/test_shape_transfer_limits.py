from types import SimpleNamespace

from pyflow.analysis.shape.constraintbuilder import ShapeConstraintBuilder, getLocals
from pyflow.language.python import ast


def _make_sys(compiler=None):
    return SimpleNamespace(extractor=SimpleNamespace(compiler=compiler))


def test_shape_transfer_limits_read_from_config(monkeypatch):
    monkeypatch.setattr("pyflow.config.shape_max_varg_transfer", 7)
    monkeypatch.setattr("pyflow.config.shape_max_vparam_transfer", 8)
    builder = ShapeConstraintBuilder(_make_sys(), invokeCallback=lambda code: code)
    assert builder.maxVArgLength() == 7
    assert builder.maxVParamLength() == 8


def test_shape_transfer_limits_compiler_overrides_config(monkeypatch):
    monkeypatch.setattr("pyflow.config.shape_max_varg_transfer", 7)
    monkeypatch.setattr("pyflow.config.shape_max_vparam_transfer", 8)
    compiler = SimpleNamespace(shape_max_varg_transfer=11, shape_max_vparam_transfer=12)
    builder = ShapeConstraintBuilder(
        _make_sys(compiler=compiler),
        invokeCallback=lambda code: code,
    )
    assert builder.maxVArgLength() == 11
    assert builder.maxVParamLength() == 12


def test_shape_transfer_limits_explicit_overrides_compiler_and_config(monkeypatch):
    monkeypatch.setattr("pyflow.config.shape_max_varg_transfer", 7)
    monkeypatch.setattr("pyflow.config.shape_max_vparam_transfer", 8)
    compiler = SimpleNamespace(shape_max_varg_transfer=11, shape_max_vparam_transfer=12)
    builder = ShapeConstraintBuilder(
        _make_sys(compiler=compiler),
        invokeCallback=lambda code: code,
        max_varg_transfer=15,
        max_vparam_transfer=16,
    )
    assert builder.maxVArgLength() == 15
    assert builder.maxVParamLength() == 16


def test_shape_constraint_builder_handles_declarations_and_type_syntax():
    builder = ShapeConstraintBuilder(_make_sys(), invokeCallback=lambda code: code)
    p = ast.TypeParam("T", None)
    tp = ast.TypeParams([p])
    ta = ast.TypeAlias("Point", [p], ast.Local("tuple"))
    gd = ast.GlobalDecl(ast.Local("g"))
    nd = ast.NonlocalDecl(ast.Local("n"))

    for node in (p, tp, ta, gd, nd):
        assert builder.visitDeclaration(node) is None

    # Verify getLocals traversal
    locals_found = getLocals(ta)
    assert any(isinstance(l, ast.Local) and l.name == "tuple" for l in locals_found)
