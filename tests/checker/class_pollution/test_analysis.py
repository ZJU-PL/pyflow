from __future__ import annotations

from pyflow.application import context
from pyflow.checker.class_pollution import (
    ClassPollutionConfiguration,
    PollutionRole,
    analyze_class_pollution,
)
from pyflow.analysis.ifds import build_supergraph_from_cfgs
from pyflow.frontend.extractor import Extractor
from pyflow.ir.cfg import transform
from pyflow.language.python import ast

from tests.analysis.ifds._support import build_cfg, call_stmt, make_code


def _analyze_source(source, configuration=None):
    compiler = context.CompilerContext(None)
    program = Extractor(compiler, verbose=False).extract_from_source(
        source,
        "class_pollution.py",
    )
    codes = tuple(program.liveCode)
    cfgs = [transform.evaluate(compiler, code) for code in codes]
    adapter = build_supergraph_from_cfgs(cfgs)
    main_cfg = next(cfg for cfg in cfgs if cfg.code.name == "main")
    return analyze_class_pollution(
        adapter,
        configuration,
        entry_nodes=[adapter.supergraph.entry_of(main_cfg)],
    )


def test_dynamic_getter_path_and_write_is_class_pollution():
    result = _analyze_source(
        """
def main(obj, key, value):
    target = getattr(obj, key)
    setattr(target, key, value)
"""
    )

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.proof_level == "pollutable-object"
    assert finding.mutation_kind == "attribute"
    assert finding.key_origin.label == "key"
    assert finding.object_path[0].kind == "attribute"
    assert finding.object_path[0].key_language.may_contain_magic()


def test_plain_dynamic_setattr_is_not_mislabeled_as_class_pollution():
    result = _analyze_source(
        """
def main(obj, key, value):
    setattr(obj, key, value)
"""
    )

    assert result.findings == ()


def test_static_class_traversal_plus_controlled_write_is_reported():
    result = _analyze_source(
        """
def main(obj, key, value):
    target = obj.__class__
    setattr(target, key, value)
"""
    )

    assert len(result.findings) == 1
    assert "__class__" in result.findings[0].dangerous_components
    assert result.findings[0].confidence == "high"


def test_global_namespace_path_is_ranked_as_gadget_reachable():
    result = _analyze_source(
        """
def main(obj, key, value):
    target = obj.__globals__
    setattr(target, key, value)
"""
    )

    assert len(result.findings) == 1
    assert result.findings[0].proof_level == "gadget-reachable"
    assert result.findings[0].severity == "critical"


def test_allowlisted_key_language_blocks_magic_path():
    config = ClassPollutionConfiguration(
        key_allowlists={"allow_key": frozenset({"name", "title"})}
    )
    result = _analyze_source(
        """
def main(obj, raw, value):
    key = allow_key(raw)
    target = getattr(obj, key)
    setattr(target, key, value)
""",
        config,
    )

    assert result.findings == ()


def test_dynamic_item_path_and_subscript_write_is_reported():
    result = _analyze_source(
        """
def main(obj, key, value):
    target = obj[key]
    target[key] = value
"""
    )

    assert len(result.findings) == 1
    assert result.findings[0].mutation_kind == "item"
    assert result.findings[0].sink_name == "subscript-assignment"


def test_direct_dunder_dict_item_write_is_reported():
    result = _analyze_source(
        """
def main(obj, key, value):
    obj.__dict__[key] = value
"""
    )

    assert len(result.findings) == 1
    assert "__dict__" in result.findings[0].dangerous_components


def test_vars_namespace_update_is_reported():
    result = _analyze_source(
        """
def main(obj, data):
    namespace = vars(obj)
    namespace.update(data)
"""
    )

    assert len(result.findings) == 1
    assert result.findings[0].mutation_kind == "namespace"


def test_interprocedural_target_path_is_preserved():
    obj = ast.Local("obj")
    key = ast.Local("key")
    helper, _ = make_code(
        "descend",
        [obj, key],
        [ast.Return([ast.Call(ast.Local("getattr"), [obj, key], [], None, None)])],
    )
    root = ast.Local("root")
    external_key = ast.Local("external_key")
    value = ast.Local("value")
    target = ast.Local("target")
    main, _ = make_code(
        "main",
        [root, external_key, value],
        [
            call_stmt(helper, [root, external_key], [target]),
            ast.Discard(
                ast.Call(
                    ast.Local("setattr"),
                    [target, external_key, value],
                    [],
                    None,
                    None,
                )
            ),
        ],
    )
    compiler = context.CompilerContext(None)
    helper_cfg = build_cfg(compiler, helper)
    main_cfg = build_cfg(compiler, main)
    adapter = build_supergraph_from_cfgs([main_cfg, helper_cfg])
    result = analyze_class_pollution(
        adapter,
        entry_nodes=[adapter.supergraph.entry_of(main_cfg)],
    )

    assert len(result.findings) == 1
    facts = result._ifds_result.facts_at(result.findings[0].sink)
    assert any(
        getattr(fact, "role", None) is PollutionRole.TARGET_OBJECT for fact in facts
    )
