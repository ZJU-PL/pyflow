from __future__ import annotations

from pyflow.application import context
from pyflow.checker.class_pollution import (
    ClassPollutionConfiguration,
    PollutionRole,
    analyze_class_pollution,
)
from pyflow.analysis.ifds import build_supergraph_from_cfgs
from pyflow.language.python import ast

from tests.analysis.ifds._support import build_cfg, call_stmt, make_code


def _call(name, arguments, targets=()):
    call = ast.Call(ast.Local(name), list(arguments), [], None, None)
    return ast.Assign(call, list(targets)) if targets else ast.Discard(call)


def _analyze(codes, configuration=None):
    compiler = context.CompilerContext(None)
    cfgs = [build_cfg(compiler, code) for code in codes]
    adapter = build_supergraph_from_cfgs(cfgs)
    return analyze_class_pollution(
        adapter,
        configuration,
        entry_nodes=[adapter.supergraph.entry_of(cfgs[0])],
    )


def test_dynamic_getter_path_and_write_is_class_pollution():
    obj = ast.Local("obj")
    key = ast.Local("key")
    value = ast.Local("value")
    target = ast.Local("target")
    main, _ = make_code(
        "main",
        [obj, key, value],
        [
            _call("getattr", [obj, key], [target]),
            _call("setattr", [target, key, value]),
        ],
    )

    result = _analyze([main])

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.proof_level == "pollutable-object"
    assert finding.mutation_kind == "attribute"
    assert finding.key_origin.label == "key"
    assert finding.object_path[0].kind == "attribute"
    assert finding.object_path[0].key_language.may_contain_magic()


def test_plain_dynamic_setattr_is_not_mislabeled_as_class_pollution():
    obj = ast.Local("obj")
    key = ast.Local("key")
    value = ast.Local("value")
    main, _ = make_code(
        "main",
        [obj, key, value],
        [_call("setattr", [obj, key, value])],
    )

    result = _analyze([main])

    assert result.findings == ()


def test_static_class_traversal_plus_controlled_write_is_reported():
    obj = ast.Local("obj")
    key = ast.Local("key")
    value = ast.Local("value")
    target = ast.Local("target")
    class_name = ast.Existing(ast.program.Object("__class__"))
    main, _ = make_code(
        "main",
        [obj, key, value],
        [
            ast.Assign(ast.GetAttr(obj, class_name), [target]),
            _call("setattr", [target, key, value]),
        ],
    )

    result = _analyze([main])

    assert len(result.findings) == 1
    assert "__class__" in result.findings[0].dangerous_components
    assert result.findings[0].confidence == "high"


def test_global_namespace_path_is_ranked_as_gadget_reachable():
    obj = ast.Local("obj")
    key = ast.Local("key")
    value = ast.Local("value")
    target = ast.Local("target")
    globals_name = ast.Existing(ast.program.Object("__globals__"))
    main, _ = make_code(
        "main",
        [obj, key, value],
        [
            ast.Assign(ast.GetAttr(obj, globals_name), [target]),
            _call("setattr", [target, key, value]),
        ],
    )

    result = _analyze([main])

    assert len(result.findings) == 1
    assert result.findings[0].proof_level == "gadget-reachable"
    assert result.findings[0].severity == "critical"


def test_allowlisted_key_language_blocks_magic_path():
    obj = ast.Local("obj")
    raw = ast.Local("raw")
    key = ast.Local("key")
    value = ast.Local("value")
    target = ast.Local("target")
    main, _ = make_code(
        "main",
        [obj, raw, value],
        [
            _call("allow_key", [raw], [key]),
            _call("getattr", [obj, key], [target]),
            _call("setattr", [target, key, value]),
        ],
    )
    config = ClassPollutionConfiguration(
        key_allowlists={"allow_key": frozenset({"name", "title"})}
    )

    result = _analyze([main], config)

    assert result.findings == ()


def test_dynamic_item_path_and_subscript_write_is_reported():
    obj = ast.Local("obj")
    key = ast.Local("key")
    value = ast.Local("value")
    target = ast.Local("target")
    main, _ = make_code(
        "main",
        [obj, key, value],
        [
            ast.Assign(ast.GetSubscript(obj, key), [target]),
            ast.SetSubscript(value, target, key),
        ],
    )

    result = _analyze([main])

    assert len(result.findings) == 1
    assert result.findings[0].mutation_kind == "item"
    assert result.findings[0].sink_name == "subscript-assignment"


def test_direct_dunder_dict_item_write_is_reported():
    obj = ast.Local("obj")
    key = ast.Local("key")
    value = ast.Local("value")
    dunder_dict = ast.GetAttr(
        obj, ast.Existing(ast.program.Object("__dict__"))
    )
    main, _ = make_code(
        "main",
        [obj, key, value],
        [ast.SetSubscript(value, dunder_dict, key)],
    )

    result = _analyze([main])

    assert len(result.findings) == 1
    assert "__dict__" in result.findings[0].dangerous_components


def test_vars_namespace_update_is_reported():
    obj = ast.Local("obj")
    data = ast.Local("data")
    namespace = ast.Local("namespace")
    main, _ = make_code(
        "main",
        [obj, data],
        [
            _call("vars", [obj], [namespace]),
            ast.Discard(
                ast.Call(
                    ast.GetAttr(
                        namespace,
                        ast.Existing(ast.program.Object("update")),
                    ),
                    [data],
                    [],
                    None,
                    None,
                )
            ),
        ],
    )

    result = _analyze([main])

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
            _call("setattr", [target, external_key, value]),
        ],
    )

    result = _analyze([main, helper])

    assert len(result.findings) == 1
    facts = result._ifds_result.facts_at(result.findings[0].sink)
    assert any(
        getattr(fact, "role", None) is PollutionRole.TARGET_OBJECT for fact in facts
    )
