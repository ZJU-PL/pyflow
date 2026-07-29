from __future__ import annotations

from pyflow.ir.cfg import transform
from pyflow.language.python import ast


def make_code(name: str, params, body_blocks, *, return_name: str = "ret0"):
    return_param = ast.Local(return_name)
    code = ast.Code(
        name,
        ast.CodeParameters(
            selfparam=None,
            posonlyparams=[],
            posonlynames=[],
            params=list(params),
            paramnames=[param.name for param in params],
            defaults=[],
            vparam=None,
            kparam=None,
            returnparams=[return_param],
            type_params=None,
        ),
        ast.Suite(list(body_blocks)),
    )
    return code, return_param


def build_cfg(compiler, code):
    return transform.evaluate(compiler, code)


def call_stmt(callee_code, args, targets=()):
    direct = ast.DirectCall(callee_code, None, list(args), [], None, None)
    if targets:
        return ast.Assign(direct, list(targets))
    return ast.Discard(direct)
