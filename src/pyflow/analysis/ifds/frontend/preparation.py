"""Strict preparation helpers for IFDS-backed entrypoints."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Sequence

from pyflow.application.errors import TemporaryLimitation

from ..diagnostics import IFDSDiagnostic


@dataclass(frozen=True)
class PreparedIFDSArtifacts:
    """Recovered CFG set and any non-fatal diagnostics produced while preparing it."""

    cfgs: tuple[object, ...]
    diagnostics: tuple[IFDSDiagnostic, ...] = ()
    catalog: object | None = None


def prepare_program_for_ifds(
    compiler,
    program,
    *,
    get_cfg: Callable[[object], object],
    run_pipeline: Callable[[], None] | None = None,
    supplemental_live_codes: Sequence[object] = (),
) -> PreparedIFDSArtifacts:
    """Prepare a complete program for IFDS or propagate the original failure."""

    del compiler

    if run_pipeline is not None:
        run_pipeline()

    if supplemental_live_codes:
        program.liveCode.update(supplemental_live_codes)

    cfgs = [get_cfg(code) for code in getattr(program, "liveCode", ())]

    if not cfgs:
        raise TemporaryLimitation("Unable to build any CFGs for IFDS analysis.")

    from pyflow.ir.core import ensure_codes_indexed, index_cfg

    from pyflow.language.python import ast as py_ast

    indexed_codes = tuple(
        cfg.code
        for cfg in cfgs
        if isinstance(getattr(cfg, "code", None), py_ast.Code)
    )
    if indexed_codes:
        program.ir = ensure_codes_indexed(
            indexed_codes, rebuild_semantics=False
        )
        for cfg in cfgs:
            if isinstance(getattr(cfg, "code", None), py_ast.Code):
                index_cfg(program.ir, cfg, rebuild_semantics=False)

        from pyflow.ir.core.build_semantics import build_semantics

        build_semantics(program.ir)

    return PreparedIFDSArtifacts(
        tuple(cfgs), catalog=getattr(program, "ir", None)
    )
