"""Shared best-effort preparation helpers for IFDS-backed entrypoints."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable, Sequence

from pyflow.application.errors import TemporaryLimitation

from .annotation_fallback import ensure_ifds_annotations_complete
from ..diagnostics import IFDSDiagnostic


@dataclass(frozen=True)
class PreparedIFDSArtifacts:
    """Recovered CFG set and any non-fatal diagnostics produced while preparing it."""

    cfgs: tuple[object, ...]
    diagnostics: tuple[IFDSDiagnostic, ...] = ()


class PreparationMode(str, Enum):
    """Failure policy for frontend and CFG preparation."""

    STRICT = "strict"
    BEST_EFFORT = "best_effort"


def prepare_program_for_ifds(
    compiler,
    program,
    *,
    get_cfg: Callable[[object], object],
    describe_code: Callable[[object], str],
    run_pipeline: Callable[[], None] | None = None,
    supplemental_live_codes: Sequence[object] = (),
    pipeline_label: str = "IPA/CPA",
    mode: PreparationMode = PreparationMode.BEST_EFFORT,
) -> PreparedIFDSArtifacts:
    """Prepare a program for IFDS analysis, recovering from non-fatal pipeline failures."""

    del compiler
    diagnostics: list[IFDSDiagnostic] = []
    pre_pipeline_live_codes = tuple(getattr(program, "liveCode", ()))

    if run_pipeline is not None:
        try:
            run_pipeline()
        except Exception as exc:
            if mode is PreparationMode.STRICT:
                raise
            diagnostics.append(
                IFDSDiagnostic(
                    severity="warning",
                    phase="pipeline",
                    message=(
                        "IFDS session fell back to best-effort mode after "
                        f"{pipeline_label} failure: {exc}"
                    ),
                    exception_type=type(exc).__name__,
                    subject=pipeline_label,
                    code="IFDS101",
                    affects_completeness=True,
                )
            )
            if pre_pipeline_live_codes:
                program.liveCode.update(pre_pipeline_live_codes)

    if supplemental_live_codes:
        program.liveCode.update(supplemental_live_codes)

    ensure_ifds_annotations_complete(tuple(getattr(program, "liveCode", ())))

    cfgs: list[object] = []
    for code in getattr(program, "liveCode", ()):
        try:
            cfgs.append(get_cfg(code))
        except Exception as exc:
            if mode is PreparationMode.STRICT:
                raise
            diagnostics.append(
                IFDSDiagnostic(
                    severity="warning",
                    phase="cfg",
                    message=f"Skipped IFDS CFG for {describe_code(code)}: {exc}",
                    exception_type=type(exc).__name__,
                    subject=describe_code(code),
                    code="IFDS102",
                    affects_completeness=True,
                )
            )

    if not cfgs:
        raise TemporaryLimitation("Unable to build any CFGs for IFDS analysis.")

    return PreparedIFDSArtifacts(tuple(cfgs), tuple(diagnostics))
