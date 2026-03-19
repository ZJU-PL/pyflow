"""Shared best-effort preparation helpers for IFDS-backed entrypoints."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Sequence

from pyflow.application.errors import TemporaryLimitation

from .annotation_fallback import ensure_ifds_annotations_complete


@dataclass(frozen=True)
class PreparedIFDSArtifacts:
    """Recovered CFG set and any non-fatal diagnostics produced while preparing it."""

    cfgs: tuple[object, ...]
    diagnostics: tuple[str, ...] = ()


def prepare_program_for_ifds(
    compiler,
    program,
    *,
    get_cfg: Callable[[object], object],
    describe_code: Callable[[object], str],
    run_pipeline: Callable[[], None] | None = None,
    supplemental_live_codes: Sequence[object] = (),
    pipeline_label: str = "IPA/CPA",
) -> PreparedIFDSArtifacts:
    """Prepare a program for IFDS analysis, recovering from non-fatal pipeline failures."""

    del compiler
    diagnostics: list[str] = []
    pre_pipeline_live_codes = tuple(getattr(program, "liveCode", ()))

    if run_pipeline is not None:
        try:
            run_pipeline()
        except Exception as exc:
            diagnostics.append(
                "IFDS session fell back to best-effort mode after "
                f"{pipeline_label} failure: {exc}"
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
            diagnostics.append(
                f"Skipped IFDS CFG for {describe_code(code)}: {exc}"
            )

    if not cfgs:
        raise TemporaryLimitation("Unable to build any CFGs for IFDS analysis.")

    return PreparedIFDSArtifacts(tuple(cfgs), tuple(diagnostics))
