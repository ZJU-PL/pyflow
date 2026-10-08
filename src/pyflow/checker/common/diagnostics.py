"""Engine-neutral diagnostic records and serialization."""

from collections.abc import Mapping
from dataclasses import asdict, dataclass, is_dataclass


@dataclass(frozen=True)
class CheckerDiagnostic:
    message: str
    code: str
    affects_completeness: bool = False
    function: str | None = None
    level: str | None = None
    filename: str | None = None
    line: int | None = None
    operation: str | None = None


def diagnostics_to_dicts(diagnostics):
    """Preserve structured diagnostics when combining native and serialized results."""
    return [
        (
            dict(diagnostic)
            if isinstance(diagnostic, Mapping)
            else (
                asdict(diagnostic)
                if is_dataclass(diagnostic)
                else diagnostic.to_dict() if hasattr(diagnostic, "to_dict") else str(diagnostic)
            )
        )
        for diagnostic in diagnostics
    ]


def affects_completeness(diagnostic):
    if isinstance(diagnostic, Mapping):
        return bool(diagnostic.get("affects_completeness", False))
    return bool(getattr(diagnostic, "affects_completeness", False))
