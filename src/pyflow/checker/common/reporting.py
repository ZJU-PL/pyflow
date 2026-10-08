"""Shared result metadata; contains no engine or transport dependencies."""

from dataclasses import asdict, is_dataclass


def result_status(result) -> tuple[str, str | None]:
    status = getattr(result, "status", "complete")
    return getattr(status, "value", str(status)), getattr(result, "termination_reason", None)


def statistics_to_dict(statistics) -> dict:
    if is_dataclass(statistics):
        return asdict(statistics)
    if hasattr(statistics, "__dict__"):
        return dict(vars(statistics))
    return dict(statistics)


def code_name(code) -> str:
    if hasattr(code, "codeName"):
        return code.codeName()
    if hasattr(code, "__name__"):
        return code.__name__
    return str(code)
