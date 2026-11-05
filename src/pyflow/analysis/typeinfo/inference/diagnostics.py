"""Registry of inference diagnostic codes.

Every code emitted by the inference engine is declared here with a category
and a one-line description, mirroring mypy's documented error-code taxonomy.
The registry is used for default severities, for ``--disable-diagnostic`` and
project configuration, and by tooling that renders or filters diagnostics.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DiagnosticSpec:
    """Description of one diagnostic code."""

    code: str
    category: str
    description: str
    severity: str = "warning"


_SPECS: tuple[DiagnosticSpec, ...] = (
    DiagnosticSpec(
        "annotation-mismatch",
        "type",
        "Inferred type is incompatible with the declared annotation.",
    ),
    DiagnosticSpec(
        "name-defined",
        "type",
        "An annotation references a name that cannot be resolved.",
    ),
    DiagnosticSpec(
        "union-attr",
        "type",
        "Attribute access on a union member that cannot provide it.",
    ),
    DiagnosticSpec(
        "attr-defined",
        "type",
        "Attribute is not defined on a fully known receiver type.",
    ),
    DiagnosticSpec(
        "index",
        "type",
        "Index type is incompatible with the container's element/key type.",
    ),
    DiagnosticSpec(
        "typed-dict-key",
        "type",
        "TypedDict access with an unknown key.",
    ),
    DiagnosticSpec(
        "format-string-mismatch",
        "type",
        "str.format or printf-style field does not match its arguments.",
    ),
    DiagnosticSpec(
        "assignment",
        "type",
        "A variable is rebound to an incompatible type in the same block.",
    ),
    DiagnosticSpec(
        "override",
        "type",
        "Method signature is incompatible with the overridden supertype method.",
    ),
    DiagnosticSpec(
        "call-arity-mismatch",
        "call",
        "Call passes the wrong number of positional or keyword arguments.",
    ),
    DiagnosticSpec(
        "missing-external-type",
        "gradual",
        "Annotation refers to a dependency with no available type facts.",
    ),
    DiagnosticSpec(
        "unresolved-annotation",
        "gradual",
        "A project or stdlib symbol could not be resolved during analysis.",
    ),
    DiagnosticSpec(
        "unmodeled-context-manager",
        "gradual",
        "Context manager protocol could not be modelled.",
    ),
    DiagnosticSpec(
        "unsupported-expression",
        "coverage",
        "Expression form has no type model yet.",
    ),
    DiagnosticSpec(
        "unsupported-statement",
        "coverage",
        "Statement form has no type model yet.",
    ),
    DiagnosticSpec(
        "loop-widened",
        "coverage",
        "A loop body widened to an imprecise type.",
    ),
    DiagnosticSpec(
        "specialization-budget-exceeded",
        "coverage",
        "Per-function specialisation budget was exhausted.",
    ),
    DiagnosticSpec(
        "inference-did-not-converge",
        "coverage",
        "The fixed-point solver hit its iteration limit.",
    ),
    DiagnosticSpec(
        "call-model-error",
        "plugin",
        "A registered call-model provider raised an exception.",
    ),
)

DIAGNOSTICS: dict[str, DiagnosticSpec] = {spec.code: spec for spec in _SPECS}


def diagnostic_spec(code: str) -> DiagnosticSpec | None:
    """Return the registry entry for *code*, if it is declared."""
    return DIAGNOSTICS.get(code)
