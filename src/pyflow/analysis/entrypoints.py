"""Engine-independent procedure entry-point selection.

The selector intentionally knows nothing about ASTs, CFGs, CPGs, or taint
facts.  Frontends describe their procedures and call edges, then map the
selected identities back to their native graph nodes.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import os
from typing import Generic, Hashable, Iterable, TypeVar


ProcedureT = TypeVar("ProcedureT", bound=Hashable)


class EntryPointMode(str, Enum):
    """Supported policies for choosing externally reachable procedures."""

    DECLARED_ONLY = "declared-only"
    INFERRED_ROOTS = "inferred-roots"
    DECLARED_PLUS_ROOTS = "declared-plus-roots"
    FILE_PUBLIC = "file-public"
    ALL_PROCEDURES = "all-procedures"


@dataclass(frozen=True)
class EntryPointOptions:
    """Shared entry selection and boundary-taint configuration.

    ``taint_parameters`` is deliberately not interpreted by the selector.  It
    is carried alongside selection so each analysis can seed its own native
    domain without duplicating entry inference.
    """

    mode: EntryPointMode = EntryPointMode.DECLARED_ONLY
    files: tuple[str, ...] = ()
    include_synthetic_modules: bool = True
    taint_parameters: bool = False


@dataclass(frozen=True)
class EntryPointDefaults:
    """Optional rule-pack defaults applied below explicit runtime options."""

    mode: EntryPointMode | None = None
    include_synthetic_modules: bool | None = None
    taint_parameters: bool | None = None

    def resolve(self, fallback: EntryPointOptions) -> EntryPointOptions:
        return EntryPointOptions(
            mode=self.mode if self.mode is not None else fallback.mode,
            files=fallback.files,
            include_synthetic_modules=(
                self.include_synthetic_modules
                if self.include_synthetic_modules is not None
                else fallback.include_synthetic_modules
            ),
            taint_parameters=(
                self.taint_parameters
                if self.taint_parameters is not None
                else fallback.taint_parameters
            ),
        )

    def overlay(self, override: "EntryPointDefaults") -> "EntryPointDefaults":
        """Apply later rule-pack defaults over earlier ones."""

        return EntryPointDefaults(
            mode=override.mode if override.mode is not None else self.mode,
            include_synthetic_modules=(
                override.include_synthetic_modules
                if override.include_synthetic_modules is not None
                else self.include_synthetic_modules
            ),
            taint_parameters=(
                override.taint_parameters
                if override.taint_parameters is not None
                else self.taint_parameters
            ),
        )


@dataclass(frozen=True)
class ProcedureDescriptor(Generic[ProcedureT]):
    """Minimal, engine-neutral description of one analyzable procedure."""

    identity: ProcedureT
    qualified_name: str
    filename: str | None = None
    callees: frozenset[ProcedureT] = frozenset()
    declared: bool = False
    synthetic_module: bool = False


@dataclass(frozen=True)
class SelectedEntryPoint(Generic[ProcedureT]):
    identity: ProcedureT
    reason: str


def select_entry_points(
    procedures: Iterable[ProcedureDescriptor[ProcedureT]],
    options: EntryPointOptions,
) -> tuple[SelectedEntryPoint[ProcedureT], ...]:
    """Select entries in descriptor order according to ``options``."""

    ordered = tuple(procedures)
    identities = {procedure.identity for procedure in ordered}
    incoming = {identity: 0 for identity in identities}
    for procedure in ordered:
        for callee in procedure.callees:
            if callee in incoming:
                incoming[callee] += 1

    target_files = {os.path.realpath(path) for path in options.files}
    selected: list[SelectedEntryPoint[ProcedureT]] = []
    for procedure in ordered:
        if procedure.synthetic_module and not options.include_synthetic_modules:
            continue
        is_root = incoming[procedure.identity] == 0
        in_file = bool(
            procedure.filename and os.path.realpath(procedure.filename) in target_files
        )
        reason: str | None = None
        if options.mode is EntryPointMode.DECLARED_ONLY and procedure.declared:
            reason = "declared"
        elif options.mode is EntryPointMode.INFERRED_ROOTS and is_root:
            reason = "inferred-root"
        elif options.mode is EntryPointMode.DECLARED_PLUS_ROOTS:
            if procedure.declared:
                reason = "declared"
            elif is_root:
                reason = "inferred-root"
        elif options.mode is EntryPointMode.FILE_PUBLIC and in_file:
            reason = "file-public"
        elif options.mode is EntryPointMode.ALL_PROCEDURES:
            reason = "all-procedures"
        if reason is not None:
            selected.append(SelectedEntryPoint(procedure.identity, reason))
    return tuple(selected)


__all__ = [
    "EntryPointMode",
    "EntryPointDefaults",
    "EntryPointOptions",
    "ProcedureDescriptor",
    "SelectedEntryPoint",
    "select_entry_points",
]
