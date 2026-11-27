"""Typed keys and capability names for context-sensitive analysis results."""

from __future__ import annotations

from dataclasses import dataclass

from .ids import CodeId, ContextId, NodeId, SymbolId


class Capabilities:
    CONTEXTS = "analysis.contexts"
    REFERENCES = "analysis.references"
    CALL_TARGETS = "analysis.call_targets"
    CALL_TARGET_CODES = "analysis.call_target_codes"
    IPA_SUMMARIES = "ipa.summaries"
    OP_READS = "analysis.operation.reads"
    OP_WRITES = "analysis.operation.writes"
    OP_ALLOCATIONS = "analysis.operation.allocations"
    CODE_READS = "analysis.code.reads"
    CODE_WRITES = "analysis.code.writes"
    CODE_ALLOCATIONS = "analysis.code.allocations"
    LIFETIME_CODE_LIVE = "lifetime.code.live"
    LIFETIME_CODE_KILLED = "lifetime.code.killed"
    LIFETIME_CODE_READS = "lifetime.code.reads"
    LIFETIME_CODE_WRITES = "lifetime.code.writes"
    LIFETIME_CODE_ALLOCATIONS = "lifetime.code.allocations"
    LIFETIME_OP_READS = "lifetime.operation.reads"
    LIFETIME_OP_WRITES = "lifetime.operation.writes"
    LIFETIME_OP_ALLOCATIONS = "lifetime.operation.allocations"
    ALIAS_POINTS_TO = "alias.points_to"
    ALIAS_REFERENCES = "alias.references"
    ALIAS_ESCAPED = "alias.escaped"
    ALIAS_REFERENCE_COUNT = "alias.reference_count"
    ALIAS_PRECISION = "alias.operation.precision"
    TYPE_SYMBOL_TYPES = "typeinfo.symbol.types"
    TYPE_CALL_RETURNS = "typeinfo.call.returns"
    TYPE_PROCEDURE_SUMMARIES = "typeinfo.procedure.summaries"

    CPA = frozenset(
        {
            CONTEXTS,
            REFERENCES,
            CALL_TARGETS,
            CALL_TARGET_CODES,
            OP_READS,
            OP_WRITES,
            OP_ALLOCATIONS,
            CODE_READS,
            CODE_WRITES,
            CODE_ALLOCATIONS,
        }
    )
    IPA = frozenset(
        {
            CONTEXTS,
            CALL_TARGETS,
            CALL_TARGET_CODES,
            IPA_SUMMARIES,
        }
    )
    LIFETIME = frozenset(
        {
            LIFETIME_CODE_LIVE,
            LIFETIME_CODE_KILLED,
            LIFETIME_CODE_READS,
            LIFETIME_CODE_WRITES,
            LIFETIME_CODE_ALLOCATIONS,
            LIFETIME_OP_READS,
            LIFETIME_OP_WRITES,
            LIFETIME_OP_ALLOCATIONS,
        }
    )
    ALIAS = frozenset(
        {
            ALIAS_POINTS_TO,
            ALIAS_REFERENCES,
            ALIAS_ESCAPED,
            ALIAS_REFERENCE_COUNT,
            ALIAS_PRECISION,
        }
    )
    TYPEINFO = frozenset(
        {
            TYPE_SYMBOL_TYPES,
            TYPE_CALL_RETURNS,
            TYPE_PROCEDURE_SUMMARIES,
        }
    )


@dataclass(frozen=True)
class ContextualKey:
    entity: CodeId | NodeId | SymbolId
    context: ContextId


@dataclass(frozen=True)
class CallTarget:
    code: CodeId
    context: ContextId


@dataclass(frozen=True)
class PublishedIPASummary:
    context: ContextId
    parameter_names: tuple[str, ...] = ()
    return_dependencies: tuple[str, ...] = ()
    returns_value: bool = False
    examples: tuple[object, ...] = ()


@dataclass(frozen=True)
class PublishedTypeFact:
    """Engine-agnostic static type fact published into the shared IR catalog."""

    type_names: tuple[str, ...]
    display: str
    is_optional: bool = False
    is_gradual: bool = False
    source: str = "typeinfo"

    @property
    def primary_type_name(self) -> str | None:
        """Return the sole concrete class/type name when unambiguous."""
        return self.type_names[0] if len(self.type_names) == 1 else None

    @property
    def is_definite_non_optional(self) -> bool:
        """True when concrete non-None types are known without gradual/None alternatives."""
        return bool(self.type_names) and not self.is_optional and not self.is_gradual


@dataclass(frozen=True)
class PublishedProcedureTypes:
    """Published parameter and return type facts for one IR procedure."""

    param_types: tuple[tuple[str, PublishedTypeFact], ...] = ()
    return_type: PublishedTypeFact | None = None

    def param_type(self, name: str) -> PublishedTypeFact | None:
        for param_name, fact in self.param_types:
            if param_name == name:
                return fact
        return None
