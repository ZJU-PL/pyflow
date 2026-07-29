"""Cull unreachable procedures and contexts from published analysis facts."""

from __future__ import annotations

from pyflow.analysis import programculler
from pyflow.ir.core import CallTarget, Capabilities, ContextualKey, FactResult


def _copy_result(result: FactResult, values) -> FactResult:
    return FactResult(
        frozenset(values),
        result.precision,
        result.producer,
        result.diagnostics,
    )


def retain_live_contexts(catalog, live_contexts) -> bool:
    """Atomically retain only facts reachable from the program entry points."""
    live_ids = {
        catalog.context_id(code, context)
        for code, contexts in live_contexts.items()
        for context in contexts
    }
    live_codes = {catalog.procedure(code).code_id for code in live_contexts}
    replacements = {}

    for capability in Capabilities.CPA:
        if not catalog.facts.has(capability):
            continue
        filtered = {}
        for key, result in catalog.facts.items(capability):
            if capability == Capabilities.CONTEXTS:
                if key not in live_codes:
                    continue
                values = (context for context in result.values if context in live_ids)
                filtered[key] = _copy_result(result, values)
                continue

            if not isinstance(key, ContextualKey) or key.context not in live_ids:
                continue
            values = result.values
            if capability == Capabilities.CALL_TARGETS:
                values = (
                    target
                    for target in values
                    if isinstance(target, CallTarget)
                    and target.code in live_codes
                    and target.context in live_ids
                )
            filtered[key] = _copy_result(result, values)
        replacements[capability] = filtered

    if not replacements:
        return False
    before = {
        capability: catalog.facts.items(capability)
        for capability in replacements
    }
    if all(tuple(replacements[name].items()) == before[name] for name in replacements):
        return False
    catalog.facts.replace_many("context-culler", replacements)
    return True


def evaluate(compiler, prgm):
    """Remove unreachable code contexts without mutating Python AST annotations."""
    with compiler.console.scope("cull"):
        old_live = set(prgm.liveCode)
        live_contexts = programculler.findLiveContexts(prgm)
        facts_changed = retain_live_contexts(prgm.ir, live_contexts)
        prgm.liveCode = set(live_contexts)
        return facts_changed or old_live != prgm.liveCode


__all__ = ["evaluate", "retain_live_contexts"]
