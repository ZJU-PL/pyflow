"""Publish IPA call/context results through the shared IR fact store."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Hashable
from typing import DefaultDict

from pyflow.ir.core import (
    CallTarget,
    Capabilities,
    ContextualKey,
    FactResult,
    PublishedIPASummary,
    index_program,
)
from pyflow.ir.core.order import canonical_context_signature, stable_ir_key
from pyflow.language.python import ast


def publish_ipa_facts(program, analysis) -> int:
    program.liveCode.update(analysis.liveCode)
    catalog = index_program(program)

    contexts_by_code = defaultdict(list)
    for context in analysis.contexts.values():
        signature = getattr(context, "signature", None)
        code = getattr(signature, "code", None)
        if isinstance(code, ast.Code) and code in program.liveCode:
            contexts_by_code[code].append(context)

    context_ids = {}
    published_contexts: dict[Hashable, FactResult] = {
        catalog.procedure(code).code_id: FactResult.exact((), "ipa")
        for code in program.liveCode
        if isinstance(code, ast.Code)
    }
    for code, contexts in contexts_by_code.items():
        ordered = sorted(
            contexts, key=lambda context: stable_ir_key(context, catalog, code)
        )
        ids = []
        for context in ordered:
            context_id = catalog.register_context(
                code,
                context,
                canonical_context_signature(context, catalog, code),
            )
            context_ids[(code, context)] = context_id
            ids.append(context_id)
        published_contexts[catalog.procedure(code).code_id] = FactResult.exact(
            ids, "ipa"
        )

    targets_by_key: DefaultDict[ContextualKey, set[CallTarget]] = defaultdict(set)
    summaries_by_code: dict[Hashable, list[PublishedIPASummary]] = {
        catalog.procedure(code).code_id: []
        for code in program.liveCode
        if isinstance(code, ast.Code)
    }
    for code, contexts in contexts_by_code.items():
        code_id = catalog.procedure(code).code_id
        for context in contexts:
            parameter_names = set()
            for param in context.params:
                raw = getattr(param, "name", None)
                name = getattr(raw, "name", None)
                if isinstance(name, str):
                    parameter_names.add(name)
                elif isinstance(raw, str):
                    parameter_names.add(raw)
            return_dependencies = set()
            for ret in context.returns:
                critical = getattr(ret, "critical", None)
                for value in getattr(critical, "values", ()):
                    name = getattr(value, "name", value)
                    if isinstance(name, str) and name in parameter_names:
                        return_dependencies.add(name)
            examples = tuple(getattr(context.summary, "examples", ()) or ())
            try:
                hash(examples)
            except TypeError:
                examples = ()
            summaries_by_code[code_id].append(
                PublishedIPASummary(
                    context_ids[(code, context)],
                    tuple(sorted(parameter_names)),
                    tuple(sorted(return_dependencies)),
                    bool(context.returns),
                    examples,
                )
            )
    for code, contexts in contexts_by_code.items():
        for node_id, semantics in catalog.semantics.items():
            if node_id.code != catalog.procedure(code).code_id or not semantics.calls:
                continue
            for context in contexts:
                targets_by_key[
                    ContextualKey(node_id, context_ids[(code, context)])
                ]
    for (code, context), context_id in context_ids.items():
        for (operation, destination), _invocation in context.invokeOut.items():
            target_code = getattr(getattr(destination, "signature", None), "code", None)
            target_context_id = context_ids.get((target_code, destination))
            if target_context_id is None or not isinstance(operation, ast.PythonASTNode):
                continue
            try:
                node_id = catalog.node_id(operation, code)
            except KeyError:
                continue
            targets_by_key[ContextualKey(node_id, context_id)].add(
                CallTarget(catalog.procedure(target_code).code_id, target_context_id)
            )

    return int(
        catalog.facts.publish_many(
            "ipa",
            {
                Capabilities.CONTEXTS: published_contexts,
                Capabilities.CALL_TARGETS: {
                    key: FactResult.exact(targets, "ipa")
                    for key, targets in targets_by_key.items()
                },
                Capabilities.IPA_SUMMARIES: {
                    code_id: FactResult.exact(summaries, "ipa")
                    for code_id, summaries in summaries_by_code.items()
                },
            },
        )
    )


__all__ = ["publish_ipa_facts"]
