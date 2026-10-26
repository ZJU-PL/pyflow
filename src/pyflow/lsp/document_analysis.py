"""Cached, document-scoped diagnostics and inference for editor requests."""

import ast
import builtins
from functools import lru_cache
from types import SimpleNamespace

from pyflow.analysis.typeinfo import InferenceOptions, StaticTypeInferenceEngine
from .workspace import SourceRange, _byte_col_to_char, offset_to_lsp_character, uri_to_path


def _range(text, uri, line=1, column=0, end_line=None, end_column=None):
    lines = text.splitlines()
    row = max(line - 1, 0)
    end_row = max((end_line or line) - 1, row)
    start = lines[row] if row < len(lines) else ""
    end = lines[end_row] if end_row < len(lines) else ""
    start_column = offset_to_lsp_character(start, _byte_col_to_char(start, column))
    stop = (
        offset_to_lsp_character(end, _byte_col_to_char(end, end_column))
        if end_column is not None
        else start_column + 1
    )
    return SourceRange(uri, row, start_column, end_row, stop).to_lsp()


@lru_cache(maxsize=64)
def infer_document(path, module, text):
    engine = StaticTypeInferenceEngine(
        options=InferenceOptions(
            max_iterations=8,
            max_loop_iterations=4,
            max_specializations_per_function=8,
            strict_annotations=True,
        )
    )
    return engine.infer_source(module, text, filename=path)


@lru_cache(maxsize=64)
def security_diagnostics(path, module, text):
    from pyflow.application.program import Program
    from pyflow.checker.ast_dataflow.core.context import AnalysisSession
    from pyflow.checker.ast_dataflow.detectors.taint import ASTDataflowTaintDetector
    from pyflow.checker.ast_dataflow.solver.cfg import SolverOptions

    files = {path: text}
    sources, filenames, imports = AnalysisSession._collect_sources_and_imports(Program(), files)
    session = SimpleNamespace(
        program=Program(),
        sources_by_name=sources,
        func_to_file=filenames,
        file_imports=imports,
        all_source_code=files,
        analysis_facts=None,
    )
    detector = ASTDataflowTaintDetector(
        unknown_call_policy="preserve",
        entry_parameter_kinds=(),
        solver_options=SolverOptions(max_steps=5000),
        max_summary_rounds=8,
    )
    return detector.analyze(session)


def _undefined_suppressions(text, tree):
    import io
    import re
    import tokenize

    ignored = set()
    for token in tokenize.generate_tokens(io.StringIO(text).readline):
        if token.type != tokenize.COMMENT:
            continue
        comment = token.string
        directive = re.search(r"#\s*type:\s*ignore(?:\[([^]]+)\])?", comment)
        if directive and (
            directive.group(1) is None
            or {"name-defined", "undefined-name"}
            & {code.strip() for code in directive.group(1).split(",")}
        ):
            ignored.add(token.start[0] - 1)
        directive = re.search(r"#\s*noqa(?::\s*([A-Za-z0-9, ]+))?", comment, re.I)
        if directive and (
            directive.group(1) is None
            or "F821" in {code.strip().upper() for code in directive.group(1).split(",")}
        ):
            ignored.add(token.start[0] - 1)
    guarded = set()

    def catches(handler):
        if handler.type is None:
            return True
        values = handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
        return any(
            isinstance(value, ast.Name) and value.id in {"NameError", "Exception", "BaseException"}
            for value in values
        )

    def names(node):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            for value in [
                *node.args.defaults,
                *node.args.kw_defaults,
                *getattr(node, "decorator_list", ()),
            ]:
                if value is not None:
                    names(value)
            return
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            guarded.add((node.lineno - 1, node.col_offset, node.id))
        for child in ast.iter_child_nodes(node):
            names(child)

    for node in ast.walk(tree):
        if isinstance(node, ast.Try) and any(catches(handler) for handler in node.handlers):
            for statement in node.body:
                names(statement)
    return ignored, guarded


def document_diagnostics(index, uri, *, include_security=False):
    syntax = index.diagnostics_for_uri(uri)
    if syntax:
        return syntax
    text = index.text_for_uri(uri)
    if text is None:
        return []
    path = uri_to_path(uri)
    module = index.module_for_uri(uri) or "__document__"
    result = []
    try:
        inferred = infer_document(path, module, text)
        for diagnostic in inferred.diagnostics:
            # Precision limitations belong in analysis status/debug output,
            # not squiggles on valid Python constructs.
            if diagnostic.affects_completeness or diagnostic.code in {
                "syntax-error",
                "unsupported-expression",
                "unsupported-statement",
                "unmodeled-context-manager",
                "unresolved-annotation",
                "call-model-error",
                "inference-did-not-converge",
                "loop-widened",
                "specialization-budget-exceeded",
            }:
                continue
            span = diagnostic.span
            result.append(
                {
                    "range": _range(
                        text,
                        uri,
                        span.lineno if span else 1,
                        span.col_offset if span else 0,
                        span.end_lineno if span else None,
                        span.end_col_offset if span else None,
                    ),
                    "source": "pyflow-type",
                    "code": diagnostic.code,
                    "severity": (
                        1
                        if diagnostic.severity == "error"
                        else 3 if diagnostic.affects_completeness else 2
                    ),
                    "message": diagnostic.message,
                }
            )
    except Exception as error:
        result.append(
            {
                "range": _range(text, uri),
                "severity": 3,
                "source": "pyflow-type",
                "code": "analysis-failed",
                "message": f"Document type analysis could not finish: {error}",
            }
        )
    tree = ast.parse(text)
    wildcard_imports = any(
        isinstance(node, ast.ImportFrom) and any(alias.name == "*" for alias in node.names)
        for node in ast.walk(tree)
    )
    known = set(dir(builtins)) | {
        "__file__",
        "__name__",
        "__package__",
        "__doc__",
        "__spec__",
        "__loader__",
        "__builtins__",
        "__annotations__",
        "__path__",
        "__cached__",
    }
    ignored, guarded = _undefined_suppressions(text, tree)
    if not wildcard_imports:
        for reference in index.references:
            if (
                reference.location.uri == uri
                and reference.symbol_id is None
                and reference.location not in index._reference_targets
                and reference.location not in index._keyword_targets
                and reference.name not in known
                and reference.location.start_line not in ignored
                and (
                    reference.location.start_line,
                    index.python_column(
                        uri, reference.location.start_line, reference.location.start_character
                    ),
                    reference.name,
                )
                not in guarded
            ):
                result.append(
                    {
                        "range": reference.location.to_lsp(),
                        "severity": 1,
                        "source": "pyflow",
                        "code": "undefined-name",
                        "message": f"Name '{reference.name}' is not defined",
                    }
                )
    if include_security:
        try:
            security = security_diagnostics(path, module, text)
            for finding in security.findings:
                result.append(
                    {
                        "range": _range(text, uri, finding.sink_line or 1),
                        "severity": 1 if finding.severity.lower() in {"high", "critical"} else 2,
                        "source": "pyflow-security",
                        "code": finding.rule_id,
                        "message": finding.rule_title + f" ({finding.sink_name})",
                        "data": {"cwe": finding.cwe},
                    }
                )
        except Exception as error:
            result.append(
                {
                    "range": _range(text, uri),
                    "severity": 3,
                    "source": "pyflow-security",
                    "code": "analysis-failed",
                    "message": f"Document security analysis could not finish: {error}",
                }
            )
    unique = {}
    for diagnostic in result:
        key = (
            diagnostic["source"],
            diagnostic["code"],
            str(diagnostic["range"]),
            diagnostic["message"],
        )
        unique[key] = diagnostic
    return list(unique.values())
