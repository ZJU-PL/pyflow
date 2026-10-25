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


def document_diagnostics(index, uri):
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
            if diagnostic.code == "syntax-error":
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
    if not wildcard_imports:
        for reference in index.references:
            if (
                reference.location.uri == uri
                and reference.symbol_id is None
                and reference.location not in index._reference_targets
                and reference.name not in known
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
