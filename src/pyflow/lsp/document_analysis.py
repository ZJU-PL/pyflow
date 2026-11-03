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


def _type_ignore_lines(text):
    """Return zero-based line numbers carrying a ``# type: ignore`` comment."""
    import io
    import re
    import tokenize

    ignored = set()
    for token in tokenize.generate_tokens(io.StringIO(text).readline):
        if token.type == tokenize.COMMENT and re.search(r"#\s*type:\s*ignore\b", token.string):
            ignored.add(token.start[0] - 1)
    return ignored


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


def _implicit_name_positions(text, tree):
    """Positions where the compiler provides names that are never bound in source.

    ``__module__``/``__qualname__`` exist in a class body.  ``__class__`` is a
    closure cell for functions (including lambdas and nested functions) defined
    in a class body, but not for the class body itself or for comprehensions
    executed directly there.
    """
    lines = text.splitlines()
    allowed = set()

    def remember(node, name):
        line = max(node.lineno - 1, 0)
        line_text = lines[line] if line < len(lines) else ""
        start = offset_to_lsp_character(line_text, _byte_col_to_char(line_text, node.col_offset))
        allowed.add((line, start, name))

    def outer_expressions(node, class_body, class_cell):
        for value in getattr(node, "decorator_list", ()):
            walk(value, class_body=class_body, class_cell=class_cell)
        if isinstance(node, ast.ClassDef):
            return
        if isinstance(node, ast.Lambda):
            for value in [*node.args.defaults, *node.args.kw_defaults]:
                if value is not None:
                    walk(value, class_body=class_body, class_cell=class_cell)
            return
        for value in [*node.args.defaults, *node.args.kw_defaults]:
            if value is not None:
                walk(value, class_body=class_body, class_cell=class_cell)
        for argument in [
            *node.args.posonlyargs,
            *node.args.args,
            *node.args.kwonlyargs,
            *([node.args.vararg] if node.args.vararg else []),
            *([node.args.kwarg] if node.args.kwarg else []),
        ]:
            if argument.annotation is not None:
                walk(argument.annotation, class_body=class_body, class_cell=class_cell)
        if getattr(node, "returns", None) is not None:
            walk(node.returns, class_body=class_body, class_cell=class_cell)

    def walk(node, *, class_body=False, class_cell=False):
        if isinstance(node, ast.ClassDef):
            outer_expressions(node, class_body, class_cell)
            for value in node.bases:
                walk(value, class_body=class_body, class_cell=class_cell)
            for keyword in node.keywords:
                walk(keyword.value, class_body=class_body, class_cell=class_cell)
            for statement in node.body:
                walk(statement, class_body=True, class_cell=False)
            return
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            outer_expressions(node, class_body, class_cell)
            body_cell = class_cell or class_body
            body = node.body if isinstance(node.body, list) else [node.body]
            for statement in body:
                walk(statement, class_body=False, class_cell=body_cell)
            return
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            generators = node.generators
            if generators:
                # The first iterable is evaluated in the enclosing scope.
                walk(generators[0].iter, class_body=class_body, class_cell=class_cell)
            for index, generator in enumerate(generators):
                if index:
                    walk(generator.iter, class_body=False, class_cell=class_cell)
                walk(generator.target, class_body=False, class_cell=class_cell)
                for condition in generator.ifs:
                    walk(condition, class_body=False, class_cell=class_cell)
            values = [node.key, node.value] if isinstance(node, ast.DictComp) else [node.elt]
            for value in values:
                walk(value, class_body=False, class_cell=class_cell)
            return
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            if node.id == "__class__" and class_cell:
                remember(node, "__class__")
            elif node.id in {"__module__", "__qualname__"} and class_body:
                remember(node, node.id)
        for child in ast.iter_child_nodes(node):
            walk(child, class_body=class_body, class_cell=class_cell)

    walk(tree)
    return allowed


def document_diagnostics(index, uri, *, include_security=False):
    syntax = index.diagnostics_for_uri(uri)
    if syntax:
        return syntax
    text = index.text_for_uri(uri)
    if text is None:
        return []
    path = uri_to_path(uri)
    module = index.module_for_uri(uri) or "__document__"
    type_ignored = _type_ignore_lines(text)
    tree = ast.parse(text)

    def function_has_ignored_return(line0: int) -> bool:
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if node.lineno - 1 != line0:
                continue
            if any(
                isinstance(child, ast.Return) and (child.lineno - 1) in type_ignored
                for child in ast.walk(node)
            ):
                return True
        return False

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
            if span is not None and (
                (span.lineno - 1) in type_ignored or function_has_ignored_return(span.lineno - 1)
            ):
                continue
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
    implicit = _implicit_name_positions(text, tree)
    if not wildcard_imports:
        for reference in index.references:
            if (
                reference.location.uri == uri
                and reference.symbol_id is None
                and reference.location not in index._reference_targets
                and reference.location not in index._keyword_targets
                and not reference.string_literal
                and reference.name not in known
                and reference.location.start_line not in ignored
                and (
                    reference.location.start_line,
                    reference.location.start_character,
                    reference.name,
                )
                not in implicit
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
