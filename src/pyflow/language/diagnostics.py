"""Unified source-span, provenance, and structured diagnostic primitives.

This module defines IR-independent location and diagnostic types shared across
PyFlow's frontend, module/stub resolver, TypeInfo engine, constraint-based call
graph, and CLI/LSP reporting layers.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, order=True)
class SourceSpan:
    """Stable 1-based line / 0-based column span suitable for AST & IR queries."""

    lineno: int
    col_offset: int
    end_lineno: int | None = None
    end_col_offset: int | None = None

    @classmethod
    def from_ast(cls, node: ast.AST) -> "SourceSpan | None":
        """Build a :class:`SourceSpan` from any Python AST node with location info."""
        lineno = getattr(node, "lineno", None)
        col_offset = getattr(node, "col_offset", None)
        if not isinstance(lineno, int) or not isinstance(col_offset, int):
            return None
        end_lineno = getattr(node, "end_lineno", None)
        end_col_offset = getattr(node, "end_col_offset", None)
        return cls(
            lineno=lineno,
            col_offset=col_offset,
            end_lineno=end_lineno if isinstance(end_lineno, int) else None,
            end_col_offset=end_col_offset if isinstance(end_col_offset, int) else None,
        )

    @classmethod
    def from_origin(cls, origin: Any) -> "SourceSpan | None":
        """Convert a PyFlow ``SourceOrigin`` or ``Origin`` object into a span."""
        if origin is None:
            return None
        lineno = getattr(origin, "lineno", None)
        if not isinstance(lineno, int) or lineno < 0:
            return None
        col = getattr(origin, "col", None)
        col_offset = col if isinstance(col, int) and col >= 0 else 0
        end_lineno = getattr(origin, "end_lineno", None)
        end_col = getattr(origin, "end_col", None)
        return cls(
            lineno=lineno,
            col_offset=col_offset,
            end_lineno=end_lineno if isinstance(end_lineno, int) and end_lineno >= 0 else None,
            end_col_offset=end_col if isinstance(end_col, int) and end_col >= 0 else None,
        )

    def to_dict(self) -> dict[str, int | None]:
        return {
            "lineno": self.lineno,
            "col_offset": self.col_offset,
            "end_lineno": self.end_lineno,
            "end_col_offset": self.end_col_offset,
        }


@dataclass(frozen=True)
class Provenance:
    """Why an analysis fact or diagnostic is believed to hold."""

    source: str
    detail: str = ""
    span: SourceSpan | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "detail": self.detail,
            "span": self.span.to_dict() if self.span is not None else None,
        }


@dataclass(frozen=True)
class Diagnostic:
    """Structured cross-subsystem analysis diagnostic."""

    code: str
    message: str
    category: str = "analysis"
    severity: str = "warning"
    module_name: str | None = None
    filename: str | None = None
    span: SourceSpan | None = None
    affects_completeness: bool = False
    provenance: Provenance | None = None

    @property
    def lineno(self) -> int | None:
        return self.span.lineno if self.span is not None else None

    @property
    def col_offset(self) -> int | None:
        return self.span.col_offset if self.span is not None else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "category": self.category,
            "severity": self.severity,
            "module_name": self.module_name,
            "filename": self.filename,
            "message": self.message,
            "lineno": self.lineno,
            "col_offset": self.col_offset,
            "end_lineno": self.span.end_lineno if self.span is not None else None,
            "end_col_offset": self.span.end_col_offset if self.span is not None else None,
            "affects_completeness": self.affects_completeness,
            "provenance": self.provenance.to_dict() if self.provenance is not None else None,
        }

    @classmethod
    def from_extraction_diagnostic(cls, diag: Any) -> "Diagnostic":
        """Adapt a frontend ``FileExtractionDiagnostic``."""
        span = None
        if isinstance(getattr(diag, "line", None), int):
            col = getattr(diag, "column", None)
            span = SourceSpan(diag.line, col if isinstance(col, int) and col >= 0 else 0)
        stage = getattr(diag, "stage", "extract")
        exc_type = getattr(diag, "exception_type", "Error")
        return cls(
            code=f"extract-{stage}-{exc_type.lower()}",
            message=getattr(diag, "message", ""),
            category="extraction",
            severity="error",
            filename=getattr(diag, "filename", None),
            span=span,
            affects_completeness=True,
            provenance=Provenance(source="frontend-extractor", detail=f"{stage}:{exc_type}"),
        )

    @classmethod
    def from_stub_diagnostic(cls, diag: Any) -> "Diagnostic":
        """Adapt a ``StubDiagnostic`` from stub resolution or TypeInfoService."""
        span = None
        lineno = getattr(diag, "lineno", None)
        if isinstance(lineno, int):
            col = getattr(diag, "col_offset", None)
            span = SourceSpan(lineno, col if isinstance(col, int) and col >= 0 else 0)
        code = getattr(diag, "code", "stub-diagnostic")
        severity = getattr(diag, "severity", "warning")
        affects = severity == "error" or code in {
            "type_source_failed",
            "type_stub_failed",
            "type_collection_budget_exceeded",
            "type_collection_depth_exceeded",
            "module-inference-error",
        }
        return cls(
            code=code,
            message=getattr(diag, "message", ""),
            category=getattr(diag, "category", "type_stub"),
            severity=severity,
            module_name=getattr(diag, "module_name", None),
            filename=getattr(diag, "path", None),
            span=span,
            affects_completeness=affects,
        )

    @classmethod
    def from_inference_diagnostic(
        cls,
        diag: Any,
        *,
        module_name: str | None = None,
        filename: str | None = None,
    ) -> "Diagnostic":
        """Adapt an ``InferenceDiagnostic`` from static type inference."""
        raw_span = getattr(diag, "span", None)
        span = (
            raw_span
            if isinstance(raw_span, SourceSpan)
            else (
                SourceSpan(
                    raw_span.lineno,
                    raw_span.col_offset,
                    raw_span.end_lineno,
                    raw_span.end_col_offset,
                )
                if raw_span is not None
                else None
            )
        )
        return cls(
            code=getattr(diag, "code", "type-inference"),
            message=getattr(diag, "message", ""),
            category="type_inference",
            severity=getattr(diag, "severity", "warning"),
            module_name=module_name,
            filename=filename,
            span=span,
            affects_completeness=bool(getattr(diag, "affects_completeness", False)),
            provenance=Provenance(source="static-inference", span=span),
        )

    @classmethod
    def from_callgraph_message(
        cls,
        message: str,
        *,
        module_name: str | None = None,
        filename: str | None = None,
    ) -> "Diagnostic":
        """Adapt a legacy string diagnostic emitted by call-graph builders."""
        lower = message.lower()
        if "budget exhausted" in lower or "time budget" in lower:
            code = "callgraph-budget-exhausted"
            affects = True
        elif lower.startswith("skipped "):
            code = "callgraph-module-skipped"
            affects = True
        elif "mro" in lower:
            code = "callgraph-inconsistent-mro"
            affects = False
        else:
            code = "callgraph-diagnostic"
            affects = False
        return cls(
            code=code,
            message=message,
            category="callgraph",
            severity="warning",
            module_name=module_name,
            filename=filename,
            affects_completeness=affects,
            provenance=Provenance(source="constraint-callgraph"),
        )


__all__ = [
    "Diagnostic",
    "Provenance",
    "SourceSpan",
]
