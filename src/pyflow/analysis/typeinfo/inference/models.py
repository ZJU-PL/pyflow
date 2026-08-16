"""Public result models for standalone static type inference."""

from __future__ import annotations

from dataclasses import dataclass, field

from pyflow.analysis.typeinfo.core.typesystem import ProperType
from pyflow.analysis.typeinfo.inference.domain import AbstractTypeValue


@dataclass(frozen=True, order=True)
class SourceSpan:
    """A stable source location suitable for expression-level queries."""

    lineno: int
    col_offset: int
    end_lineno: int | None = None
    end_col_offset: int | None = None


@dataclass(frozen=True)
class InferenceProvenance:
    """Why an inferred fact is believed to hold."""

    source: str
    detail: str = ""
    span: SourceSpan | None = None


@dataclass(frozen=True)
class InferenceDiagnostic:
    """A non-fatal precision or consistency problem found by inference."""

    code: str
    message: str
    severity: str = "warning"
    span: SourceSpan | None = None


@dataclass(frozen=True)
class InferredSymbol:
    """The final inferred value and provenance for a qualified symbol."""

    name: str
    value: AbstractTypeValue
    provenance: tuple[InferenceProvenance, ...] = ()

    @property
    def typ(self) -> ProperType | None:
        """Return the public type projection."""
        return self.value.public_type()

    @property
    def is_complete(self) -> bool:
        """Whether ``typ`` describes all possible inferred alternatives."""
        return self.value.is_complete

    @property
    def has_unknown_alternatives(self) -> bool:
        """Whether alternatives beyond ``typ`` may still be possible."""
        return self.value.has_unknown_alternatives


@dataclass(frozen=True)
class FunctionSpecialization:
    """Argument-sensitive result for one normalized callable context."""

    parameters: tuple[tuple[str, AbstractTypeValue], ...]
    return_value: AbstractTypeValue
    yield_value: AbstractTypeValue = field(default_factory=AbstractTypeValue.bottom)
    widened: bool = False

    @property
    def parameter_map(self) -> dict[str, AbstractTypeValue]:
        """Return the normalized call arguments as a convenient mapping."""
        return dict(self.parameters)

    @property
    def return_type(self) -> ProperType | None:
        """Return the public return-type projection."""
        return self.return_value.public_type()


@dataclass(frozen=True)
class FunctionSummary:
    """Monotone interprocedural summary for one callable."""

    qualified_name: str
    parameters: dict[str, AbstractTypeValue]
    return_value: AbstractTypeValue
    yield_value: AbstractTypeValue = field(default_factory=AbstractTypeValue.bottom)
    return_dependencies: frozenset[str] = field(default_factory=frozenset)
    is_async: bool = False
    is_generator: bool = False
    specializations: tuple[FunctionSpecialization, ...] = ()

    @property
    def return_type(self) -> ProperType | None:
        """Return the public return-type projection."""
        return self.return_value.public_type()


@dataclass
class ModuleInferenceResult:
    """Complete queryable result of analysing one source module."""

    module_name: str
    symbols: dict[str, InferredSymbol] = field(default_factory=dict)
    functions: dict[str, FunctionSummary] = field(default_factory=dict)
    expressions: dict[SourceSpan, AbstractTypeValue] = field(default_factory=dict)
    diagnostics: list[InferenceDiagnostic] = field(default_factory=list)
    iterations: int = 0
    converged: bool = True

    def type_of(self, name: str) -> ProperType | None:
        """Return the inferred type of a module or qualified symbol."""
        symbol = self.symbols.get(name)
        if symbol is None and "." not in name:
            symbol = self.symbols.get(f"{self.module_name}.{name}")
        return None if symbol is None else symbol.typ

    def known_type_of(self, name: str) -> ProperType | None:
        """Return only the known projection, without implying completeness."""
        return self.type_of(name)

    def value_of(self, name: str) -> AbstractTypeValue | None:
        """Return the full abstract value of a symbol."""
        symbol = self.symbols.get(name)
        if symbol is None and "." not in name:
            symbol = self.symbols.get(f"{self.module_name}.{name}")
        return None if symbol is None else symbol.value

    def expression_type(
        self,
        lineno: int,
        col_offset: int,
    ) -> ProperType | None:
        """Return the type of the expression starting at a source position."""
        value = self.expression_value(lineno, col_offset)
        return None if value is None else value.public_type()

    def expression_value(
        self,
        lineno: int,
        col_offset: int,
    ) -> AbstractTypeValue | None:
        """Return the full abstract value at a source expression position."""
        matches = [
            (span, value)
            for span, value in self.expressions.items()
            if span.lineno == lineno and span.col_offset == col_offset
        ]
        if not matches:
            return None
        # A call and its callee commonly start at the same position.  Prefer
        # the widest expression, which is the user-visible outer expression.
        _, value = max(
            matches,
            key=lambda item: (
                item[0].end_lineno or item[0].lineno,
                item[0].end_col_offset or item[0].col_offset,
            ),
        )
        return value


@dataclass
class ProjectInferenceResult:
    """Fixed-point results for a set of mutually importing modules."""

    modules: dict[str, ModuleInferenceResult] = field(default_factory=dict)
    diagnostics: list[InferenceDiagnostic] = field(default_factory=list)
    iterations: int = 0
    converged: bool = True

    def module(self, module_name: str) -> ModuleInferenceResult | None:
        """Return one module result, if it was resolved and analysed."""
        return self.modules.get(module_name)

    def type_of(self, qualified_name: str) -> ProperType | None:
        """Resolve a fully qualified symbol across project results."""
        for module_name in sorted(self.modules, key=len, reverse=True):
            prefix = f"{module_name}."
            if qualified_name.startswith(prefix):
                return self.modules[module_name].type_of(
                    qualified_name.removeprefix(prefix)
                )
        return None
