"""Incremental SMT state and reusable decision primitives."""

from __future__ import annotations

from dataclasses import dataclass, field
from time import monotonic
from typing import Any, Callable, Iterable, Sequence


@dataclass(frozen=True)
class SolverCheck:
    result: Any
    reason: str | None
    seconds: float
    cache_hit: bool = False
    model: Any = None


@dataclass
class SolverResultCache:
    """Cache conclusive constraint-set results across path-flip queries."""

    results: dict[tuple[str, ...], tuple[str, str | None]] = field(default_factory=dict)

    def key(self, assertions: Iterable[Any]) -> tuple[str, ...]:
        return tuple(sorted(assertion.sexpr() for assertion in assertions))


class SolverStateSpace:
    """Own one incremental solver and the decisions made against it."""

    def __init__(
        self,
        z3: Any,
        *,
        timeout_seconds: float | None = None,
        rlimit: int | None = None,
        cache: SolverResultCache | None = None,
    ) -> None:
        self.z3 = z3
        self.solver = z3.Solver()
        self.solver.set(random_seed=42)
        if timeout_seconds is not None:
            self.solver.set(timeout=max(1, int(timeout_seconds * 1000 + 0.999)))
        if rlimit is not None:
            self.solver.set(rlimit=rlimit)
        self.cache = cache
        self._known: set[str] = set()
        self._deferred: list[tuple[str, Callable[[], Any]]] = []
        self.decisions: list[tuple[str, bool]] = []

    def add(self, *expressions: Any) -> None:
        for expression in expressions:
            if isinstance(expression, bool):
                expression = self.z3.BoolVal(expression)
            key = expression.sexpr()
            if key in self._known:
                continue
            self._known.add(key)
            self.solver.add(expression)

    def defer_assumption(self, description: str, checker: Callable[[], Any]) -> None:
        self._deferred.append((description, checker))

    def check(self, *extra: Any) -> SolverCheck:
        scoped = (
            bool(extra or self._deferred)
            and hasattr(self.solver, "push")
            and hasattr(self.solver, "pop")
        )
        if scoped:
            self.solver.push()
        try:
            for description, checker in self._deferred:
                assumption = checker()
                if assumption is False:
                    return SolverCheck(self.z3.unsat, description, 0.0)
                if assumption is not True:
                    self.solver.add(assumption)
            self.solver.add(*extra)
            assertions = (
                tuple(self.solver.assertions()) if hasattr(self.solver, "assertions") else ()
            )
            cache_key = self.cache.key(assertions) if self.cache is not None else None
            if cache_key is not None:
                cached = self.cache.results.get(cache_key)
                if cached is not None and cached[0] != "sat":
                    result = self.z3.unsat if cached[0] == "unsat" else self.z3.unknown
                    return SolverCheck(result, cached[1], 0.0, True)
            started = monotonic()
            result = self.solver.check()
            seconds = monotonic() - started
            reason = self.solver.reason_unknown() if result == self.z3.unknown else None
            if cache_key is not None:
                status = (
                    "sat"
                    if result == self.z3.sat
                    else "unsat" if result == self.z3.unsat else "unknown"
                )
                self.cache.results[cache_key] = (status, reason)
            model = self.solver.model() if result == self.z3.sat else None
            return SolverCheck(result, reason, seconds, model=model)
        finally:
            if scoped:
                self.solver.pop()

    def is_possible(self, expression: Any) -> bool:
        return self.check(expression).result == self.z3.sat

    def choose_possible(self, expression: Any, *, prefer_true: bool = True) -> bool:
        choices = (True, False) if prefer_true else (False, True)
        for choice in choices:
            constraint = expression if choice else self.z3.Not(expression)
            if self.is_possible(constraint):
                self.add(constraint)
                self.decisions.append((expression.sexpr(), choice))
                return choice
        raise ValueError("neither side of symbolic decision is feasible")

    def fanout(
        self,
        alternatives: Sequence[tuple[Any, Any]],
        *,
        description: str = "fanout",
    ) -> Any:
        for expression, result in alternatives:
            if self.is_possible(expression):
                self.add(expression)
                self.decisions.append((description, True))
                return result
        raise ValueError(f"no feasible alternative for {description}")

    def model(self) -> Any:
        result = self.solver.check()
        if result != self.z3.sat:
            raise ValueError(f"cannot obtain model from {result}")
        return self.solver.model()
