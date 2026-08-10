"""Protocol-neutral type-information queries."""

from __future__ import annotations

from typing import Optional

from pyflow.analysis.typeinfo import TypeFact, TypeInfoService
from pyflow.analysis.typeinfo.core.typesystem import ProperType
from pyflow.analysis.typeinfo.inference.models import FunctionSummary


class TypeInfoQueries:
    """Expose optional project type information without a transport facade."""

    def __init__(self, service: Optional[TypeInfoService] = None):
        self._service = service

    @property
    def available(self) -> bool:
        return self._service is not None

    def get_symbol_type(self, module_name: str, name: str) -> Optional[ProperType]:
        return self._service.type_of(module_name, name) if self._service else None

    def get_type_fact(self, module_name: str, name: str) -> Optional[TypeFact]:
        return self._service.fact_of(module_name, name) if self._service else None

    def get_expression_type(
        self, module_name: str, lineno: int, col_offset: int
    ) -> Optional[ProperType]:
        if self._service is None:
            return None
        result = self._service.inference_result(module_name)
        return result.expression_type(lineno, col_offset) if result else None

    def get_function_type_summary(
        self, module_name: str, qualified_name: str
    ) -> Optional[FunctionSummary]:
        if self._service is None:
            return None
        result = self._service.inference_result(module_name)
        if result is None:
            return None
        full_name = (
            qualified_name
            if qualified_name.startswith(f"{module_name}.")
            else f"{module_name}.{qualified_name}"
        )
        return result.functions.get(full_name)
