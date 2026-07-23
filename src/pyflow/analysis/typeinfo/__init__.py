"""Public type-information query API.

Implementation modules are grouped by responsibility under ``core``, ``query``,
``resolution``, ``inference``, and ``generation``.  Only the stable query and
resolution entry points are exported from this package.
"""

from . import config
from .query.evidence import (
    TypeEvidence,
    TypeEvidenceIndex,
    collect_pyflow_type_info,
    collect_python_type_info,
)
from .query.models import ClassTypeInfo, FunctionTypeInfo, TypeFact
from .query.service import TypeInfoService
from .resolution.annotations import (
    BuiltinTypeLookup,
    TypeLookup,
    resolve_annotation,
    resolve_forward_reference,
)
from pyflow.language.modules.type_stubs import (
    ResolvedStub,
    StubClassInfo,
    StubDiagnostic,
    StubFunctionInfo,
    StubImportInfo,
    StubInfo,
    StubResolver,
    build_stub_map,
    parse_stub_file,
    parse_stub_source,
)

__all__ = [
    "BuiltinTypeLookup",
    "ClassTypeInfo",
    "FunctionTypeInfo",
    "ResolvedStub",
    "StubClassInfo",
    "StubDiagnostic",
    "StubFunctionInfo",
    "StubImportInfo",
    "StubInfo",
    "StubResolver",
    "TypeEvidence",
    "TypeEvidenceIndex",
    "TypeFact",
    "TypeInfoService",
    "TypeLookup",
    "build_stub_map",
    "collect_pyflow_type_info",
    "collect_python_type_info",
    "config",
    "parse_stub_file",
    "parse_stub_source",
    "resolve_annotation",
    "resolve_forward_reference",
]
