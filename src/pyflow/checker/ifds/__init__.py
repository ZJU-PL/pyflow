"""Security checks using the general IFDS framework in pyflow.analysis.ifds."""

from .taint import (
    CATEGORY_DATABASE,
    CATEGORY_ENVIRONMENT,
    CATEGORY_FILE,
    CATEGORY_NETWORK,
    CATEGORY_USER_INPUT,
    ExpressionTaintFact,
    InterproceduralTaintAnalysis,
    TaintAnalysisResult,
    TaintConfiguration,
    TaintFact,
    TaintFinding,
    analyze_taint,
)
from pyflow.analysis.taint_policy import TaintRule
from .shadow_scan import (
    DiffEntry,
    ShadowMatch,
    ShadowScanReport,
    diff_scans,
    generate_shadow_report,
    run_shadow_scan,
)

__all__ = [
    "CATEGORY_DATABASE",
    "CATEGORY_ENVIRONMENT",
    "CATEGORY_FILE",
    "CATEGORY_NETWORK",
    "CATEGORY_USER_INPUT",
    "DiffEntry",
    "ExpressionTaintFact",
    "InterproceduralTaintAnalysis",
    "ShadowMatch",
    "ShadowScanReport",
    "TaintAnalysisResult",
    "TaintConfiguration",
    "TaintFact",
    "TaintFinding",
    "TaintRule",
    "analyze_taint",
    "diff_scans",
    "generate_shadow_report",
    "run_shadow_scan",
]
