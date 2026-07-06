"""Synthetic buggy version of black's Feature/VERSION_TO_FEATURES pattern.

This reproduces BugsInPy black#6: the Feature enum lacks async-related
members, so PY36/PY37/PY38 all map to identical feature sets.
"""
from enum import Enum
from typing import Dict, Set, List


class TargetVersion(Enum):
    PY27 = 2
    PY33 = 3
    PY34 = 4
    PY35 = 5
    PY36 = 6
    PY37 = 7
    PY38 = 8

    def is_python2(self) -> bool:
        return self is TargetVersion.PY27


class Feature(Enum):
    UNICODE_LITERALS = 0
    F_STRINGS = 1
    NUMERIC_UNDERSCORES = 3
    TRAILING_COMMA_IN_CALL = 4
    TRAILING_COMMA_IN_DEF = 5


# BUG: PY36, PY37, PY38 all have identical feature sets — no way to
# distinguish Python 3.6 (async is identifier) from 3.7+ (async is keyword).
VERSION_TO_FEATURES: Dict[TargetVersion, Set[Feature]] = {
    TargetVersion.PY27: set(),
    TargetVersion.PY33: {Feature.UNICODE_LITERALS},
    TargetVersion.PY34: {Feature.UNICODE_LITERALS},
    TargetVersion.PY35: {Feature.UNICODE_LITERALS, Feature.TRAILING_COMMA_IN_CALL},
    TargetVersion.PY36: {
        Feature.UNICODE_LITERALS,
        Feature.F_STRINGS,
        Feature.NUMERIC_UNDERSCORES,
        Feature.TRAILING_COMMA_IN_CALL,
        Feature.TRAILING_COMMA_IN_DEF,
    },
    TargetVersion.PY37: {
        Feature.UNICODE_LITERALS,
        Feature.F_STRINGS,
        Feature.NUMERIC_UNDERSCORES,
        Feature.TRAILING_COMMA_IN_CALL,
        Feature.TRAILING_COMMA_IN_DEF,
    },
    TargetVersion.PY38: {
        Feature.UNICODE_LITERALS,
        Feature.F_STRINGS,
        Feature.NUMERIC_UNDERSCORES,
        Feature.TRAILING_COMMA_IN_CALL,
        Feature.TRAILING_COMMA_IN_DEF,
    },
}


def get_grammars(target_versions: Set[TargetVersion]) -> List[str]:
    if not target_versions:
        return [
            "python_grammar_no_print_no_exec",
            "python_grammar_no_print",
            "python_grammar",
        ]
    elif all(version.is_python2() for version in target_versions):
        return ["python_grammar_no_print", "python_grammar"]
    else:
        return ["python_grammar_no_print_no_exec"]
