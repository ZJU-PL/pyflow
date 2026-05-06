"""Synthetic fixed version of black's Feature/VERSION_TO_FEATURES pattern.

This reproduces the FIX for BugsInPy black#6: the Feature enum now has
ASYNC_IS_VALID_IDENTIFIER and ASYNC_IS_RESERVED_KEYWORD, so PY36 is
distinguishable from PY37/PY38.
"""
from enum import Enum
from typing import Dict, Set, List
from dataclasses import dataclass


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
    # The following two feature-flags are mutually exclusive, and exactly one
    # should be set for every version of python.
    ASYNC_IS_VALID_IDENTIFIER = 6
    ASYNC_IS_RESERVED_KEYWORD = 7


# FIXED: PY36 now has ASYNC_IS_VALID_IDENTIFIER, PY37/PY38 have
# ASYNC_IS_RESERVED_KEYWORD. No group of 3+ versions is identical.
VERSION_TO_FEATURES: Dict[TargetVersion, Set[Feature]] = {
    TargetVersion.PY27: {Feature.ASYNC_IS_VALID_IDENTIFIER},
    TargetVersion.PY33: {Feature.UNICODE_LITERALS, Feature.ASYNC_IS_VALID_IDENTIFIER},
    TargetVersion.PY34: {Feature.UNICODE_LITERALS, Feature.ASYNC_IS_VALID_IDENTIFIER},
    TargetVersion.PY35: {
        Feature.UNICODE_LITERALS,
        Feature.TRAILING_COMMA_IN_CALL,
        Feature.ASYNC_IS_VALID_IDENTIFIER,
    },
    TargetVersion.PY36: {
        Feature.UNICODE_LITERALS,
        Feature.F_STRINGS,
        Feature.NUMERIC_UNDERSCORES,
        Feature.TRAILING_COMMA_IN_CALL,
        Feature.TRAILING_COMMA_IN_DEF,
        Feature.ASYNC_IS_VALID_IDENTIFIER,
    },
    TargetVersion.PY37: {
        Feature.UNICODE_LITERALS,
        Feature.F_STRINGS,
        Feature.NUMERIC_UNDERSCORES,
        Feature.TRAILING_COMMA_IN_CALL,
        Feature.TRAILING_COMMA_IN_DEF,
        Feature.ASYNC_IS_RESERVED_KEYWORD,
    },
    TargetVersion.PY38: {
        Feature.UNICODE_LITERALS,
        Feature.F_STRINGS,
        Feature.NUMERIC_UNDERSCORES,
        Feature.TRAILING_COMMA_IN_CALL,
        Feature.TRAILING_COMMA_IN_DEF,
        Feature.ASYNC_IS_RESERVED_KEYWORD,
    },
}


@dataclass(frozen=True)
class TokenizerConfig:
    async_is_reserved_keyword: bool = False


@dataclass(frozen=True)
class ParserConfig:
    grammar: str
    tokenizer_config: TokenizerConfig = TokenizerConfig()


def get_parser_configs(target_versions: Set[TargetVersion]) -> List[ParserConfig]:
    if not target_versions:
        return [
            ParserConfig(
                "python_grammar_no_print_no_exec",
                TokenizerConfig(async_is_reserved_keyword=True),
            ),
            ParserConfig(
                "python_grammar_no_print_no_exec",
                TokenizerConfig(async_is_reserved_keyword=False),
            ),
            ParserConfig("python_grammar_no_print"),
            ParserConfig("python_grammar"),
        ]
    elif all(version.is_python2() for version in target_versions):
        return [
            ParserConfig("python_grammar_no_print"),
            ParserConfig("python_grammar"),
        ]
    else:
        return [
            ParserConfig(
                "python_grammar_no_print_no_exec",
                TokenizerConfig(async_is_reserved_keyword=True),
            ),
        ]
