"""Configuration defaults for the type system.

These values originate from Pynguin's configuration system and are provided
here with sensible defaults so the migrated type system remains self-contained.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class SubtypeInferenceStrategy(enum.Enum):
    """Strategy for inferring subtypes of strings."""

    NONE = 0
    STRING = 1


@dataclass
class GeneratorSelectionConfig:
    """Configuration for generator selection."""

    generator_any_distance: int = 100


@dataclass
class TestCreationConfig:
    """Configuration for test creation affecting type guessing."""

    none_weight: float = 0.1
    any_weight: float = 0.1
    original_type_weight: float = 0.5
    type_tracing_weight: float = 0.3
    wrap_var_param_type_probability: float = 0.5
    type_tracing_kept_guesses: int = 5
    collection_size: int = 5
    negate_type: float = 0.0


@dataclass
class TypeInferenceConfig:
    """Configuration for type inference."""

    type_tracing_subtype_weight: float = 0.1
    type_tracing_argument_type_weight: float = 0.1
    type_tracing_attribute_weight: float = 0.8
    subtype_inference: SubtypeInferenceStrategy = SubtypeInferenceStrategy.NONE


@dataclass
class StatisticsOutputConfig:
    """Configuration for statistics output."""

    type_guess_top_n: int = 3


@dataclass
class LargeLanguageModelConfig:
    """Configuration for LLM-based type inference."""

    api_key: str = ""
    model_name: str = "gpt-5.5"


@dataclass
class TypeSystemSettings:
    """Aggregate of all type-system-related configuration."""

    generator_selection: GeneratorSelectionConfig = field(
        default_factory=GeneratorSelectionConfig
    )
    test_creation: TestCreationConfig = field(default_factory=TestCreationConfig)
    type_inference: TypeInferenceConfig = field(default_factory=TypeInferenceConfig)
    statistics_output: StatisticsOutputConfig = field(
        default_factory=StatisticsOutputConfig
    )
    large_language_model: LargeLanguageModelConfig = field(
        default_factory=LargeLanguageModelConfig
    )


settings = TypeSystemSettings()
"""Module-level singleton of type system settings."""
