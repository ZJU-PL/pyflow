"""Engine-neutral typed taint policy objects."""

from .policy import TaintPolicy, TaintRule
from .sink_semantics import (
    SINK_BEHAVIOR_JINJA_AUTOESCAPE,
    SUPPORTED_SINK_BEHAVIORS,
    sink_behavior_is_active,
)

__all__ = [
    "SINK_BEHAVIOR_JINJA_AUTOESCAPE",
    "SUPPORTED_SINK_BEHAVIORS",
    "TaintPolicy",
    "TaintRule",
    "sink_behavior_is_active",
]
