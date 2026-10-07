"""MIR: a minimal, explicit IR and its concrete reference semantics."""

from .model import *  # noqa: F401,F403
from .model import __all__ as _model_exports
from .interpreter import *  # noqa: F401,F403
from .interpreter import __all__ as _interpreter_exports
from .lowering import LoweringError, PythonToMIR, lower_file, lower_source
from .serialization import program_from_dict, program_from_json

__all__ = [
    *_model_exports,
    *_interpreter_exports,
    "LoweringError",
    "PythonToMIR",
    "lower_file",
    "lower_source",
    "program_from_dict",
    "program_from_json",
]
