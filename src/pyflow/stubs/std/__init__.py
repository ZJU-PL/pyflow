"""
Standard library stub generators.

This package contains stub generators for Python's standard library modules.
Each module provides stub implementations that enable static analysis of
code using those standard library functions.

The stub generators are automatically registered via the @stubgenerator
decorator and are called during stub collection to register their stubs
with the StubCollector.

Modules:
    interpreter: Interpreter-level operations (global access, attribute access)
    llfunc: Low-level object operations (__getattribute__, __init__, etc.)
    objects: Built-in object stubs (int, float, str methods)
    container: Container operations (list, dict, tuple, etc.)
    random: Random number generation functions
    mathstubs: Mathematical functions
    sampler: Sampling utilities
    os_stubs: Operating system interface functions
    json_stubs: JSON encoding/decoding functions
    re_stubs: Regular expression operations
    datetime_stubs: Date and time operations
    collections_stubs: Collections data structures
    itertools_stubs: Iterator utilities
    functools_stubs: Higher-order functions
    operator_stubs: Operator functions
"""

from __future__ import absolute_import

# Core stub generators
from . import interpreter
from . import llfunc
from .objects import float
from .objects import int
from .objects import str
from . import container
from . import random
from . import mathstubs
from . import sampler

# Additional standard library stubs
from . import os_stubs
from . import json_stubs
from . import re_stubs
from . import datetime_stubs
from . import collections_stubs
from . import itertools_stubs
from . import functools_stubs
from . import operator_stubs
