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
    container: Container operations (list, dict, tuple, set, etc.)
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
    io_stubs: File I/O operations
    sys_stubs: System-specific parameters and functions
    copy_stubs: Object copying utilities
    subprocess_stubs: Subprocess management
    pathlib_stubs: Path manipulation utilities
    pickle_stubs: Object serialization
    hashlib_stubs: Cryptographic hashing
    time_stubs: Time access and conversions
    threading_stubs: Threading primitives
    logging_stubs: Logging facility
    argparse_stubs: Command-line argument parsing
    tempfile_stubs: Temporary file handling
    shutil_stubs: High-level file operations
    csv_stubs: CSV file handling
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

# Standard library stubs
from . import os_stubs
from . import json_stubs
from . import re_stubs
from . import datetime_stubs
from . import collections_stubs
from . import itertools_stubs
from . import functools_stubs
from . import operator_stubs

# I/O and system stubs
from . import io_stubs
from . import sys_stubs
from . import copy_stubs
from . import subprocess_stubs
from . import pathlib_stubs
from . import pickle_stubs
from . import hashlib_stubs
from . import time_stubs
from . import tempfile_stubs
from . import shutil_stubs

# Concurrency and utilities
from . import threading_stubs
from . import logging_stubs
from . import argparse_stubs
from . import csv_stubs
