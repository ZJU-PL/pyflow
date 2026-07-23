"""Unified security-analysis command.

Parser construction and command execution are implemented in
:mod:`pyflow.cli.security.command`.
"""

from .command import run_security
from .parser import add_security_parser

__all__ = ["add_security_parser", "run_security"]
