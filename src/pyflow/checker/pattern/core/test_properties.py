# Test properties and decorators
import logging
from . import utils

LOG = logging.getLogger(__name__)


def checks(*args):
    """Decorator function to set checks to be run"""

    def wrapper(func):
        if not hasattr(func, "_checks"):
            func._checks = []
        for arg in args:
            if arg == "File":
                func._checks.append("File")
            else:
                func._checks.append(utils.check_ast_node(arg))
        return func

    return wrapper


def with_id(id_val):
    """Test function identifier decorator"""

    def _has_id(func):
        if not hasattr(func, "_test_id"):
            func._test_id = id_val
        return func

    return _has_id


def takes_config(*args):
    """Test function takes config decorator"""
    name = ""

    def _takes_config(func):
        if not hasattr(func, "_takes_config"):
            func._takes_config = name
        return func

    if len(args) == 1 and callable(args[0]):
        name = args[0].__name__
        return _takes_config(args[0])
    else:
        name = args[0]
        return _takes_config


def accepts_baseline(func):
    """Decorator to mark formatter functions that can handle baseline data"""
    return func
