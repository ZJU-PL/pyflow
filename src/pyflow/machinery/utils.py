import os


def get_lambda_name(counter):
    return "<lambda{}>".format(counter)


def get_dict_name(counter):
    return "<dict{}>".format(counter)


def get_list_name(counter):
    return "<list{}>".format(counter)


def get_int_name(counter):
    return "<int{}>".format(counter)


def join_ns(*args):
    return ".".join([arg for arg in args])


def to_mod_name(name, package=None):
    return os.path.splitext(name)[0].replace("/", ".")


RETURN_NAME = "<RETURN>"
LAMBDA_NAME = "<LAMBDA_{}>"  # needs to be formatted
BUILTIN_NAME = "<builtin>"
EXT_NAME = "<external>"

FUN_DEF = "FUNCTIONDEF"
NAME_DEF = "NAMEDEF"
MOD_DEF = "MODULEDEF"
CLS_DEF = "CLASSDEF"
EXT_DEF = "EXTERNALDEF"

OBJECT_BASE = "object"

CLS_INIT = "__init__"
ITER_METHOD = "__iter__"
NEXT_METHOD = "__next__"
STATIC_METHOD = "staticmethod"

INVALID_NAME = "<**INVALID**>"

CALL_GRAPH_OP = "call-graph"
KEY_ERR_OP = "key-error"