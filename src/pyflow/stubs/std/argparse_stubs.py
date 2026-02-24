from __future__ import absolute_import

from ..stubcollector import stubgenerator

import argparse


@stubgenerator
def makeArgparseStubs(collector):
    llfunc = collector.llfunc
    export = collector.export
    attachPtr = collector.attachPtr

    ### ArgumentParser ###
    @export
    @attachPtr(argparse, "ArgumentParser")
    @llfunc
    def argparse_ArgumentParser(prog=None, usage=None, description=None, epilog=None, parents=(), formatter_class=argparse.HelpFormatter, prefix_chars='-', fromfile_prefix_chars=None, argument_default=None, conflict_handler='error', add_help=True, allow_abbrev=True, exit_on_error=True):
        return allocate(argparse.ArgumentParser)

    @attachPtr(argparse.ArgumentParser, "add_argument")
    @llfunc
    def argumentparser_add_argument(self, *args, **kwargs):
        return allocate(argparse.Action)

    @attachPtr(argparse.ArgumentParser, "add_argument_group")
    @llfunc
    def argumentparser_add_argument_group(self, *args, **kwargs):
        return allocate(argparse._ArgumentGroup)

    @attachPtr(argparse.ArgumentParser, "add_mutually_exclusive_group")
    @llfunc
    def argumentparser_add_mutually_exclusive_group(self, required=False):
        return allocate(argparse._MutuallyExclusiveGroup)

    @attachPtr(argparse.ArgumentParser, "add_subparsers")
    @llfunc
    def argumentparser_add_subparsers(self, title=None, description=None, prog=None, parser_class=None, action=None, option_strings=(), dest=None, required=False, help=None, metavar=None):
        return allocate(argparse._SubParsersAction)

    @attachPtr(argparse.ArgumentParser, "parse_args")
    @llfunc
    def argumentparser_parse_args(self, args=None, namespace=None):
        return allocate(argparse.Namespace)

    @attachPtr(argparse.ArgumentParser, "parse_known_args")
    @llfunc
    def argumentparser_parse_known_args(self, args=None, namespace=None):
        return allocate(tuple)

    @attachPtr(argparse.ArgumentParser, "parse_intermixed_args")
    @llfunc
    def argumentparser_parse_intermixed_args(self, args=None, namespace=None):
        return allocate(argparse.Namespace)

    @attachPtr(argparse.ArgumentParser, "parse_intermixed_known_args")
    @llfunc
    def argumentparser_parse_intermixed_known_args(self, args=None, namespace=None):
        return allocate(tuple)

    @attachPtr(argparse.ArgumentParser, "set_defaults")
    @llfunc
    def argumentparser_set_defaults(self, **kwargs):
        return allocate(type(None))

    @attachPtr(argparse.ArgumentParser, "get_default")
    @llfunc
    def argumentparser_get_default(self, dest):
        return allocate(object)

    @attachPtr(argparse.ArgumentParser, "print_usage")
    @llfunc
    def argumentparser_print_usage(self, file=None):
        return allocate(type(None))

    @attachPtr(argparse.ArgumentParser, "print_help")
    @llfunc
    def argumentparser_print_help(self, file=None):
        return allocate(type(None))

    @attachPtr(argparse.ArgumentParser, "format_usage")
    @llfunc
    def argumentparser_format_usage(self):
        return allocate(str)

    @attachPtr(argparse.ArgumentParser, "format_help")
    @llfunc
    def argumentparser_format_help(self):
        return allocate(str)

    @attachPtr(argparse.ArgumentParser, "error")
    @llfunc
    def argumentparser_error(self, message):
        return allocate(type(None))

    @attachPtr(argparse.ArgumentParser, "exit")
    @llfunc
    def argumentparser_exit(self, status=0, message=None):
        return allocate(type(None))

    ### Namespace ###
    @export
    @attachPtr(argparse, "Namespace")
    @llfunc
    def argparse_Namespace(**kwargs):
        return allocate(argparse.Namespace)

    @attachPtr(argparse.Namespace, "__getitem__")
    @llfunc
    def namespace__getitem__(self, key):
        return allocate(object)

    @attachPtr(argparse.Namespace, "__setitem__")
    @llfunc
    def namespace__setitem__(self, key, value):
        return allocate(type(None))

    @attachPtr(argparse.Namespace, "__contains__")
    @llfunc
    def namespace__contains__(self, key):
        return allocate(bool)

    @attachPtr(argparse.Namespace, "__iter__")
    @llfunc
    def namespace__iter__(self):
        return allocate(type(iter({})))

    ### HelpFormatter ###
    @export
    @attachPtr(argparse, "HelpFormatter")
    @llfunc
    def argparse_HelpFormatter(prog, indent_increment=2, max_help_position=24, width=None):
        return allocate(argparse.HelpFormatter)

    ### ArgumentDefaultsHelpFormatter ###
    @export
    @attachPtr(argparse, "ArgumentDefaultsHelpFormatter")
    @llfunc
    def argparse_ArgumentDefaultsHelpFormatter(prog, indent_increment=2, max_help_position=24, width=None):
        return allocate(argparse.ArgumentDefaultsHelpFormatter)

    ### RawDescriptionHelpFormatter ###
    @export
    @attachPtr(argparse, "RawDescriptionHelpFormatter")
    @llfunc
    def argparse_RawDescriptionHelpFormatter(prog, indent_increment=2, max_help_position=24, width=None):
        return allocate(argparse.RawDescriptionHelpFormatter)

    ### RawTextHelpFormatter ###
    @export
    @attachPtr(argparse, "RawTextHelpFormatter")
    @llfunc
    def argparse_RawTextHelpFormatter(prog, indent_increment=2, max_help_position=24, width=None):
        return allocate(argparse.RawTextHelpFormatter)

    ### MetavarTypeHelpFormatter ###
    @export
    @attachPtr(argparse, "MetavarTypeHelpFormatter")
    @llfunc
    def argparse_MetavarTypeHelpFormatter(prog, indent_increment=2, max_help_position=24, width=None):
        return allocate(argparse.MetavarTypeHelpFormatter)

    ### FileType ###
    @export
    @attachPtr(argparse, "FileType")
    @llfunc
    def argparse_FileType(mode='r', bufsize=-1, encoding=None, errors=None):
        return allocate(argparse.FileType)

    @attachPtr(argparse.FileType, "__call__")
    @llfunc
    def filetype__call__(self, string):
        return allocate(type(open(".")))

    ### Action ###
    @export
    @attachPtr(argparse, "Action")
    @llfunc
    def argparse_Action(option_strings, dest, nargs=None, const=None, default=None, type=None, choices=None, required=False, help=None, metavar=None):
        return allocate(argparse.Action)

    ### BooleanOptionalAction ###
    @export
    @attachPtr(argparse, "BooleanOptionalAction")
    @llfunc
    def argparse_BooleanOptionalAction(option_strings, dest, nargs=0, const=None, default=None, type=None, choices=None, required=False, help=None, metavar=None):
        return allocate(argparse.BooleanOptionalAction)

    ### Exceptions ###
    @export
    @attachPtr(argparse, "ArgumentError")
    @llfunc
    def argparse_ArgumentError(argument, message):
        return allocate(argparse.ArgumentError)

    @export
    @attachPtr(argparse, "ArgumentTypeError")
    @llfunc
    def argparse_ArgumentTypeError(message):
        return allocate(argparse.ArgumentTypeError)
