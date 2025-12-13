# Security checker context
import ast
from . import utils


class Context:
    def __init__(self, context_object=None):
        """Initialize with a context object or empty dict"""
        self._context = context_object or {}

    def __repr__(self):
        return f"<Context {self._context}>"

    @property
    def call_args(self):
        """Get a list of function args"""
        if "call" not in self._context or not hasattr(self._context["call"], "args"):
            return []
        return [arg.attr if hasattr(arg, "attr") else self._get_literal_value(arg) 
                for arg in self._context["call"].args]

    @property
    def call_args_count(self):
        """Get the number of args a function call has"""
        return len(self._context["call"].args) if "call" in self._context and hasattr(self._context["call"], "args") else None

    @property
    def call_function_name(self):
        """Get the name (not FQ) of a function call"""
        return self._context.get("name")

    @property
    def call_function_name_qual(self):
        """Get the FQ name of a function call"""
        return self._context.get("qualname")

    @property
    def call_keywords(self):
        """Get a dictionary of keyword parameters"""
        if "call" not in self._context or not hasattr(self._context["call"], "keywords"):
            return None
        return {li.arg: (li.value.attr if hasattr(li.value, "attr") else self._get_literal_value(li.value))
                for li in self._context["call"].keywords}

    @property
    def node(self):
        """Get the raw AST node associated with the context"""
        return self._context.get("node")

    @property
    def string_val(self):
        """Get the value of a standalone string object"""
        return self._context.get("str")

    @property
    def bytes_val(self):
        """Get the value of a standalone bytes object"""
        return self._context.get("bytes")

    @property
    def filename(self):
        return self._context.get("filename")

    @property
    def file_data(self):
        return self._context.get("file_data")

    @property
    def import_aliases(self):
        return self._context.get("import_aliases")

    def _get_literal_value(self, literal):
        """Convert AST literals to native Python types"""
        literal_map = {
            ast.Num: lambda x: x.n,
            ast.Str: lambda x: x.s,
            # Python 3.8+ folds several literal nodes into `ast.Constant`.
            # This keeps keyword/arg extraction working across versions.
            ast.Constant: lambda x: x.value,
            ast.List: lambda x: [self._get_literal_value(li) for li in x.elts],
            ast.Tuple: lambda x: tuple(self._get_literal_value(ti) for ti in x.elts),
            ast.Set: lambda x: {self._get_literal_value(si) for si in x.elts},
            ast.Dict: lambda x: dict(zip(x.keys, x.values)),
            ast.Ellipsis: lambda x: None,
            ast.Name: lambda x: x.id,
            ast.NameConstant: lambda x: str(x.value),
            ast.Bytes: lambda x: x.s,
        }
        return literal_map.get(type(literal), lambda x: None)(literal)

    def get_call_arg_value(self, argument_name):
        """Get the value of a named argument in a function call"""
        kwd_values = self.call_keywords
        return kwd_values.get(argument_name) if kwd_values else None

    def check_call_arg_value(self, argument_name, argument_values=None):
        """Check for a value of a named argument in a function call"""
        arg_value = self.get_call_arg_value(argument_name)
        if arg_value is None:
            return None
        values = argument_values if isinstance(argument_values, list) else [argument_values]
        return arg_value in values

    def is_module_being_imported(self, module):
        """Check if the specified module is currently being imported"""
        return self._context.get("module") == module

    def is_module_imported_exact(self, module):
        """Check if a specified module has been imported; only exact matches"""
        return module in self._context.get("imports", [])

    def is_module_imported_like(self, module):
        """Check if a specified module has been imported (partial match)"""
        imports = self._context.get("imports", [])
        return any(module in imp for imp in imports)
