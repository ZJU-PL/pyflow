"""
Function Extractor for converting Python functions to PyFlow AST.

This module handles the extraction and conversion of Python functions
to PyFlow's internal representation for static analysis.
"""

import ast as python_ast
import inspect
import textwrap
from typing import Any, Optional

from pyflow.language.python import ast as pyflow_ast
from pyflow.language.python.annotations import CodeAnnotation
from pyflow.language.python.pythonbase import PythonASTNode
from pyflow.application.program import Program

from .ast_converter import ASTConverter


class FunctionExtractor:
    """Extracts and converts Python functions to PyFlow AST."""

    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self.ast_converter = ASTConverter(verbose)

    def convert_function(
        self,
        func: Any,
        source_code: Optional[str] = None,
        trace: bool = False,
        ssa: bool = True,
        descriptive: bool = False,
    ) -> PythonASTNode:
        """Convert a Python function to PyFlow AST for static analysis."""
        try:
            # Try to get source code from the provided source_code first
            source = source_code
            if self.verbose and source_code:
                print(f"DEBUG: Using provided source code for {func.__name__}")
            elif self.verbose:
                print(f"DEBUG: No source code provided for {func.__name__}")

            if not source:
                # Fallback to inspect.getsource
                try:
                    source = inspect.getsource(func)
                    if self.verbose:
                        print(
                            f"DEBUG: Got source from inspect.getsource for {func.__name__}"
                        )
                except (OSError, TypeError):
                    if self.verbose:
                        print(f"DEBUG: inspect.getsource failed for {func.__name__}")

            if not source:
                if self.verbose:
                    print(f"DEBUG: Could not get source code for {func.__name__}")
                return self._create_minimal_code(func)

            if self.verbose:
                print(
                    f"DEBUG: Processing source code for {func.__name__} (length: {len(source)})"
                )

            # Dedent the source code to handle class-level indentation
            try:
                source = textwrap.dedent(source)
            except Exception as e:
                if self.verbose:
                    print(f"DEBUG: Error dedenting source for {func.__name__}: {e}")

            # Parse it into a Python AST
            tree = python_ast.parse(source)

            # Find the function definition
            func_node = None
            for node in python_ast.walk(tree):
                if (
                    isinstance(node, (python_ast.FunctionDef, python_ast.AsyncFunctionDef))
                    and node.name == func.__name__
                ):
                    func_node = node
                    break

            if func_node is None:
                if self.verbose:
                    print(
                        f"DEBUG: Could not find function definition for {func.__name__}"
                    )
                return self._create_minimal_code(func)

            # Convert Python AST to pyflow AST
            result = self._convert_python_function_to_pyflow(func_node, func)
            return result

        except Exception as e:
            if self.verbose:
                print(f"DEBUG: Error analyzing function {func.__name__}: {e}")
                import traceback

                traceback.print_exc()
            # Fallback: create a minimal code stub
            return self._create_minimal_code(func)

    def _create_minimal_code(self, func: Any) -> pyflow_ast.Code:
        """Create a minimal pyflow AST Code node with an empty Suite."""
        # Provide a default single return param to satisfy IPA's visitReturn assertions
        codeparams = pyflow_ast.CodeParameters(
            None, [], [], [], None, None, [pyflow_ast.Local("ret0")]
        )
        suite = pyflow_ast.Suite([])
        code = pyflow_ast.Code(func.__name__, codeparams, suite)

        # Initialize the annotation properly
        code.annotation = CodeAnnotation(
            contexts=None,
            descriptive=False,
            primitive=False,
            staticFold=False,
            dynamicFold=False,
            origin=[f"minimal_code({func.__name__})"],
            live=None,
            killed=None,
            codeReads=None,
            codeModifies=None,
            codeAllocates=None,
            lowered=False,
            runtime=False,
            interpreter=False,
        )

        return code

    def _convert_python_function_to_pyflow(
        self, func_node: python_ast.AST, func: Any, *, filename: Optional[str] = None
    ) -> pyflow_ast.Code:
        """Convert a Python AST FunctionDef to a pyflow AST Code node."""
        # Convert function parameters
        codeparams = self._convert_function_args(func_node.args, func)

        # Convert function body
        body = self.ast_converter.convert_python_ast_to_pyflow(func_node.body)

        # Use func_node.name if func is None
        func_name = func.__name__ if func else func_node.name

        # Ensure at least one return parameter for IPA
        if not codeparams.returnparams:
            codeparams = pyflow_ast.CodeParameters(
                codeparams.selfparam,
                codeparams.params,
                codeparams.paramnames,
                tuple(codeparams.defaults),
                codeparams.vparam,
                codeparams.kparam,
                [pyflow_ast.Local("ret0")],
            )

        code = pyflow_ast.Code(func_name, codeparams, body)

        # Initialize the annotation properly
        origin = [f"converted_function({func_name})"]
        try:
            if func is not None and hasattr(func, "__code__") and func.__code__ is not None:
                origin.append(
                    f"source({func.__code__.co_filename}:{func.__code__.co_firstlineno})"
                )
            else:
                lineno = getattr(func_node, "lineno", None)
                if filename and isinstance(lineno, int):
                    origin.append(f"source({filename}:{lineno})")
        except Exception:
            pass

        code.annotation = CodeAnnotation(
            contexts=None,
            descriptive=False,
            primitive=False,
            staticFold=False,
            dynamicFold=False,
            origin=origin,
            live=None,
            killed=None,
            codeReads=None,
            codeModifies=None,
            codeAllocates=None,
            lowered=False,
            runtime=False,
            interpreter=False,
        )

        return code

    def _convert_function_args(
        self, args_node: python_ast.arguments, func: Any
    ) -> pyflow_ast.CodeParameters:
        """Convert Python AST arguments to pyflow AST CodeParameters."""
        from pyflow.language.python.program import Object

        # Prefer inspect.signature for real callables; it captures pos-only and kw-only.
        param_names = []
        per_param_defaults = []
        vararg = None
        kwarg = None

        sig = None
        if func is not None:
            try:
                sig = inspect.signature(func)
            except (TypeError, ValueError):
                sig = None

        if sig is not None:
            for p in sig.parameters.values():
                if p.kind in (
                    inspect.Parameter.POSITIONAL_ONLY,
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    inspect.Parameter.KEYWORD_ONLY,
                ):
                    param_names.append(p.name)
                    if p.default is inspect._empty:
                        per_param_defaults.append(None)
                    else:
                        per_param_defaults.append(pyflow_ast.Existing(Object(p.default)))
                elif p.kind == inspect.Parameter.VAR_POSITIONAL:
                    vararg = pyflow_ast.Local(p.name)
                elif p.kind == inspect.Parameter.VAR_KEYWORD:
                    kwarg = pyflow_ast.Local(p.name)
        else:
            # AST-only fallback.
            posonly = [a.arg for a in getattr(args_node, "posonlyargs", [])]
            regular = [a.arg for a in getattr(args_node, "args", [])]
            kwonly = [a.arg for a in getattr(args_node, "kwonlyargs", [])]
            param_names = [*posonly, *regular, *kwonly]
            per_param_defaults = [None] * len(param_names)

            positional_names = [*posonly, *regular]
            pos_defaults = list(getattr(args_node, "defaults", []) or [])
            if pos_defaults:
                start = len(positional_names) - len(pos_defaults)
                for i, default_node in enumerate(pos_defaults):
                    idx = start + i
                    try:
                        default_value = python_ast.literal_eval(default_node)
                        per_param_defaults[idx] = pyflow_ast.Existing(Object(default_value))
                    except Exception:
                        per_param_defaults[idx] = pyflow_ast.Existing(Object(None))

            kw_defaults = list(getattr(args_node, "kw_defaults", []) or [])
            if kwonly and kw_defaults:
                base = len(positional_names)
                for i, default_node in enumerate(kw_defaults):
                    if default_node is None:
                        continue
                    try:
                        default_value = python_ast.literal_eval(default_node)
                        per_param_defaults[base + i] = pyflow_ast.Existing(Object(default_value))
                    except Exception:
                        per_param_defaults[base + i] = pyflow_ast.Existing(Object(None))

            if args_node.vararg:
                vararg = pyflow_ast.Local(args_node.vararg.arg)
            if args_node.kwarg:
                kwarg = pyflow_ast.Local(args_node.kwarg.arg)

        params = [pyflow_ast.Local(name) for name in param_names]

        # Collapse to trailing-contiguous defaults as required by CalleeParams.
        first_default = next((i for i, d in enumerate(per_param_defaults) if d is not None), None)
        defaults = []
        if first_default is not None:
            for d in per_param_defaults[first_default:]:
                defaults.append(d if d is not None else pyflow_ast.Existing(Object(None)))

        return pyflow_ast.CodeParameters(
            selfparam=None,
            params=params,
            paramnames=param_names,
            defaults=tuple(defaults),
            vparam=vararg,
            kparam=kwarg,
            returnparams=[pyflow_ast.Local("ret0")],
        )

    def extract_function(
        self, node: python_ast.AST, program: Program, filename: Optional[str] = None
    ) -> None:
        """Extract information from a function definition."""
        try:
            if self.verbose:
                print(f"Found function: {node.name}")

            # Convert Python AST function to pyflow AST
            pyflow_code = self._convert_python_function_to_pyflow(node, None, filename=filename)

            # Add to program
            if hasattr(program, "liveCode"):
                program.liveCode.add(pyflow_code)
            else:
                # Create liveCode if it doesn't exist
                program.liveCode = {pyflow_code}

            if self.verbose:
                print(f"Added function {node.name} to program")

        except Exception as e:
            if self.verbose:
                print(f"Error processing function {node.name}: {e}")
                import traceback

                traceback.print_exc()

    def extract_class(
        self, node: python_ast.ClassDef, program: Program, filename: Optional[str] = None
    ) -> None:
        """Extract information from a class definition."""
        try:
            if self.verbose:
                print(f"Found class: {node.name}")
            # For now, treat methods as additional code objects with qualified names.
            # This provides method bodies to the analysis pipeline without requiring
            # full class-object modeling in the interface.
            for child in node.body:
                if isinstance(child, (python_ast.FunctionDef, python_ast.AsyncFunctionDef)):
                    code = self._convert_python_function_to_pyflow(child, None, filename=filename)
                    code.setCodeName(f"{node.name}.{child.name}")
                    if hasattr(program, "liveCode"):
                        program.liveCode.add(code)
                    else:
                        program.liveCode = {code}
                    if self.verbose:
                        print(f"Added method {node.name}.{child.name} to program")
        except Exception as e:
            if self.verbose:
                print(f"Error processing class {node.name}: {e}")
