"""
Function Extractor for converting Python functions to PyFlow AST.

This module handles the extraction and conversion of Python functions
to PyFlow's internal representation for static analysis.
"""

import ast as python_ast
import inspect
import textwrap
from typing import Any, Iterable, Optional

from pyflow.language.python import ast as pyflow_ast
from pyflow.language.python.annotations import CodeAnnotation
from pyflow.language.python.default_markers import MISSING_DEFAULT
from pyflow.language.python.pythonbase import PythonASTNode
from pyflow.application.program import Program

from .ast import ASTConverter
from .source import find_function_source_segment

_KWONLY_PARAM_PREFIX = "kwonly:"


class FunctionExtractor:
    """Extracts and converts Python functions to PyFlow AST."""

    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self.ast_converter = ASTConverter(verbose)
        self.diagnostics: list[str] = []

    def _callable_name(self, func: Any) -> str:
        return getattr(func, "__name__", "<unknown>")

    def _record_diagnostic(self, stage: str, func: Any, detail: str) -> None:
        message = f"{stage}:{self._callable_name(func)}: {detail}"
        self.diagnostics.append(message)

    def get_diagnostics(self) -> list[str]:
        return list(self.diagnostics)

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
                self._record_diagnostic(
                    "source_lookup", func, "source code unavailable; using minimal code"
                )
                return self._create_minimal_code(func, reason="source code unavailable")

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

            if func is not None:
                source = self._refine_source_for_callable(func, source)
                try:
                    source = textwrap.dedent(source)
                except Exception as e:
                    if self.verbose:
                        print(
                            f"DEBUG: Error dedenting refined source for {func.__name__}: {e}"
                        )

            # Parse it into a Python AST
            tree = python_ast.parse(source)

            # Find the function definition
            func_node = self._find_matching_function_node(tree, func)

            if func_node is None:
                if self.verbose:
                    print(
                        f"DEBUG: Could not find function definition for {func.__name__}"
                    )
                self._record_diagnostic(
                    "ast_match",
                    func,
                    "function definition not found; using minimal code",
                )
                return self._create_minimal_code(
                    func, reason="function definition not found"
                )

            # Convert Python AST to pyflow AST
            code_object = getattr(func, "__code__", None)
            result = self._convert_python_function_to_pyflow(
                func_node,
                func,
                filename=getattr(code_object, "co_filename", None),
            )
            return result

        except Exception as e:
            if self.verbose:
                print(f"DEBUG: Error analyzing function {func.__name__}: {e}")
                import traceback

                traceback.print_exc()
            # Fallback: create a minimal code stub
            self._record_diagnostic(
                "convert_function", func, f"{type(e).__name__}: {e}"
            )
            return self._create_minimal_code(func, reason=f"{type(e).__name__}: {e}")

    def _normalize_qualname(self, qualname: Optional[str]) -> Optional[str]:
        if qualname is None:
            return None
        return qualname.replace(".<locals>", "")

    def _refine_source_for_callable(self, func: Any, source: str) -> str:
        """Narrow a source blob to the best matching callable body when possible."""
        try:
            refined = find_function_source_segment(
                source,
                name=getattr(func, "__name__", None),
                qualname=getattr(func, "__qualname__", None),
                lineno=getattr(getattr(func, "__code__", None), "co_firstlineno", None),
            )
        except Exception:
            refined = None
        return refined or source

    def _iter_function_nodes_with_qualname(
        self,
        node: python_ast.AST,
        stack: Optional[list[str]] = None,
    ):
        if stack is None:
            stack = []

        body = getattr(node, "body", None)
        if not body:
            return

        for child in body:
            if isinstance(child, python_ast.ClassDef):
                yield from self._iter_function_nodes_with_qualname(
                    child, stack + [child.name]
                )
            elif isinstance(
                child, (python_ast.FunctionDef, python_ast.AsyncFunctionDef)
            ):
                qualname = ".".join([*stack, child.name])
                yield child, qualname
                yield from self._iter_function_nodes_with_qualname(
                    child, [*stack, child.name]
                )

    def _find_matching_function_node(
        self,
        tree: python_ast.AST,
        func: Any,
    ) -> Optional[python_ast.AST]:
        if func is None:
            for node, _qualname in self._iter_function_nodes_with_qualname(tree):
                return node
            return None

        target_name = getattr(func, "__name__", None)
        target_qualname = self._normalize_qualname(getattr(func, "__qualname__", None))
        target_lineno = getattr(getattr(func, "__code__", None), "co_firstlineno", None)

        candidates = []
        for node, qualname in self._iter_function_nodes_with_qualname(tree):
            if node.name != target_name:
                continue
            lineno = getattr(node, "lineno", None)
            normalized_qualname = self._normalize_qualname(qualname)
            candidates.append((node, normalized_qualname, lineno))

        if not candidates:
            return None

        if isinstance(target_lineno, int):
            line_matches = [
                node for node, _q, lineno in candidates if lineno == target_lineno
            ]
            if line_matches:
                return line_matches[0]

        if target_qualname:
            qual_matches = [
                node
                for node, qualname, _lineno in candidates
                if qualname == target_qualname
            ]
            if qual_matches:
                return qual_matches[0]

        return candidates[0][0]

    def _create_minimal_code(
        self, func: Any, reason: Optional[str] = None
    ) -> pyflow_ast.Code:
        """Create a minimal pyflow AST Code node with an empty Suite."""
        codeparams = self._empty_code_parameters()
        func_name = self._callable_name(func)
        code = pyflow_ast.Code(func_name, codeparams, pyflow_ast.Suite([]))
        origin = [f"minimal_code({func_name})"]
        if reason:
            origin.append(f"fallback_reason({reason})")
        code.annotation = self._make_code_annotation(origin)
        return code

    def _empty_code_parameters(self) -> pyflow_ast.CodeParameters:
        return pyflow_ast.CodeParameters(
            selfparam=None,
            posonlyparams=[],
            posonlynames=[],
            params=[],
            paramnames=[],
            defaults=[],
            vparam=None,
            kparam=None,
            returnparams=[pyflow_ast.Local("ret0")],
            type_params=None,
        )

    def _make_code_annotation(self, origin: list[str]) -> CodeAnnotation:
        return CodeAnnotation(
            descriptive=False,
            primitive=False,
            staticFold=False,
            dynamicFold=False,
            origin=origin,
            lowered=False,
            runtime=False,
            interpreter=False,
        )

    def create_synthetic_code(
        self,
        name: str,
        body_nodes: Iterable[python_ast.AST],
        *,
        filename: Optional[str] = None,
        first_lineno: int = 1,
        origin_tag: str,
    ) -> pyflow_ast.Code:
        body = self._convert_body(body_nodes, filename)
        code = pyflow_ast.Code(name, self._empty_code_parameters(), body)
        origin = [f"{origin_tag}({name})"]
        if filename:
            origin.append(f"source({filename}:{first_lineno})")
        code.annotation = self._make_code_annotation(origin)
        return code

    def _convert_python_function_to_pyflow(
        self, func_node: python_ast.AST, func: Any, *, filename: Optional[str] = None
    ) -> pyflow_ast.Code:
        """Convert a Python AST FunctionDef to a pyflow AST Code node."""
        # Convert function parameters
        codeparams = self._convert_function_args(func_node.args, func)

        # Convert function body
        body = self._convert_body(func_node.body, filename)

        # Use func_node.name if func is None
        func_name = func.__name__ if func else func_node.name

        # Ensure at least one return parameter for IPA
        if not codeparams.returnparams:
            codeparams = pyflow_ast.CodeParameters(
                selfparam=codeparams.selfparam,
                posonlyparams=codeparams.posonlyparams,
                posonlynames=codeparams.posonlynames,
                params=codeparams.params,
                paramnames=codeparams.paramnames,
                defaults=tuple(codeparams.defaults),
                vparam=codeparams.vparam,
                kparam=codeparams.kparam,
                returnparams=[pyflow_ast.Local("ret0")],
                type_params=codeparams.type_params,
            )

        code = pyflow_ast.Code(func_name, codeparams, body)

        # Initialize the annotation properly
        origin = [f"converted_function({func_name})"]
        if isinstance(func_node, python_ast.AsyncFunctionDef):
            origin.append("converted_async_function")
        if self._contains_yield(func_node):
            origin.append("converted_generator")
        try:
            if (
                func is not None
                and hasattr(func, "__code__")
                and func.__code__ is not None
            ):
                origin.append(
                    f"source({func.__code__.co_filename}:{func.__code__.co_firstlineno})"
                )
            else:
                lineno = getattr(func_node, "lineno", None)
                if filename and isinstance(lineno, int):
                    origin.append(f"source({filename}:{lineno})")
        except Exception:
            pass

        code.annotation = self._make_code_annotation(origin)

        return code

    @staticmethod
    def _contains_yield(func_node: python_ast.AST) -> bool:
        class YieldVisitor(python_ast.NodeVisitor):
            found = False

            def visit_Yield(self, node):
                self.found = True

            def visit_YieldFrom(self, node):
                self.found = True

            def visit_FunctionDef(self, node):
                if node is func_node:
                    self.generic_visit(node)

            def visit_AsyncFunctionDef(self, node):
                if node is func_node:
                    self.generic_visit(node)

            def visit_Lambda(self, node):
                return None

        visitor = YieldVisitor()
        visitor.visit(func_node)
        return visitor.found

    def _convert_body(
        self, body_nodes: Iterable[python_ast.AST], filename: Optional[str]
    ) -> pyflow_ast.Suite:
        previous_filename = self.ast_converter.current_filename
        self.ast_converter.current_filename = filename
        try:
            return self.ast_converter.convert_python_ast_to_pyflow(list(body_nodes))
        finally:
            self.ast_converter.current_filename = previous_filename

    def _add_code_to_program(self, program: Program, code: pyflow_ast.Code) -> None:
        if hasattr(program, "liveCode"):
            program.liveCode.add(code)
        else:
            program.liveCode = {code}

    def extract_module_body(
        self,
        body_nodes: Iterable[python_ast.AST],
        program: Program,
        *,
        module_name: str,
        filename: Optional[str] = None,
    ) -> None:
        body_nodes = list(body_nodes)
        if not body_nodes:
            return
        code = self.create_synthetic_code(
            f"{module_name}.<module>",
            body_nodes,
            filename=filename,
            first_lineno=1,
            origin_tag="synthetic_module",
        )
        self._add_code_to_program(program, code)

    def _convert_function_args(
        self, args_node: python_ast.arguments, func: Any
    ) -> pyflow_ast.CodeParameters:
        """Convert Python AST arguments to pyflow AST CodeParameters."""
        from pyflow.language.python.program import Object

        # Prefer inspect.signature for real callables; it captures pos-only and kw-only.
        # Parameter records are (kind, name, default) in declaration order.
        param_records: list[tuple[str, str, PythonASTNode | None]] = []
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
                if p.kind == inspect.Parameter.POSITIONAL_ONLY:
                    kind = "posonly"
                elif p.kind == inspect.Parameter.POSITIONAL_OR_KEYWORD:
                    kind = "regular"
                elif p.kind == inspect.Parameter.KEYWORD_ONLY:
                    kind = "kwonly"
                else:
                    kind = None
                if kind is not None:
                    default = (
                        None
                        if p.default is inspect._empty
                        else pyflow_ast.Existing(Object(p.default))
                    )
                    param_records.append((kind, p.name, default))
                elif p.kind == inspect.Parameter.VAR_POSITIONAL:
                    vararg = pyflow_ast.Local(p.name)
                elif p.kind == inspect.Parameter.VAR_KEYWORD:
                    kwarg = pyflow_ast.Local(p.name)
        else:
            # AST-only fallback.
            posonly = [a.arg for a in getattr(args_node, "posonlyargs", [])]
            regular = [a.arg for a in getattr(args_node, "args", [])]
            kwonly = [a.arg for a in getattr(args_node, "kwonlyargs", [])]
            param_records = (
                [("posonly", name, None) for name in posonly]
                + [("regular", name, None) for name in regular]
                + [("kwonly", name, None) for name in kwonly]
            )

            positional_names = [*posonly, *regular]
            pos_defaults = list(getattr(args_node, "defaults", []) or [])
            if pos_defaults:
                start = len(positional_names) - len(pos_defaults)
                for i, default_node in enumerate(pos_defaults):
                    idx = start + i
                    default = self.ast_converter._convert_default_value(default_node)
                    kind, name, _ = param_records[idx]
                    param_records[idx] = (kind, name, default)

            kw_defaults = list(getattr(args_node, "kw_defaults", []) or [])
            if kwonly and kw_defaults:
                base = len(positional_names)
                for i, default_node in enumerate(kw_defaults):
                    if default_node is None:
                        continue
                    default = self.ast_converter._convert_default_value(default_node)
                    kind, name, _ = param_records[base + i]
                    param_records[base + i] = (kind, name, default)

            if args_node.vararg:
                vararg = pyflow_ast.Local(args_node.vararg.arg)
            if args_node.kwarg:
                kwarg = pyflow_ast.Local(args_node.kwarg.arg)

        posonly_params = [
            pyflow_ast.Local(name)
            for kind, name, _default in param_records
            if kind == "posonly"
        ]
        posonly_names = [
            name for kind, name, _default in param_records if kind == "posonly"
        ]
        regular_params = [
            pyflow_ast.Local(name)
            for kind, name, _default in param_records
            if kind == "regular"
        ]
        regular_names = [
            name for kind, name, _default in param_records if kind == "regular"
        ]
        kwonly_params = [
            pyflow_ast.Local(name)
            for kind, name, _default in param_records
            if kind == "kwonly"
        ]
        kwonly_names = [
            name for kind, name, _default in param_records if kind == "kwonly"
        ]
        params = [*regular_params, *kwonly_params]
        param_names = [
            *regular_names,
            *(f"{_KWONLY_PARAM_PREFIX}{name}" for name in kwonly_names),
        ]
        per_param_defaults = [default for _kind, _name, default in param_records]

        first_default = next(
            (i for i, d in enumerate(per_param_defaults) if d is not None), None
        )
        defaults = []
        if first_default is not None:
            for d in per_param_defaults[first_default:]:
                defaults.append(
                    d if d is not None else pyflow_ast.Existing(Object(MISSING_DEFAULT))
                )

        return pyflow_ast.CodeParameters(
            selfparam=None,
            posonlyparams=posonly_params,
            posonlynames=posonly_names,
            params=params,
            paramnames=param_names,
            defaults=tuple(defaults),
            vparam=vararg,
            kparam=kwarg,
            returnparams=[pyflow_ast.Local("ret0")],
            type_params=None,
        )

    def extract_function(
        self, node: python_ast.AST, program: Program, filename: Optional[str] = None
    ) -> None:
        """Extract information from a function definition."""
        try:
            if self.verbose:
                print(f"Found function: {node.name}")

            # Convert Python AST function to pyflow AST
            pyflow_code = self._convert_python_function_to_pyflow(
                node, None, filename=filename
            )

            # Add to program
            self._add_code_to_program(program, pyflow_code)

            if self.verbose:
                print(f"Added function {node.name} to program")

        except Exception as e:
            if self.verbose:
                print(f"Error processing function {node.name}: {e}")
                import traceback

                traceback.print_exc()

    def extract_class(
        self,
        node: python_ast.ClassDef,
        program: Program,
        filename: Optional[str] = None,
        *,
        module_name: Optional[str] = None,
        qualname: Optional[str] = None,
    ) -> None:
        """Extract information from a class definition."""
        try:
            if self.verbose:
                print(f"Found class: {node.name}")
            qualname = qualname or node.name

            for child in node.body:
                if isinstance(
                    child, (python_ast.FunctionDef, python_ast.AsyncFunctionDef)
                ):
                    code = self._convert_python_function_to_pyflow(
                        child, None, filename=filename
                    )
                    code.setCodeName(f"{qualname}.{child.name}")
                    self._add_code_to_program(program, code)
                    if self.verbose:
                        print(f"Added method {qualname}.{child.name} to program")
                elif isinstance(child, python_ast.ClassDef):
                    self.extract_class(
                        child,
                        program,
                        filename=filename,
                        module_name=module_name,
                        qualname=f"{qualname}.{child.name}",
                    )
        except Exception as e:
            if self.verbose:
                print(f"Error processing class {node.name}: {e}")
