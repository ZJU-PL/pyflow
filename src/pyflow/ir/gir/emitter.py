"""Emit Lian-compatible GIR from pyflow's python IR.

The emitter walks the pyflow python AST (``pyflow.language.python``) and
produces an *unflattened* GIR statement tree: a nested structure of
``{operation: {fields...}}`` dicts exactly like the one Lian's Python frontend
builds before flattening. The Lian post-passes
(``unify_python_self`` / ``adjust_variable_decls`` / ``add_main_func``) run
afterward on the tree (see ``gir/postprocess.py``), followed by flattening to
rows (see ``gir/flatten.py``).

Lowering notes (mirroring the pyflow frontend in
``pyflow/frontend/conversion/ast.py``):

* binary/unary operators are lowered by the frontend to
  ``Call(Existing(Object("interpreter__add__")), [left, right])``; this emitter
  recognizes those helper names and re-materializes the Lian
  ``assign_stmt {operator}`` form;
* subscript reads are ``interpreter_getitem``, writes ``interpreter_setitem``
  and deletes ``interpreter_delitem`` (emitted as ``array_read`` /
  ``array_write`` / ``array_write %null``), and attribute reads
  ``interpreter_getattr`` (``field_read``);
* ``x += y`` reaches us as ``Assign(Call(op, [Local(x), y]), [Local(x)])`` and
  ``x = a + b`` as ``Assign(Call(op, [a, b]), [Local(x)])`` -- both are emitted
  as the operator form ``assign_stmt {target, operator, operand, operand2}``;
* source locations live in ``node.annotation.origin`` (a tuple for ordinary
  nodes, a tag list ending in a ``SourceOrigin`` for ``Code`` nodes).
* upstream Lian GIR represents class type parameters through the
  ``type_parameters`` field but has no corresponding function field. Generic
  classes preserve their parameters; generic functions emit a
  :class:`GirCompatibilityWarning` instead of inventing a non-Lian field.
"""

from __future__ import annotations

import ast as python_ast
import operator as python_operator
import warnings
from typing import Any, Dict, List, Optional, Sequence, Tuple

from pyflow.ir.gir.constants import (
    GirCounter,
    LIAN_INTERNAL,
    default_value_variable,
    tmp_method,
    tmp_variable,
)
from pyflow.language.asttools.origin import SourceOrigin
from pyflow.language.python import ast
from pyflow.language.python.default_markers import MISSING_DEFAULT
from pyflow.language.python.ir_metadata import (
    call_keyword_spreads,
    call_positional_items,
    gir_source_node,
)

#: Interpreter helper names for binary operators -> Lian ``assign_stmt``
#: operator strings. These are the callee names produced by the pyflow frontend
#: for ``a + b`` and comparison operators.
INTERPRETER_BINARY: Dict[str, str] = {
    "interpreter__add__": "+",
    "interpreter__sub__": "-",
    "interpreter__mul__": "*",
    "interpreter__matmul__": "@",
    "interpreter__truediv__": "/",
    "interpreter__floordiv__": "//",
    "interpreter__mod__": "%",
    "interpreter__pow__": "**",
    "interpreter__and__": "&",
    "interpreter__or__": "|",
    "interpreter__xor__": "^",
    "interpreter__lshift__": "<<",
    "interpreter__rshift__": ">>",
    "interpreter__eq__": "==",
    "interpreter__ne__": "!=",
    "interpreter__lt__": "<",
    "interpreter__le__": "<=",
    "interpreter__gt__": ">",
    "interpreter__ge__": ">=",
    "interpreter__is__": "is",
    "interpreter__is_not__": "is not",
    "interpreter__contains__": "in",
}

#: Interpreter helper names for unary operators.
INTERPRETER_UNARY: Dict[str, str] = {
    "interpreter__neg__": "-",
    "interpreter__pos__": "+",
    "interpreter__invert__": "~",
}

#: Interpreter helpers with dedicated GIR statement lowerings.
INTERPRETER_GETITEM = "interpreter_getitem"
INTERPRETER_SETITEM = "interpreter_setitem"
INTERPRETER_DELITEM = "interpreter_delitem"
INTERPRETER_GETATTR = "interpreter_getattr"

#: Prefix the pyflow frontend applies to keyword-only parameter names in
#: ``CodeParameters.paramnames`` (see ``frontend/conversion/functions.py``).
KWONLY_PARAM_PREFIX = "kwonly:"


class GirCompatibilityWarning(UserWarning):
    """Warn that source information cannot be represented in Lian GIR."""


class GirEmitter:
    """Transforms one pyflow ``Code`` into an unflattened GIR tree.

    Attribute ``counter`` is a per-unit :class:`GirCounter`; a fresh emitter
    must be created for every unit (module) so temporary names match Lian's
    per-parser allocation.
    """

    def __init__(self, counter: Optional[GirCounter] = None) -> None:
        self.counter = counter or GirCounter()

    # ------------------------------------------------------------------
    # Public entrypoints
    # ------------------------------------------------------------------
    def emit_unit(self, code: "ast.Code") -> List[Dict[str, Any]]:
        """Emit a module's top-level statements as a flat GIR statement list.

        ``FunctionDef`` / ``ClassDef`` blocks become top-level
        ``method_decl`` / ``class_decl`` rows; all other statements stay flat
        so that ``add_main_func`` can wrap them into ``%unit_init`` later.
        """
        statements: List[Dict[str, Any]] = []
        for block in code.ast.blocks:
            self.emit_statement(block, statements)
        return statements

    def emit_code(self, code: "ast.Code") -> List[Dict[str, Any]]:
        """Emit a single ``Code`` (function/method) as one ``method_decl``.

        Returns ``[preamble..., method_decl]`` where the preamble holds any
        default-value evaluation side effects that must run before the
        function is entered.
        """
        source = gir_source_node(code)
        source_function = source if isinstance(
            source, (python_ast.FunctionDef, python_ast.AsyncFunctionDef)
        ) else None
        parameters, preamble = self._code_parameters(code, source_function)
        body: List[Dict[str, Any]] = []
        for block in code.ast.blocks:
            self.emit_statement(block, body)
        method_decl = {
            "method_decl": {
                "attrs": (
                    [
                        python_ast.unparse(
                            decorator.func
                            if isinstance(decorator, python_ast.Call)
                            else decorator
                        )
                        for decorator in source_function.decorator_list
                    ]
                    + (
                        ["async"]
                        if isinstance(source_function, python_ast.AsyncFunctionDef)
                        else []
                    )
                    if source_function is not None
                    else []
                ),
                "data_type": (
                    python_ast.unparse(source_function.returns)
                    if source_function is not None
                    and source_function.returns is not None
                    else None
                ),
                "name": code.name,
                "parameters": parameters,
                "body": body,
            }
        }
        row = self._row_of(code)
        if source_function is not None:
            location_node: python_ast.AST = source_function
            if source_function.decorator_list:
                location_node = source_function.decorator_list[0]
            row = max(0, int(getattr(location_node, "lineno", 1)) - 1)
        method_decl["method_decl"]["decorators"] = row if row is not None else 0
        statements = list(preamble)
        statements.append(self.add_col_row_info(code, method_decl))
        return statements

    # ------------------------------------------------------------------
    # Location attachment (mirrors lian add_col_row_info)
    # ------------------------------------------------------------------
    @staticmethod
    def _source_origin(node: Any) -> Optional[SourceOrigin]:
        origin = getattr(getattr(node, "annotation", None), "origin", None)
        if origin is None:
            return None
        if isinstance(origin, SourceOrigin):
            return origin
        if isinstance(origin, (list, tuple)):
            for item in reversed(origin):
                if isinstance(item, SourceOrigin):
                    return item
        return None

    @classmethod
    def add_col_row_info(
        cls, node: Any, gir_node: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Attach source spans to the first dict of ``gir_node``."""
        origin = cls._source_origin(node)
        if origin is not None:
            inner = next(iter(gir_node.values()))
            # Lian/tree-sitter locations are zero-based; Python AST locations
            # stored by SourceOrigin are one-based.
            start_row = int(origin.lineno or 1)
            end_row = int(origin.end_lineno or start_row)
            inner["start_row"] = max(0, start_row - 1)
            inner["start_col"] = int(origin.col or 0)
            inner["end_row"] = max(0, end_row - 1)
            inner["end_col"] = int(origin.end_col or origin.col or 0)
        return gir_node

    @classmethod
    def _row_of(cls, node: Any) -> Optional[int]:
        origin = cls._source_origin(node)
        return (
            max(0, int(origin.lineno or 1) - 1)
            if origin is not None
            else None
        )

    @staticmethod
    def _add_python_col_row_info(
        node: python_ast.AST, gir_node: Dict[str, Any]
    ) -> Dict[str, Any]:
        inner = next(iter(gir_node.values()))
        start_row = int(getattr(node, "lineno", 1) or 1)
        start_col = int(getattr(node, "col_offset", 0) or 0)
        end_row = int(getattr(node, "end_lineno", start_row) or start_row)
        end_col = int(getattr(node, "end_col_offset", start_col) or start_col)
        inner["start_row"] = max(0, start_row - 1)
        inner["start_col"] = start_col
        inner["end_row"] = max(0, end_row - 1)
        inner["end_col"] = end_col
        return gir_node

    def _append_python_stmt(
        self,
        statements: List[Dict[str, Any]],
        node: python_ast.AST,
        gir_node: Dict[str, Any],
    ) -> None:
        statements.append(self._add_python_col_row_info(node, gir_node))

    @staticmethod
    def _python_literal(node: python_ast.Constant) -> str:
        value = node.value
        if value is None:
            return LIAN_INTERNAL.NULL
        if value is True:
            return LIAN_INTERNAL.TRUE
        if value is False:
            return LIAN_INTERNAL.FALSE
        if isinstance(value, (str, bytes)):
            return repr(value)
        return str(value)

    @staticmethod
    def _python_operator(operator: python_ast.AST) -> str:
        operators = {
            python_ast.Add: "+",
            python_ast.Sub: "-",
            python_ast.Mult: "*",
            python_ast.Div: "/",
            python_ast.FloorDiv: "//",
            python_ast.Mod: "%",
            python_ast.Pow: "**",
            python_ast.BitAnd: "&",
            python_ast.BitOr: "|",
            python_ast.BitXor: "^",
            python_ast.LShift: "<<",
            python_ast.RShift: ">>",
            python_ast.Eq: "==",
            python_ast.NotEq: "!=",
            python_ast.Lt: "<",
            python_ast.LtE: "<=",
            python_ast.Gt: ">",
            python_ast.GtE: ">=",
            python_ast.Is: "is",
            python_ast.IsNot: "is not",
            python_ast.In: "in",
            python_ast.NotIn: "not in",
            python_ast.UAdd: "+",
            python_ast.USub: "-",
            python_ast.Invert: "~",
        }
        return operators.get(type(operator), type(operator).__name__)

    @staticmethod
    def _evaluated_literal_expression(node: python_ast.AST) -> Optional[str]:
        binary = {
            python_ast.Add: python_operator.add,
            python_ast.Sub: python_operator.sub,
            python_ast.Mult: python_operator.mul,
            python_ast.Div: python_operator.truediv,
            python_ast.FloorDiv: python_operator.floordiv,
            python_ast.Mod: python_operator.mod,
            python_ast.Pow: python_operator.pow,
            python_ast.BitAnd: python_operator.and_,
            python_ast.BitOr: python_operator.or_,
            python_ast.BitXor: python_operator.xor,
            python_ast.LShift: python_operator.lshift,
            python_ast.RShift: python_operator.rshift,
        }
        comparisons = {
            python_ast.Eq: python_operator.eq,
            python_ast.NotEq: python_operator.ne,
            python_ast.Lt: python_operator.lt,
            python_ast.LtE: python_operator.le,
            python_ast.Gt: python_operator.gt,
            python_ast.GtE: python_operator.ge,
            python_ast.Is: python_operator.is_,
            python_ast.IsNot: python_operator.is_not,
            python_ast.In: lambda left, right: left in right,
            python_ast.NotIn: lambda left, right: left not in right,
        }

        def evaluate(current: python_ast.AST) -> Any:
            if isinstance(current, python_ast.Constant):
                return current.value
            if isinstance(current, python_ast.BinOp) and type(current.op) in binary:
                return binary[type(current.op)](
                    evaluate(current.left), evaluate(current.right)
                )
            if (
                isinstance(current, python_ast.Compare)
                and len(current.ops) == 1
                and type(current.ops[0]) in comparisons
            ):
                return comparisons[type(current.ops[0])](
                    evaluate(current.left), evaluate(current.comparators[0])
                )
            raise ValueError

        try:
            value = evaluate(node)
        except (ArithmeticError, TypeError, ValueError):
            return None
        return repr(value) if isinstance(value, (str, bytes)) else str(value)

    def _emit_python_collection(
        self, node: python_ast.AST, statements: List[Dict[str, Any]]
    ) -> str:
        target = tmp_variable(self.counter)
        if isinstance(node, python_ast.Dict):
            self._append_python_stmt(
                statements, node, {"new_record": {"target": target}}
            )
            pair_count = 0
            for key, value in zip(node.keys, node.values):
                if key is None:
                    source = self._emit_python_expression(value, statements)
                    self._append_python_stmt(
                        statements,
                        node,
                        {"record_extend": {"record": target, "source": source}},
                    )
                else:
                    if pair_count >= 32:
                        continue
                    key_name = self._emit_python_expression(key, statements)
                    source = self._emit_python_expression(value, statements)
                    self._append_python_stmt(
                        statements,
                        node,
                        {
                            "record_write": {
                                "receiver_record": target,
                                "key": key_name,
                                "value": source,
                            }
                        },
                    )
                    pair_count += 1
            return target

        attrs: List[str] = []
        if isinstance(node, python_ast.Tuple):
            attrs = ["tuple"]
        elif isinstance(node, python_ast.Set):
            attrs = ["set"]
        gir: Dict[str, Any] = {"new_array": {"target": target}}
        if attrs:
            gir["new_array"]["attrs"] = attrs
        self._append_python_stmt(statements, node, gir)
        if isinstance(node, python_ast.Set):
            # Preserve Lian's current Python-parser row sequence: set literals
            # carry an attributed allocation followed by the common array
            # allocation row used for lists and sets.
            self._append_python_stmt(
                statements, node, {"new_array": {"target": target}}
            )
        elements = list(getattr(node, "elts", ()))
        met_spread = False
        plain_index = 0
        for element in elements:
            if isinstance(element, python_ast.Starred):
                met_spread = True
                source = self._emit_python_expression(element.value, statements)
                operation = {"array_extend": {"array": target, "source": source}}
            else:
                source = self._emit_python_expression(element, statements)
                if met_spread:
                    operation = {
                        "array_append": {"array": target, "source": source}
                    }
                else:
                    operation = {
                        "array_write": {
                            "array": target,
                            "index": str(plain_index),
                            "source": source,
                        }
                    }
                    plain_index += 1
            self._append_python_stmt(statements, element, operation)
        return target

    def _emit_python_call(
        self, node: python_ast.Call, statements: List[Dict[str, Any]]
    ) -> str:
        target = tmp_variable(self.counter)
        receiver: Optional[str] = None
        if isinstance(node.func, python_ast.Attribute):
            receiver = self._emit_python_expression(node.func.value, statements)
            name = node.func.attr
        else:
            name = self._emit_python_expression(node.func, statements)

        positional: List[str] = []
        packed_positional: Optional[str] = None
        if any(isinstance(arg, python_ast.Starred) for arg in node.args):
            packed_positional = tmp_variable(self.counter)
            self._append_python_stmt(
                statements, node, {"new_array": {"target": packed_positional}}
            )
            met_spread = False
            index = 0
            for argument in node.args:
                if isinstance(argument, python_ast.Starred):
                    met_spread = True
                    value = self._emit_python_expression(argument.value, statements)
                    operation = {
                        "array_extend": {
                            "array": packed_positional,
                            "source": value,
                        }
                    }
                else:
                    value = self._emit_python_expression(argument, statements)
                    if met_spread:
                        operation = {
                            "array_append": {
                                "array": packed_positional,
                                "source": value,
                            }
                        }
                    else:
                        operation = {
                            "array_write": {
                                "array": packed_positional,
                                "index": str(index),
                                "source": value,
                            }
                        }
                        index += 1
                self._append_python_stmt(statements, argument, operation)
        else:
            positional = [
                self._emit_python_expression(argument, statements)
                for argument in node.args
            ]

        named: Dict[str, str] = {}
        packed_named: Optional[str] = None
        if any(keyword.arg is None for keyword in node.keywords):
            packed_named = tmp_variable(self.counter)
            self._append_python_stmt(
                statements, node, {"new_record": {"target": packed_named}}
            )
            for keyword in node.keywords:
                value = self._emit_python_expression(keyword.value, statements)
                if keyword.arg is None:
                    operation = {
                        "record_extend": {
                            "record": packed_named,
                            "source": value,
                        }
                    }
                else:
                    operation = {
                        "record_write": {
                            "receiver_record": packed_named,
                            "key": keyword.arg,
                            "value": value,
                        }
                    }
                self._append_python_stmt(statements, keyword.value, operation)
        else:
            for keyword in node.keywords:
                named[str(keyword.arg)] = self._emit_python_expression(
                    keyword.value, statements
                )

        if receiver is None:
            operation = {"call_stmt": {"target": target, "name": name}}
        else:
            operation = {
                "object_call_stmt": {
                    "target": target,
                    "field": name,
                    "receiver_object": receiver,
                }
            }
        content = next(iter(operation.values()))
        if node.args or node.keywords:
            content["positional_args"] = positional
            content["packed_positional_args"] = packed_positional
            content["packed_named_args"] = packed_named
            content["named_args"] = str(named) if named else None
        self._append_python_stmt(statements, node, operation)
        return target

    def _emit_python_comprehension(
        self, node: python_ast.AST, statements: List[Dict[str, Any]]
    ) -> str:
        target = tmp_variable(self.counter)
        is_dict = isinstance(node, python_ast.DictComp)
        init = "new_record" if is_dict else "new_array"
        self._append_python_stmt(statements, node, {init: {"target": target}})

        generators = list(getattr(node, "generators", ()))

        def build_clause(index: int, destination: List[Dict[str, Any]]) -> None:
            if index >= len(generators):
                if is_dict:
                    key = self._emit_python_expression(node.key, destination)
                    value = self._emit_python_expression(node.value, destination)
                    self._append_python_stmt(
                        destination,
                        node,
                        {
                            "record_write": {
                                "receiver_record": target,
                                "key": key,
                                "value": value,
                            }
                        },
                    )
                else:
                    value = self._emit_python_expression(node.elt, destination)
                    self._append_python_stmt(
                        destination,
                        node,
                        {"array_append": {"array": target, "source": value}},
                    )
                return
            generator = generators[index]
            body: List[Dict[str, Any]] = []

            def build_filters(filter_index: int, output: List[Dict[str, Any]]) -> None:
                if filter_index >= len(generator.ifs):
                    build_clause(index + 1, output)
                    return
                condition = self._emit_python_expression(
                    generator.ifs[filter_index], output
                )
                then_body: List[Dict[str, Any]] = []
                build_filters(filter_index + 1, then_body)
                self._append_python_stmt(
                    output,
                    generator.ifs[filter_index],
                    {"if_stmt": {"condition": condition, "then_body": then_body}},
                )

            build_filters(0, body)
            receiver = self._emit_python_expression(generator.iter, destination)
            name = self._python_target_name(generator.target)
            self._append_python_stmt(
                destination,
                generator.target,
                {"variable_decl": {"name": name}},
            )
            self._append_python_stmt(
                destination,
                generator.target,
                {
                    "forin_stmt": {
                        "attr": ["async"] if generator.is_async else [],
                        "name": name,
                        "receiver": receiver,
                        "body": body,
                    }
                },
            )

        build_clause(0, statements)
        return target

    def _emit_python_lambda(
        self, node: python_ast.Lambda, statements: List[Dict[str, Any]]
    ) -> str:
        method_name = tmp_method(self.counter)
        parameters: List[Dict[str, Any]] = []
        positional = [*node.args.posonlyargs, *node.args.args]
        default_offset = len(positional) - len(node.args.defaults)
        for index, argument in enumerate(positional):
            attrs = (
                [LIAN_INTERNAL.POSITIONAL_ONLY_PARAMETER]
                if index < len(node.args.posonlyargs)
                else []
            )
            default_value: Optional[str] = None
            if index >= default_offset:
                default = node.args.defaults[index - default_offset]
                if isinstance(default, python_ast.Constant):
                    default_value = self._python_literal(default)
                else:
                    default_value = default_value_variable(self.counter)
                    statements.append({"variable_decl": {"name": default_value}})
                    value = self._emit_python_expression(default, statements)
                    statements.append(
                        {
                            "assign_stmt": {
                                "target": default_value,
                                "operand": value,
                            }
                        }
                    )
            parameter = {
                "parameter_decl": {
                    "data_type": (
                        python_ast.unparse(argument.annotation)
                        if argument.annotation is not None
                        else None
                    ),
                    "name": argument.arg,
                    "attrs": attrs,
                    "default_value": default_value,
                }
            }
            parameters.append(self._add_python_col_row_info(argument, parameter))
        if node.args.vararg is not None:
            argument = node.args.vararg
            parameters.append(
                self._add_python_col_row_info(
                    argument,
                    {
                        "parameter_decl": {
                            "data_type": (
                                python_ast.unparse(argument.annotation)
                                if argument.annotation is not None
                                else None
                            ),
                            "name": argument.arg,
                            "attrs": [LIAN_INTERNAL.PACKED_POSITIONAL_PARAMETER],
                        }
                    },
                )
            )
        for argument, default in zip(
            node.args.kwonlyargs, node.args.kw_defaults
        ):
            default_value = (
                self._emit_python_expression(default, statements)
                if default is not None
                else None
            )
            parameters.append(
                self._add_python_col_row_info(
                    argument,
                    {
                        "parameter_decl": {
                            "data_type": (
                                python_ast.unparse(argument.annotation)
                                if argument.annotation is not None
                                else None
                            ),
                            "name": argument.arg,
                            "attrs": [LIAN_INTERNAL.KEYWORLD_ONLY_PARAMETER],
                            "default_value": default_value,
                        }
                    },
                )
            )
        if node.args.kwarg is not None:
            argument = node.args.kwarg
            parameters.append(
                self._add_python_col_row_info(
                    argument,
                    {
                        "parameter_decl": {
                            "data_type": (
                                python_ast.unparse(argument.annotation)
                                if argument.annotation is not None
                                else None
                            ),
                            "name": argument.arg,
                            "attrs": [LIAN_INTERNAL.PACKED_NAMED_PARAMETER],
                        }
                    },
                )
            )
        body: List[Dict[str, Any]] = []
        result = self._emit_python_expression(node.body, body)
        body.append(
            self._add_python_col_row_info(
                node, {"return_stmt": {"name": result}}
            )
        )
        self._append_python_stmt(
            statements,
            node,
            {
                "method_decl": {
                    "name": method_name,
                    "parameters": parameters,
                    "body": body,
                }
            },
        )
        return method_name

    @staticmethod
    def _python_target_name(target: python_ast.AST) -> str:
        if isinstance(target, python_ast.Name):
            return target.id
        return python_ast.unparse(target)

    def _emit_python_expression(
        self, node: Optional[python_ast.AST], statements: List[Dict[str, Any]]
    ) -> str:
        if node is None:
            return ""
        if isinstance(node, python_ast.Name):
            return node.id
        if isinstance(node, python_ast.Constant):
            return self._python_literal(node)
        if isinstance(
            node,
            (python_ast.List, python_ast.Tuple, python_ast.Set, python_ast.Dict),
        ):
            return self._emit_python_collection(node, statements)
        if isinstance(
            node,
            (
                python_ast.ListComp,
                python_ast.SetComp,
                python_ast.DictComp,
                python_ast.GeneratorExp,
            ),
        ):
            return self._emit_python_comprehension(node, statements)
        if isinstance(node, python_ast.Call):
            return self._emit_python_call(node, statements)
        if isinstance(node, python_ast.Lambda):
            return self._emit_python_lambda(node, statements)
        if isinstance(node, python_ast.JoinedStr):
            rendered = python_ast.unparse(node)
            for part in node.values:
                if isinstance(part, python_ast.FormattedValue):
                    source_text = python_ast.unparse(part.value)
                    value = self._emit_python_expression(part.value, statements)
                    rendered = rendered.replace(source_text, value)
            return rendered
        if isinstance(node, python_ast.FormattedValue):
            return self._emit_python_expression(node.value, statements)
        if isinstance(node, python_ast.Attribute):
            target = tmp_variable(self.counter)
            receiver = self._emit_python_expression(node.value, statements)
            self._append_python_stmt(
                statements,
                node,
                {
                    "field_read": {
                        "target": target,
                        "receiver_object": receiver,
                        "field": node.attr,
                    }
                },
            )
            return target
        if isinstance(node, python_ast.Subscript):
            array = self._emit_python_expression(node.value, statements)
            target = tmp_variable(self.counter)
            if isinstance(node.slice, python_ast.Slice):
                operation = {
                    "slice_read": {
                        "target": target,
                        "array": array,
                        "start": self._emit_python_expression(
                            node.slice.lower, statements
                        ),
                        "end": self._emit_python_expression(
                            node.slice.upper, statements
                        ),
                        "step": self._emit_python_expression(
                            node.slice.step, statements
                        ),
                    }
                }
            else:
                operation = {
                    "array_read": {
                        "target": target,
                        "array": array,
                        "index": self._emit_python_expression(node.slice, statements),
                    }
                }
            self._append_python_stmt(statements, node, operation)
            return target
        if isinstance(node, (python_ast.BinOp, python_ast.Compare)):
            evaluated = self._evaluated_literal_expression(node)
            if evaluated is not None:
                return evaluated
            if isinstance(node, python_ast.BinOp):
                left_node, right_node, operator_node = node.left, node.right, node.op
                operator_text = self._python_operator(operator_node)
            else:
                left_node = node.left
                right_node = node.comparators[-1]
                operator_node = node.ops[0]
                operator_text = " ".join(
                    self._python_operator(operator) for operator in node.ops
                )
            target = tmp_variable(self.counter)
            left = self._emit_python_expression(left_node, statements)
            right = self._emit_python_expression(right_node, statements)
            self._append_python_stmt(
                statements,
                node,
                {
                    "assign_stmt": {
                        "target": target,
                        "operator": operator_text,
                        "operand": left,
                        "operand2": right,
                    }
                },
            )
            return target
        if isinstance(node, python_ast.UnaryOp):
            operand = self._emit_python_expression(node.operand, statements)
            if isinstance(node.op, python_ast.Not):
                target = tmp_variable(self.counter)
                self._append_python_stmt(
                    statements,
                    node,
                    {
                        "assign_stmt": {
                            "target": target,
                            "operator": "not",
                            "operand": operand,
                        }
                    },
                )
                return target
            target = tmp_variable(self.counter)
            self._append_python_stmt(
                statements,
                node,
                {
                    "assign_stmt": {
                        "target": target,
                        "operator": self._python_operator(node.op),
                        "operand": operand,
                    }
                },
            )
            return target
        if isinstance(node, python_ast.BoolOp):
            values = list(node.values)
            result = self._emit_python_expression(values[0], statements)
            operator = "and" if isinstance(node.op, python_ast.And) else "or"
            for value_node in values[1:]:
                right = self._emit_python_expression(value_node, statements)
                target = tmp_variable(self.counter)
                self._append_python_stmt(
                    statements,
                    node,
                    {
                        "assign_stmt": {
                            "target": target,
                            "operator": operator,
                            "operand": result,
                            "operand2": right,
                        }
                    },
                )
                result = target
            return result
        if isinstance(node, python_ast.IfExp):
            target = tmp_variable(self.counter)
            condition = self._emit_python_expression(node.test, statements)
            then_body: List[Dict[str, Any]] = []
            else_body: List[Dict[str, Any]] = []
            then_value = self._emit_python_expression(node.body, then_body)
            else_value = self._emit_python_expression(node.orelse, else_body)
            then_body.append({"assign_stmt": {"target": target, "operand": then_value}})
            else_body.append({"assign_stmt": {"target": target, "operand": else_value}})
            self._append_python_stmt(
                statements,
                node,
                {
                    "if_stmt": {
                        "condition": condition,
                        "then_body": then_body,
                        "else_body": else_body,
                    }
                },
            )
            return target
        if isinstance(node, python_ast.NamedExpr):
            value = self._emit_python_expression(node.value, statements)
            name = self._python_target_name(node.target)
            self._append_python_stmt(
                statements, node, {"assign_stmt": {"target": name, "operand": value}}
            )
            return name
        if isinstance(node, python_ast.Await):
            target = self._emit_python_expression(node.value, statements)
            self._append_python_stmt(
                statements, node, {"await_stmt": {"target": target}}
            )
            return target
        if isinstance(node, (python_ast.Yield, python_ast.YieldFrom)):
            value_node = getattr(node, "value", None)
            target = self._emit_python_expression(value_node, statements)
            self._append_python_stmt(
                statements, node, {"yield_stmt": {"target": target}}
            )
            return ""
        return python_ast.unparse(node)

    def _emit_python_store(
        self,
        target: python_ast.AST,
        source: str,
        statements: List[Dict[str, Any]],
        location: python_ast.AST,
        *,
        declare: bool = True,
    ) -> None:
        if isinstance(target, python_ast.Name):
            if declare:
                self._append_python_stmt(
                    statements,
                    location,
                    {
                        "variable_decl": {
                            "data_type": None,
                            "name": target.id,
                        }
                    },
                )
            self._append_python_stmt(
                statements,
                location,
                {"assign_stmt": {"target": target.id, "operand": source}},
            )
            return
        if isinstance(target, python_ast.Attribute):
            receiver = self._emit_python_expression(target.value, statements)
            self._append_python_stmt(
                statements,
                location,
                {
                    "field_write": {
                        "receiver_object": receiver,
                        "field": target.attr,
                        "source": source,
                    }
                },
            )
            return
        if isinstance(target, python_ast.Subscript):
            array = self._emit_python_expression(target.value, statements)
            if isinstance(target.slice, python_ast.Slice):
                operation = {
                    "slice_write": {
                        "array": array,
                        "source": source,
                        "start": self._emit_python_expression(
                            target.slice.lower, statements
                        ),
                        "end": self._emit_python_expression(
                            target.slice.upper, statements
                        ),
                        "step": self._emit_python_expression(
                            target.slice.step, statements
                        ),
                    }
                }
            else:
                operation = {
                    "array_write": {
                        "array": array,
                        "index": self._emit_python_expression(
                            target.slice, statements
                        ),
                        "source": source,
                    }
                }
            self._append_python_stmt(statements, location, operation)
            return
        if isinstance(target, (python_ast.Tuple, python_ast.List)):
            for index, element in enumerate(target.elts):
                value = tmp_variable(self.counter)
                self._append_python_stmt(
                    statements,
                    location,
                    {
                        "array_read": {
                            "target": value,
                            "array": source,
                            "index": str(index),
                        }
                    },
                )
                self._emit_python_store(element, value, statements, location)

    def _emit_python_body(
        self,
        body: Sequence[python_ast.stmt],
        statements: List[Dict[str, Any]],
    ) -> None:
        for child in body:
            self._emit_python_statement(child, statements)

    def _emit_python_pattern(
        self, pattern: python_ast.AST, statements: List[Dict[str, Any]]
    ) -> str:
        if isinstance(pattern, python_ast.MatchValue):
            return self._emit_python_expression(pattern.value, statements)
        if isinstance(pattern, python_ast.MatchSingleton):
            constant = python_ast.Constant(pattern.value)
            return self._python_literal(constant)
        if isinstance(pattern, python_ast.MatchAs):
            if pattern.pattern is None:
                return "_" if pattern.name is None else pattern.name
            return self._emit_python_pattern(pattern.pattern, statements)
        if isinstance(pattern, python_ast.MatchOr):
            return " | ".join(
                self._emit_python_pattern(item, statements)
                for item in pattern.patterns
            )
        return python_ast.unparse(pattern)

    def _emit_python_statement(
        self, node: python_ast.stmt, statements: List[Dict[str, Any]]
    ) -> bool:
        if isinstance(node, python_ast.Import):
            for alias in node.names:
                content: Dict[str, Any] = {"name": alias.name}
                if alias.asname:
                    content["alias"] = alias.asname
                self._append_python_stmt(
                    statements, node, {"import_stmt": content}
                )
            return True
        if isinstance(node, python_ast.ImportFrom):
            source = "." * int(node.level or 0) + (node.module or "")
            if node.module == "__future__":
                source = "__future__"
            for alias in node.names:
                content = {"source": source, "name": alias.name}
                if alias.asname:
                    content["alias"] = alias.asname
                self._append_python_stmt(
                    statements, node, {"from_import_stmt": content}
                )
            return True
        if isinstance(node, (python_ast.Assign, python_ast.AnnAssign)):
            value_node = getattr(node, "value", None)
            if isinstance(node, python_ast.AnnAssign):
                target_name = self._python_target_name(node.target)
                self._append_python_stmt(
                    statements,
                    node,
                    {
                        "variable_decl": {
                            "data_type": python_ast.unparse(node.annotation),
                            "name": target_name,
                        }
                    },
                )
                if value_node is None:
                    return True
                targets = [node.target]
            else:
                targets = list(node.targets)
            source = self._emit_python_expression(value_node, statements)
            for target in targets:
                self._emit_python_store(
                    target,
                    source,
                    statements,
                    node,
                    declare=not isinstance(node, python_ast.AnnAssign),
                )
            return True
        if isinstance(node, python_ast.AugAssign):
            if isinstance(node.target, python_ast.Name):
                left = node.target.id
            else:
                left = self._emit_python_expression(node.target, statements)
            right = self._emit_python_expression(node.value, statements)
            result = tmp_variable(self.counter)
            self._append_python_stmt(
                statements,
                node,
                {
                    "assign_stmt": {
                        "target": result,
                        "operator": self._python_operator(node.op),
                        "operand": left,
                        "operand2": right,
                    }
                },
            )
            self._emit_python_store(
                node.target, result, statements, node, declare=False
            )
            return True
        if isinstance(node, python_ast.Expr):
            self._emit_python_expression(node.value, statements)
            return True
        if isinstance(node, python_ast.Return):
            name = self._emit_python_expression(node.value, statements)
            self._append_python_stmt(
                statements, node, {"return_stmt": {"name": name}}
            )
            return True
        if isinstance(node, python_ast.Raise):
            name = self._emit_python_expression(node.exc, statements)
            self._append_python_stmt(
                statements, node, {"throw_stmt": {"name": name}}
            )
            return True
        if isinstance(node, python_ast.Assert):
            condition = self._emit_python_expression(node.test, statements)
            self._append_python_stmt(
                statements, node, {"assert_stmt": {"condition": condition}}
            )
            return True
        if isinstance(node, python_ast.If):
            condition = self._emit_python_expression(node.test, statements)
            then_body: List[Dict[str, Any]] = []
            else_body: List[Dict[str, Any]] = []
            self._emit_python_body(node.body, then_body)
            self._emit_python_body(node.orelse, else_body)
            self._append_python_stmt(
                statements,
                node,
                {
                    "if_stmt": {
                        "condition": condition,
                        "then_body": then_body,
                        "else_body": else_body,
                    }
                },
            )
            return True
        if isinstance(node, (python_ast.For, python_ast.AsyncFor)):
            receiver = self._emit_python_expression(node.iter, statements)
            body: List[Dict[str, Any]] = []
            if isinstance(node.target, python_ast.Name):
                name = node.target.id
            else:
                name = tmp_variable(self.counter)
                for index, target in enumerate(node.target.elts):
                    target_name = self._python_target_name(target)
                    self._append_python_stmt(
                        body,
                        node,
                        {
                            "array_read": {
                                "array": name,
                                "index": str(index),
                                "target": target_name,
                            }
                        },
                    )
            self._emit_python_body(node.body, body)
            self._append_python_stmt(
                statements, node, {"variable_decl": {"name": name}}
            )
            self._append_python_stmt(
                statements,
                node,
                {
                    "forin_stmt": {
                        "attrs": ["async"]
                        if isinstance(node, python_ast.AsyncFor)
                        else [],
                        "name": name,
                        "receiver": receiver,
                        "body": body,
                    }
                },
            )
            return True
        if isinstance(node, python_ast.While):
            condition_init: List[Dict[str, Any]] = []
            condition = self._emit_python_expression(node.test, condition_init)
            body: List[Dict[str, Any]] = []
            self._emit_python_body(node.body, body)
            body.extend(condition_init)
            statements.extend(condition_init)
            else_body: List[Dict[str, Any]] = []
            self._emit_python_body(node.orelse, else_body)
            self._append_python_stmt(
                statements,
                node,
                {
                    "while_stmt": {
                        "condition": condition,
                        "body": body,
                        "else_body": else_body,
                    }
                },
            )
            return True
        if isinstance(node, (python_ast.Try, getattr(python_ast, "TryStar", python_ast.Try))):
            try_body: List[Dict[str, Any]] = []
            self._emit_python_body(node.body, try_body)
            catches: List[Dict[str, Any]] = []
            for handler in node.handlers:
                content: Dict[str, Any] = {}
                if handler.type is not None:
                    content["expcetion"] = self._emit_python_expression(
                        handler.type, statements
                    )
                if handler.name:
                    content["as"] = handler.name
                handler_body: List[Dict[str, Any]] = []
                self._emit_python_body(handler.body, handler_body)
                content["body"] = handler_body
                catches.append(
                    self._add_python_col_row_info(
                        handler, {"catch_clause": content}
                    )
                )
            else_body: List[Dict[str, Any]] = []
            final_body: List[Dict[str, Any]] = []
            self._emit_python_body(node.orelse, else_body)
            self._emit_python_body(node.finalbody, final_body)
            self._append_python_stmt(
                statements,
                node,
                {
                    "try_stmt": {
                        "try_body": try_body,
                        "catch_body": catches,
                        "else_body": else_body,
                        "final_body": final_body,
                    }
                },
            )
            return True
        if isinstance(node, (python_ast.With, python_ast.AsyncWith)):
            init_body: List[Dict[str, Any]] = []
            for item in node.items:
                self._emit_python_expression(item.context_expr, init_body)
            update_body: List[Dict[str, Any]] = []
            self._emit_python_body(node.body, update_body)
            self._append_python_stmt(
                statements,
                node,
                {
                    "with_stmt": {
                        "attrs": ["async"]
                        if isinstance(node, python_ast.AsyncWith)
                        else [],
                        "init_body": init_body,
                        "update_body": update_body,
                    }
                },
            )
            return True
        if isinstance(node, python_ast.Match):
            condition = self._emit_python_expression(node.subject, statements)
            cases: List[Dict[str, Any]] = []
            for case in node.cases:
                body: List[Dict[str, Any]] = []
                self._emit_python_body(case.body, body)
                if (
                    isinstance(case.pattern, python_ast.MatchAs)
                    and case.pattern.pattern is None
                    and case.pattern.name is None
                ):
                    cases.append({"default_stmt": {"body": body}})
                else:
                    pattern = self._emit_python_pattern(case.pattern, statements)
                    cases.append(
                        {"case_stmt": {"condition": pattern, "body": body}}
                    )
            self._append_python_stmt(
                statements,
                node,
                {"switch_stmt": {"condition": condition, "body": cases}},
            )
            return True
        if isinstance(node, python_ast.Delete):
            for target in node.targets:
                name = self._emit_python_expression(target, statements)
                self._append_python_stmt(
                    statements, node, {"del_stmt": {"name": name}}
                )
            return True
        if isinstance(node, python_ast.Global):
            for name in node.names:
                self._append_python_stmt(
                    statements, node, {"global_stmt": {"name": name}}
                )
            return True
        if isinstance(node, python_ast.Nonlocal):
            for name in node.names:
                self._append_python_stmt(
                    statements, node, {"nonlocal_stmt": {"name": name}}
                )
            return True
        if isinstance(node, python_ast.Break):
            self._append_python_stmt(
                statements, node, {"break_stmt": {"name": ""}}
            )
            return True
        if isinstance(node, python_ast.Continue):
            self._append_python_stmt(
                statements, node, {"continue_stmt": {"name": ""}}
            )
            return True
        if isinstance(node, python_ast.Pass):
            self._append_python_stmt(statements, node, {"pass_stmt": {}})
            return True
        if hasattr(python_ast, "TypeAlias") and isinstance(
            node, python_ast.TypeAlias
        ):
            name = self._python_target_name(node.name)
            data_type = python_ast.unparse(node.value)
            self._append_python_stmt(
                statements,
                node,
                {"type_alias_decl": {"name": name, "data_type": data_type}},
            )
            return True
        return False

    # ------------------------------------------------------------------
    # Literals / names
    # ------------------------------------------------------------------
    @staticmethod
    def _existing_value(expr: "ast.Existing") -> Optional[str]:
        pyobj = getattr(getattr(expr, "object", None), "pyobj", None)
        if pyobj is None or pyobj is MISSING_DEFAULT:
            return None
        if pyobj is True:
            return LIAN_INTERNAL.TRUE
        if pyobj is False:
            return LIAN_INTERNAL.FALSE
        if isinstance(pyobj, str):
            return pyobj
        return str(pyobj)

    def emit_expression(
        self, expr: Any, statements: List[Dict[str, Any]]
    ) -> str:
        """Emit an expression, appending side-effect statements, and return
        the name of the value it produces (a plain name, temp, or literal)."""
        if expr is None:
            return ""

        source = gir_source_node(expr)
        if isinstance(source, python_ast.expr):
            return self._emit_python_expression(source, statements)

        handler = getattr(self, f"_emit_{type(expr).__name__}", None)
        if handler is not None:
            return handler(expr, statements)

        # Fallback: unknown expressions produce no value.
        return ""

    # ------------------------------------------------------------------
    # Names
    # ------------------------------------------------------------------
    @staticmethod
    def _emit_Local(expr, statements: List[Dict[str, Any]]) -> str:
        return expr.name or ""

    @staticmethod
    def _emit_DoNotCare(expr, statements: List[Dict[str, Any]]) -> str:
        return ""

    def _emit_GetGlobal(self, expr, statements: List[Dict[str, Any]]) -> str:
        return self._existing_value(expr.name) or ""

    @staticmethod
    def _emit_GetCell(expr, statements: List[Dict[str, Any]]) -> str:
        return expr.cell.name

    @staticmethod
    def _emit_GetCellDeref(expr, statements: List[Dict[str, Any]]) -> str:
        return expr.cell.name

    def _emit_GetIter(self, expr, statements: List[Dict[str, Any]]) -> str:
        # Lian parses the iterable expression directly in for_statement.
        return self.emit_expression(expr.expr, statements)

    def _emit_AsyncGetIter(self, expr, statements: List[Dict[str, Any]]) -> str:
        return self.emit_expression(expr.expr, statements)

    @staticmethod
    def _emit_Input(expr, statements: List[Dict[str, Any]]) -> str:
        return ""

    @staticmethod
    def _emit_Output(expr, statements: List[Dict[str, Any]]) -> str:
        return ""

    def _emit_Existing(self, expr, statements: List[Dict[str, Any]]) -> str:
        return self._existing_value(expr) or ""

    def _emit_Import(self, expr, statements: List[Dict[str, Any]]) -> str:
        # The frontend wraps Import inside Assign; a bare Import expression
        # simply evaluates to its module name.
        return expr.name

    # ------------------------------------------------------------------
    # Attribute / subscript reads
    # ------------------------------------------------------------------
    def _emit_GetAttr(self, expr, statements: List[Dict[str, Any]]) -> str:
        target = tmp_variable(self.counter)
        receiver = self.emit_expression(expr.expr, statements)
        field = self.emit_expression(expr.name, statements)
        self._emit_variable_decl(target, statements)
        statements.append(
            self.add_col_row_info(
                expr,
                {
                    "field_read": {
                        "target": target,
                        "receiver_object": receiver,
                        "field": field,
                    }
                },
            )
        )
        return target

    def _emit_GetSubscript(self, expr, statements: List[Dict[str, Any]]) -> str:
        target = tmp_variable(self.counter)
        array = self.emit_expression(expr.expr, statements)
        index = self.emit_expression(expr.subscript, statements)
        self._emit_variable_decl(target, statements)
        statements.append(
            self.add_col_row_info(
                expr,
                {
                    "array_read": {
                        "target": target,
                        "array": array,
                        "index": index,
                    }
                },
            )
        )
        return target

    def _emit_GetSlice(self, expr, statements: List[Dict[str, Any]]) -> str:
        target = tmp_variable(self.counter)
        array = self.emit_expression(expr.expr, statements)
        start = self.emit_expression(expr.start, statements)
        stop = self.emit_expression(expr.stop, statements)
        step = self.emit_expression(expr.step, statements)
        self._emit_variable_decl(target, statements)
        statements.append(
            self.add_col_row_info(
                expr,
                {
                    "slice_read": {
                        "target": target,
                        "array": array,
                        "start": start,
                        "end": stop,
                        "step": step,
                    }
                },
            )
        )
        return target

    # ------------------------------------------------------------------
    # Attribute / subscript writes (statement level)
    # ------------------------------------------------------------------
    def _emit_SetAttr(self, stmt, statements: List[Dict[str, Any]]) -> None:
        receiver = self.emit_expression(stmt.expr, statements)
        field = self.emit_expression(stmt.name, statements)
        source = self.emit_expression(stmt.value, statements)
        statements.append(
            self.add_col_row_info(
                stmt,
                {
                    "field_write": {
                        "receiver_object": receiver,
                        "field": field,
                        "source": source,
                    }
                },
            )
        )

    def _emit_SetSubscript(self, stmt, statements: List[Dict[str, Any]]) -> None:
        array = self.emit_expression(stmt.expr, statements)
        index = self.emit_expression(stmt.subscript, statements)
        source = self.emit_expression(stmt.value, statements)
        statements.append(
            self.add_col_row_info(
                stmt,
                {
                    "array_write": {
                        "array": array,
                        "index": index,
                        "source": source,
                    }
                },
            )
        )

    def _emit_SetSlice(self, stmt, statements: List[Dict[str, Any]]) -> None:
        array = self.emit_expression(stmt.expr, statements)
        start = self.emit_expression(stmt.start, statements)
        stop = self.emit_expression(stmt.stop, statements)
        step = self.emit_expression(stmt.step, statements)
        source = self.emit_expression(stmt.value, statements)
        statements.append(
            self.add_col_row_info(
                stmt,
                {
                    "slice_write": {
                        "array": array,
                        "source": source,
                        "start": start,
                        "end": stop,
                        "step": step,
                    }
                },
            )
        )

    def _emit_SetGlobal(self, stmt, statements: List[Dict[str, Any]]) -> None:
        target = self._existing_value(stmt.name) or ""
        source = self.emit_expression(stmt.value, statements)
        self._emit_variable_decl(target, statements)
        statements.append(
            self.add_col_row_info(
                stmt, {"assign_stmt": {"target": target, "operand": source}}
            )
        )

    def _emit_SetCellDeref(self, stmt, statements: List[Dict[str, Any]]) -> None:
        target = stmt.cell.name
        source = self.emit_expression(stmt.value, statements)
        self._emit_variable_decl(target, statements)
        statements.append(
            self.add_col_row_info(
                stmt, {"assign_stmt": {"target": target, "operand": source}}
            )
        )

    # ------------------------------------------------------------------
    # Deletions
    # ------------------------------------------------------------------
    def _emit_Delete(self, stmt, statements: List[Dict[str, Any]]) -> None:
        name = stmt.lcl.name if isinstance(stmt.lcl, ast.Local) else ""
        statements.append(
            self.add_col_row_info(stmt, {"del_stmt": {"name": name}})
        )

    def _emit_DeleteGlobal(self, stmt, statements: List[Dict[str, Any]]) -> None:
        name = self._existing_value(stmt.name) or ""
        statements.append(
            self.add_col_row_info(stmt, {"del_stmt": {"name": name}})
        )

    def _emit_DeleteAttr(self, stmt, statements: List[Dict[str, Any]]) -> None:
        receiver = self.emit_expression(stmt.expr, statements)
        field = self.emit_expression(stmt.name, statements)
        statements.append(
            self.add_col_row_info(
                stmt,
                {
                    "field_write": {
                        "receiver_object": receiver,
                        "field": field,
                        "source": LIAN_INTERNAL.NULL,
                    }
                },
            )
        )

    def _emit_DeleteSubscript(
        self, stmt, statements: List[Dict[str, Any]]
    ) -> None:
        array = self.emit_expression(stmt.expr, statements)
        index = self.emit_expression(stmt.subscript, statements)
        statements.append(
            self.add_col_row_info(
                stmt,
                {
                    "array_write": {
                        "array": array,
                        "index": index,
                        "source": LIAN_INTERNAL.NULL,
                    }
                },
            )
        )

    def _emit_DeleteSlice(self, stmt, statements: List[Dict[str, Any]]) -> None:
        array = self.emit_expression(stmt.expr, statements)
        start = self.emit_expression(stmt.start, statements)
        stop = self.emit_expression(stmt.stop, statements)
        step = self.emit_expression(stmt.step, statements)
        statements.append(
            self.add_col_row_info(
                stmt,
                {
                    "slice_write": {
                        "array": array,
                        "source": LIAN_INTERNAL.NULL,
                        "start": start,
                        "end": stop,
                        "step": step,
                    }
                },
            )
        )

    # ------------------------------------------------------------------
    # Assignments
    # ------------------------------------------------------------------
    def _emit_Assign(self, stmt, statements: List[Dict[str, Any]]) -> None:
        expr = stmt.expr
        targets = list(getattr(stmt, "lcls", ()) or ())

        # import x as y  ->  Assign(Import(...), [Local(y)])
        if isinstance(expr, ast.Import):
            name = expr.name
            alias = (
                targets[0].name
                if targets and isinstance(targets[0], ast.Local)
                else name
            )
            statements.append(
                self.add_col_row_info(
                    stmt, {"import_stmt": {"name": name, "alias": alias}}
                )
            )
            return

        if len(targets) == 1 and isinstance(targets[0], ast.Local):
            target = targets[0].name or ""
            operator = self._binary_call_operator(expr)
            if operator is not None:
                # x = a + b  /  x += b  ->  assign_stmt {operator}
                operand = self.emit_expression(expr.args[0], statements)
                operand2 = self.emit_expression(expr.args[1], statements)
                self._emit_variable_decl(target, statements)
                statements.append(
                    self.add_col_row_info(
                        stmt,
                        {
                            "assign_stmt": {
                                "target": target,
                                "operator": operator,
                                "operand": operand,
                                "operand2": operand2,
                            }
                        },
                    )
                )
                return
            operand = self.emit_expression(expr, statements)
            self._emit_variable_decl(target, statements)
            statements.append(
                self.add_col_row_info(
                    stmt,
                    {"assign_stmt": {"target": target, "operand": operand}},
                )
            )
            return

        # Multi-target assignment: x, y = rhs
        self._emit_multi_assign(targets, expr, statements)

    def _binary_call_operator(self, expr: Any) -> Optional[str]:
        """Return the Lian operator if ``expr`` is a binary interpreter call."""
        if not isinstance(expr, ast.Call):
            return None
        if not isinstance(expr.expr, ast.Existing):
            return None
        name = self._existing_value(expr.expr)
        if name not in INTERPRETER_BINARY:
            return None
        args = list(getattr(expr, "args", ()) or ())
        if len(args) != 2:
            return None
        return INTERPRETER_BINARY[name]

    def _emit_multi_assign(
        self,
        targets: Sequence[Any],
        expr: Any,
        statements: List[Dict[str, Any]],
    ) -> None:
        shadow = tmp_variable(self.counter)
        source = self.emit_expression(expr, statements)
        self._emit_variable_decl(shadow, statements)
        statements.append(
            {"assign_stmt": {"target": shadow, "operand": source}}
        )
        for index, target in enumerate(targets):
            if not isinstance(target, ast.Local):
                continue
            array_read_tmp = tmp_variable(self.counter)
            statements.append(
                self.add_col_row_info(
                    expr,
                    {
                        "array_read": {
                            "target": array_read_tmp,
                            "array": shadow,
                            "index": str(index),
                        }
                    },
                )
            )
            self._emit_variable_decl(target.name, statements)
            statements.append(
                {
                    "assign_stmt": {
                        "target": target.name,
                        "operand": array_read_tmp,
                    }
                }
            )

    def _emit_variable_decl(
        self, name: str, statements: List[Dict[str, Any]]
    ) -> None:
        if not name:
            return
        statements.append(
            {"variable_decl": {"data_type": None, "name": name}}
        )

    # ------------------------------------------------------------------
    # Calls
    # ------------------------------------------------------------------
    def _emit_Call(self, expr, statements: List[Dict[str, Any]]) -> str:
        callee = expr.expr
        if isinstance(callee, ast.Existing):
            name = self._existing_value(callee)
            if name in INTERPRETER_BINARY:
                return self._emit_binary_op(
                    expr, INTERPRETER_BINARY[name], statements
                )
            if name in INTERPRETER_UNARY:
                return self._emit_unary_op(
                    expr, INTERPRETER_UNARY[name], statements
                )
            if name == INTERPRETER_GETITEM:
                return self._emit_getitem(expr, statements)
            if name == INTERPRETER_SETITEM:
                self._emit_setitem(expr, statements)
                return ""
            if name == INTERPRETER_DELITEM:
                self._emit_delitem(expr, statements)
                return ""
            if name == INTERPRETER_GETATTR:
                return self._emit_getattr(expr, statements)
            return self._emit_named_call(expr, name or "", statements)
        if isinstance(callee, ast.GetAttr):
            return self._emit_object_call(expr, statements)
        name = self.emit_expression(callee, statements)
        return self._emit_named_call(expr, name, statements)

    def _emit_binary_op(
        self, expr, operator: str, statements: List[Dict[str, Any]]
    ) -> str:
        target = tmp_variable(self.counter)
        operand = self.emit_expression(expr.args[0], statements)
        operand2 = self.emit_expression(expr.args[1], statements)
        self._emit_variable_decl(target, statements)
        statements.append(
            self.add_col_row_info(
                expr,
                {
                    "assign_stmt": {
                        "target": target,
                        "operator": operator,
                        "operand": operand,
                        "operand2": operand2,
                    }
                },
            )
        )
        return target

    def _emit_unary_op(
        self, expr, operator: str, statements: List[Dict[str, Any]]
    ) -> str:
        target = tmp_variable(self.counter)
        operand = self.emit_expression(expr.args[0], statements)
        self._emit_variable_decl(target, statements)
        statements.append(
            self.add_col_row_info(
                expr,
                {
                    "assign_stmt": {
                        "target": target,
                        "operator": operator,
                        "operand": operand,
                    }
                },
            )
        )
        return target

    def _emit_getitem(self, expr, statements: List[Dict[str, Any]]) -> str:
        args = list(getattr(expr, "args", ()) or ())
        array = self.emit_expression(args[0], statements) if args else ""
        index = args[1] if len(args) > 1 else None
        if isinstance(index, ast.BuildSlice):
            target = tmp_variable(self.counter)
            start = self.emit_expression(index.start, statements)
            stop = self.emit_expression(index.stop, statements)
            step = self.emit_expression(index.step, statements)
            self._emit_variable_decl(target, statements)
            statements.append(
                self.add_col_row_info(
                    expr,
                    {
                        "slice_read": {
                            "target": target,
                            "array": array,
                            "start": start,
                            "end": stop,
                            "step": step,
                        }
                    },
                )
            )
            return target
        target = tmp_variable(self.counter)
        index_name = self.emit_expression(index, statements) if index else ""
        self._emit_variable_decl(target, statements)
        statements.append(
            self.add_col_row_info(
                expr,
                {
                    "array_read": {
                        "target": target,
                        "array": array,
                        "index": index_name,
                    }
                },
            )
        )
        return target

    def _emit_setitem(self, expr, statements: List[Dict[str, Any]]) -> None:
        args = list(getattr(expr, "args", ()) or ())
        array = self.emit_expression(args[0], statements) if args else ""
        index = args[1] if len(args) > 1 else None
        source = self.emit_expression(args[2], statements) if len(args) > 2 else ""
        if isinstance(index, ast.BuildSlice):
            start = self.emit_expression(index.start, statements)
            stop = self.emit_expression(index.stop, statements)
            step = self.emit_expression(index.step, statements)
            statements.append(
                self.add_col_row_info(
                    expr,
                    {
                        "slice_write": {
                            "array": array,
                            "source": source,
                            "start": start,
                            "end": stop,
                            "step": step,
                        }
                    },
                )
            )
            return
        index_name = self.emit_expression(index, statements) if index else ""
        statements.append(
            self.add_col_row_info(
                expr,
                {
                    "array_write": {
                        "array": array,
                        "index": index_name,
                        "source": source,
                    }
                },
            )
        )

    def _emit_delitem(self, expr, statements: List[Dict[str, Any]]) -> None:
        args = list(getattr(expr, "args", ()) or ())
        array = self.emit_expression(args[0], statements) if args else ""
        index = args[1] if len(args) > 1 else None
        index_name = self.emit_expression(index, statements) if index else ""
        statements.append(
            self.add_col_row_info(
                expr,
                {
                    "array_write": {
                        "array": array,
                        "index": index_name,
                        "source": LIAN_INTERNAL.NULL,
                    }
                },
            )
        )

    def _emit_getattr(self, expr, statements: List[Dict[str, Any]]) -> str:
        args = list(getattr(expr, "args", ()) or ())
        target = tmp_variable(self.counter)
        receiver = self.emit_expression(args[0], statements) if args else ""
        field = self.emit_expression(args[1], statements) if len(args) > 1 else ""
        self._emit_variable_decl(target, statements)
        statements.append(
            self.add_col_row_info(
                expr,
                {
                    "field_read": {
                        "target": target,
                        "receiver_object": receiver,
                        "field": field,
                    }
                },
            )
        )
        return target

    def _emit_named_call(
        self, expr, name: str, statements: List[Dict[str, Any]]
    ) -> str:
        target = tmp_variable(self.counter)
        positional, named, packed_positional, packed_named = (
            self._emit_arguments(expr, statements)
        )
        gir: Dict[str, Any] = {"call_stmt": {"target": target, "name": name}}
        if positional:
            gir["call_stmt"]["positional_args"] = positional
        if named:
            gir["call_stmt"]["named_args"] = str(named)
        if packed_positional is not None:
            gir["call_stmt"]["packed_positional_args"] = packed_positional
        if packed_named is not None:
            gir["call_stmt"]["packed_named_args"] = packed_named
        self._emit_variable_decl(target, statements)
        statements.append(self.add_col_row_info(expr, gir))
        return target

    def _emit_object_call(self, expr, statements: List[Dict[str, Any]]) -> str:
        target = tmp_variable(self.counter)
        receiver = self.emit_expression(expr.expr.expr, statements)
        field = self.emit_expression(expr.expr.name, statements)
        positional, named, packed_positional, packed_named = (
            self._emit_arguments(expr, statements)
        )
        gir: Dict[str, Any] = {
            "object_call_stmt": {
                "target": target,
                "field": field,
                "receiver_object": receiver,
            }
        }
        if positional:
            gir["object_call_stmt"]["positional_args"] = positional
        if named:
            gir["object_call_stmt"]["named_args"] = str(named)
        if packed_positional is not None:
            gir["object_call_stmt"]["packed_positional_args"] = packed_positional
        if packed_named is not None:
            gir["object_call_stmt"]["packed_named_args"] = packed_named
        self._emit_variable_decl(target, statements)
        statements.append(self.add_col_row_info(expr, gir))
        return target

    def _emit_MethodCall(self, expr, statements: List[Dict[str, Any]]) -> str:
        target = tmp_variable(self.counter)
        receiver = self.emit_expression(expr.expr, statements)
        field = self.emit_expression(expr.name, statements)
        positional, named, packed_positional, packed_named = (
            self._emit_arguments(expr, statements)
        )
        gir: Dict[str, Any] = {
            "object_call_stmt": {
                "target": target,
                "field": field,
                "receiver_object": receiver,
            }
        }
        if positional:
            gir["object_call_stmt"]["positional_args"] = positional
        if named:
            gir["object_call_stmt"]["named_args"] = str(named)
        if packed_positional is not None:
            gir["object_call_stmt"]["packed_positional_args"] = packed_positional
        if packed_named is not None:
            gir["object_call_stmt"]["packed_named_args"] = packed_named
        self._emit_variable_decl(target, statements)
        statements.append(self.add_col_row_info(expr, gir))
        return target

    def _emit_DirectCall(self, expr, statements: List[Dict[str, Any]]) -> str:
        target = tmp_variable(self.counter)
        code = expr.code
        name = code.codeName() if code is not None else ""
        positional: List[str] = []
        named: Dict[str, str] = {}
        if expr.selfarg is not None:
            positional.append(self.emit_expression(expr.selfarg, statements))
        for arg in getattr(expr, "args", ()) or ():
            positional.append(self.emit_expression(arg, statements))
        for key, value in getattr(expr, "kwds", ()) or ():
            named[str(key)] = self.emit_expression(value, statements)
        gir: Dict[str, Any] = {"call_stmt": {"target": target, "name": name}}
        if positional:
            gir["call_stmt"]["positional_args"] = positional
        if named:
            gir["call_stmt"]["named_args"] = str(named)
        self._emit_variable_decl(target, statements)
        statements.append(self.add_col_row_info(expr, gir))
        return target

    def _emit_arguments(
        self, expr, statements: List[Dict[str, Any]]
    ) -> Tuple[List[str], Dict[str, str], Optional[str], Optional[str]]:
        positional: List[str] = []
        named: Dict[str, str] = {}
        packed_positional: Optional[str] = None
        packed_named: Optional[str] = None
        positional_items = call_positional_items(expr)
        if positional_items and any(is_spread for is_spread, _ in positional_items):
            packed_positional = tmp_variable(self.counter)
            statements.append({"new_array": {"target": packed_positional}})
            met_spread = False
            plain_index = 0
            for is_spread, arg in positional_items:
                value = self.emit_expression(arg, statements)
                if is_spread:
                    met_spread = True
                    statements.append(
                        {"array_extend": {"array": packed_positional, "source": value}}
                    )
                elif met_spread:
                    statements.append(
                        {"array_append": {"array": packed_positional, "source": value}}
                    )
                else:
                    statements.append(
                        {
                            "array_write": {
                                "array": packed_positional,
                                "index": str(plain_index),
                                "source": value,
                            }
                        }
                    )
                    plain_index += 1
        else:
            for arg in getattr(expr, "args", ()) or ():
                positional.append(self.emit_expression(arg, statements))
        for key, value in getattr(expr, "kwds", ()) or ():
            named[str(key)] = self.emit_expression(value, statements)
        keyword_spreads = call_keyword_spreads(expr)
        if keyword_spreads or getattr(expr, "kargs", None) is not None:
            packed_named = tmp_variable(self.counter)
            statements.append({"new_record": {"target": packed_named}})
            spreads = keyword_spreads or (expr.kargs,)
            for spread in spreads:
                value = self.emit_expression(spread, statements)
                statements.append(
                    {"record_extend": {"record": packed_named, "source": value}}
                )
            for key, value in named.items():
                statements.append(
                    {
                        "record_write": {
                            "receiver_record": packed_named,
                            "key": key,
                            "value": value,
                        }
                    }
                )
            named = {}
        return positional, named, packed_positional, packed_named

    # ------------------------------------------------------------------
    # Binary / unary / comparison expressions (native AST nodes)
    # ------------------------------------------------------------------
    def _emit_BinaryOp(self, expr, statements: List[Dict[str, Any]]) -> str:
        target = tmp_variable(self.counter)
        operand = self.emit_expression(expr.left, statements)
        operand2 = self.emit_expression(expr.right, statements)
        self._emit_variable_decl(target, statements)
        statements.append(
            self.add_col_row_info(
                expr,
                {
                    "assign_stmt": {
                        "target": target,
                        "operator": expr.op,
                        "operand": operand,
                        "operand2": operand2,
                    }
                },
            )
        )
        return target

    def _emit_UnaryPrefixOp(self, expr, statements: List[Dict[str, Any]]) -> str:
        target = tmp_variable(self.counter)
        operand = self.emit_expression(expr.expr, statements)
        self._emit_variable_decl(target, statements)
        statements.append(
            self.add_col_row_info(
                expr,
                {
                    "assign_stmt": {
                        "target": target,
                        "operator": expr.op,
                        "operand": operand,
                    }
                },
            )
        )
        return target

    def _emit_Not(self, expr, statements: List[Dict[str, Any]]) -> str:
        target = tmp_variable(self.counter)
        operand = self.emit_expression(expr.expr, statements)
        self._emit_variable_decl(target, statements)
        statements.append(
            self.add_col_row_info(
                expr,
                {
                    "assign_stmt": {
                        "target": target,
                        "operator": "not",
                        "operand": operand,
                    }
                },
            )
        )
        return target

    def _emit_Is(self, expr, statements: List[Dict[str, Any]]) -> str:
        target = tmp_variable(self.counter)
        operand = self.emit_expression(expr.left, statements)
        operand2 = self.emit_expression(expr.right, statements)
        self._emit_variable_decl(target, statements)
        statements.append(
            self.add_col_row_info(
                expr,
                {
                    "assign_stmt": {
                        "target": target,
                        "operator": "is",
                        "operand": operand,
                        "operand2": operand2,
                    }
                },
            )
        )
        return target

    def _emit_ConvertToBool(self, expr, statements: List[Dict[str, Any]]) -> str:
        # Truthiness conversion is implicit in Lian; unwrap the operand.
        return self.emit_expression(expr.expr, statements)

    def _emit_ShortCircutAnd(self, expr, statements: List[Dict[str, Any]]) -> str:
        terms = list(getattr(expr, "terms", ()) or ())
        if not terms:
            return ""
        if len(terms) == 1:
            return self.emit_expression(terms[0], statements)
        target = tmp_variable(self.counter)
        operand = self.emit_expression(terms[0], statements)
        self._emit_variable_decl(target, statements)
        statements.append(
            {"assign_stmt": {"target": target, "operand": operand}}
        )
        for term in terms[1:]:
            operand2 = self.emit_expression(term, statements)
            statements.append(
                {
                    "assign_stmt": {
                        "target": target,
                        "operator": "and",
                        "operand": target,
                        "operand2": operand2,
                    }
                }
            )
        return target

    def _emit_ShortCircutOr(self, expr, statements: List[Dict[str, Any]]) -> str:
        terms = list(getattr(expr, "terms", ()) or ())
        if not terms:
            return ""
        if len(terms) == 1:
            return self.emit_expression(terms[0], statements)
        target = tmp_variable(self.counter)
        operand = self.emit_expression(terms[0], statements)
        self._emit_variable_decl(target, statements)
        statements.append(
            {"assign_stmt": {"target": target, "operand": operand}}
        )
        for term in terms[1:]:
            operand2 = self.emit_expression(term, statements)
            statements.append(
                {
                    "assign_stmt": {
                        "target": target,
                        "operator": "or",
                        "operand": target,
                        "operand2": operand2,
                    }
                }
            )
        return target

    def _emit_NamedExpr(self, expr, statements: List[Dict[str, Any]]) -> str:
        target = expr.target.name if isinstance(expr.target, ast.Local) else ""
        value = self.emit_expression(expr.value, statements)
        self._emit_variable_decl(target, statements)
        statements.append(
            self.add_col_row_info(
                expr, {"assign_stmt": {"target": target, "operand": value}}
            )
        )
        return target

    def _emit_ConditionalExpr(self, expr, statements: List[Dict[str, Any]]) -> str:
        target = tmp_variable(self.counter)
        condition = self.emit_expression(expr.test, statements)
        then_body: List[Dict[str, Any]] = []
        then_value = self.emit_expression(expr.body, then_body)
        then_body.append({"assign_stmt": {"target": target, "operand": then_value}})
        else_body: List[Dict[str, Any]] = []
        else_value = self.emit_expression(expr.orelse, else_body)
        else_body.append({"assign_stmt": {"target": target, "operand": else_value}})
        self._emit_variable_decl(target, statements)
        statements.append(
            self.add_col_row_info(
                expr,
                {
                    "if_stmt": {
                        "condition": condition,
                        "then_body": then_body,
                        "else_body": else_body,
                    }
                },
            )
        )
        return target

    # ------------------------------------------------------------------
    # Collections
    # ------------------------------------------------------------------
    def _emit_BuildList(self, expr, statements: List[Dict[str, Any]]) -> str:
        target = tmp_variable(self.counter)
        self._emit_variable_decl(target, statements)
        statements.append(
            self.add_col_row_info(
                expr, {"new_array": {"target": target, "attrs": []}}
            )
        )
        for index, value in enumerate(getattr(expr, "args", ()) or ()):
            source = self.emit_expression(value, statements)
            statements.append(
                self.add_col_row_info(
                    value,
                    {
                        "array_write": {
                            "array": target,
                            "index": str(index),
                            "source": source,
                        }
                    },
                )
            )
        return target

    def _emit_BuildTuple(self, expr, statements: List[Dict[str, Any]]) -> str:
        target = tmp_variable(self.counter)
        self._emit_variable_decl(target, statements)
        statements.append(
            self.add_col_row_info(
                expr,
                {"new_array": {"target": target, "attrs": ["tuple"]}},
            )
        )
        for index, value in enumerate(getattr(expr, "args", ()) or ()):
            source = self.emit_expression(value, statements)
            statements.append(
                self.add_col_row_info(
                    value,
                    {
                        "array_write": {
                            "array": target,
                            "index": str(index),
                            "source": source,
                        }
                    },
                )
            )
        return target

    def _emit_BuildSet(self, expr, statements: List[Dict[str, Any]]) -> str:
        target = tmp_variable(self.counter)
        self._emit_variable_decl(target, statements)
        statements.append(
            self.add_col_row_info(
                expr, {"new_array": {"target": target, "attrs": ["set"]}}
            )
        )
        for index, value in enumerate(getattr(expr, "args", ()) or ()):
            source = self.emit_expression(value, statements)
            statements.append(
                self.add_col_row_info(
                    value,
                    {
                        "array_write": {
                            "array": target,
                            "index": str(index),
                            "source": source,
                        }
                    },
                )
            )
        return target

    def _emit_BuildMap(self, expr, statements: List[Dict[str, Any]]) -> str:
        target = tmp_variable(self.counter)
        self._emit_variable_decl(target, statements)
        statements.append(
            self.add_col_row_info(
                expr, {"new_record": {"target": target, "attrs": []}}
            )
        )
        args = list(getattr(expr, "args", ()) or ())
        # BuildMap stores key/value pairs flat: key at even index, value at odd.
        for index in range(0, len(args) - 1, 2):
            key = args[index]
            value = args[index + 1]
            if key is None:
                source = self.emit_expression(value, statements)
                statements.append(
                    self.add_col_row_info(
                        value,
                        {"record_extend": {"record": target, "source": source}},
                    )
                )
            else:
                key_name = self.emit_expression(key, statements)
                source = self.emit_expression(value, statements)
                statements.append(
                    self.add_col_row_info(
                        key,
                        {
                            "record_write": {
                                "receiver_record": target,
                                "key": key_name,
                                "value": source,
                            }
                        },
                    )
                )
        return target

    def _emit_BuildSlice(self, expr, statements: List[Dict[str, Any]]) -> str:
        # BuildSlice is handled inline by getitem/setitem; standalone slices
        # are not emitted as separate rows.
        return ""

    # ------------------------------------------------------------------
    # Yield / await
    # ------------------------------------------------------------------
    def _emit_Yield(self, expr, statements: List[Dict[str, Any]]) -> str:
        value = self.emit_expression(expr.expr, statements)
        statements.append(
            self.add_col_row_info(
                expr, {"yield_stmt": {"target": value}}
            )
        )
        return ""

    def _emit_YieldFrom(self, expr, statements: List[Dict[str, Any]]) -> str:
        return self._emit_Yield(expr, statements)

    def _emit_AsyncYield(self, expr, statements: List[Dict[str, Any]]) -> str:
        return self._emit_Yield(expr, statements)

    def _emit_Await(self, expr, statements: List[Dict[str, Any]]) -> str:
        value = self.emit_expression(expr.expr, statements)
        statements.append(
            self.add_col_row_info(
                expr, {"await_stmt": {"target": value}}
            )
        )
        return value

    # ------------------------------------------------------------------
    # Control-flow statements
    # ------------------------------------------------------------------
    def _emit_Return(self, stmt, statements: List[Dict[str, Any]]) -> None:
        exprs = list(getattr(stmt, "exprs", ()) or ())
        name = self.emit_expression(exprs[0], statements) if exprs else ""
        statements.append(
            self.add_col_row_info(
                stmt, {"return_stmt": {"name": name}}
            )
        )

    def _emit_Raise(self, stmt, statements: List[Dict[str, Any]]) -> None:
        exc = getattr(stmt, "exception", None) or getattr(
            stmt, "parameter", None
        )
        name = self.emit_expression(exc, statements)
        statements.append(
            self.add_col_row_info(
                stmt, {"throw_stmt": {"name": name}}
            )
        )

    def _emit_Assert(self, stmt, statements: List[Dict[str, Any]]) -> None:
        test = self.emit_expression(stmt.test, statements)
        statements.append(
            self.add_col_row_info(
                stmt, {"assert_stmt": {"condition": test}}
            )
        )

    def _emit_Break(self, stmt, statements: List[Dict[str, Any]]) -> None:
        statements.append(
            self.add_col_row_info(stmt, {"break_stmt": {"name": ""}})
        )

    def _emit_Continue(self, stmt, statements: List[Dict[str, Any]]) -> None:
        statements.append(
            self.add_col_row_info(stmt, {"continue_stmt": {"name": ""}})
        )

    def _emit_Pass(self, stmt, statements: List[Dict[str, Any]]) -> None:
        statements.append(self.add_col_row_info(stmt, {"pass_stmt": {}}))

    def _emit_GlobalDecl(self, stmt, statements: List[Dict[str, Any]]) -> None:
        name = stmt.name.name if isinstance(stmt.name, ast.Local) else ""
        statements.append(
            self.add_col_row_info(stmt, {"global_stmt": {"name": name}})
        )

    def _emit_NonlocalDecl(self, stmt, statements: List[Dict[str, Any]]) -> None:
        name = stmt.name.name if isinstance(stmt.name, ast.Local) else ""
        statements.append(
            self.add_col_row_info(stmt, {"nonlocal_stmt": {"name": name}})
        )

    def _emit_TypeAlias(self, stmt, statements: List[Dict[str, Any]]) -> None:
        data_type = self.emit_expression(stmt.value, statements)
        statements.append(
            self.add_col_row_info(
                stmt,
                {
                    "type_alias_decl": {
                        "name": stmt.name,
                        "data_type": data_type,
                    }
                },
            )
        )

    def _emit_AnnAssign(self, stmt, statements: List[Dict[str, Any]]) -> None:
        if stmt.value is None:
            return
        target = stmt.target
        if isinstance(target, ast.Local):
            operand = self.emit_expression(stmt.value, statements)
            self._emit_variable_decl(target.name, statements)
            statements.append(
                self.add_col_row_info(
                    stmt,
                    {"assign_stmt": {"target": target.name, "operand": operand}},
                )
            )
        else:
            self._emit_store_to(target, stmt.value, statements)

    def _emit_store_to(
        self, target: Any, value: Any, statements: List[Dict[str, Any]]
    ) -> None:
        if isinstance(target, ast.GetAttr):
            receiver = self.emit_expression(target.expr, statements)
            field = self.emit_expression(target.name, statements)
            source = self.emit_expression(value, statements)
            statements.append(
                {
                    "field_write": {
                        "receiver_object": receiver,
                        "field": field,
                        "source": source,
                    }
                }
            )
        elif isinstance(target, ast.GetSubscript):
            array = self.emit_expression(target.expr, statements)
            index = self.emit_expression(target.subscript, statements)
            source = self.emit_expression(value, statements)
            statements.append(
                {
                    "array_write": {
                        "array": array,
                        "index": index,
                        "source": source,
                    }
                }
            )

    # ------------------------------------------------------------------
    # Switch / if
    # ------------------------------------------------------------------
    def _emit_Switch(self, stmt, statements: List[Dict[str, Any]]) -> None:
        condition = self.emit_expression(stmt.condition.conditional, statements)
        then_body: List[Dict[str, Any]] = []
        for block in stmt.t.blocks:
            self.emit_statement(block, then_body)
        else_body: List[Dict[str, Any]] = []
        for block in stmt.f.blocks:
            self.emit_statement(block, else_body)
        statements.append(
            self.add_col_row_info(
                stmt,
                {
                    "if_stmt": {
                        "condition": condition,
                        "then_body": then_body,
                        "else_body": else_body,
                    }
                },
            )
        )

    def _emit_TypeSwitch(self, stmt, statements: List[Dict[str, Any]]) -> None:
        condition = self.emit_expression(stmt.conditional, statements)
        case_rows: List[Dict[str, Any]] = []
        for case in getattr(stmt, "cases", ()) or ():
            case_body: List[Dict[str, Any]] = []
            for block in case.body.blocks:
                self.emit_statement(block, case_body)
            types = list(getattr(case, "types", ()) or ())
            if types:
                type_value = self._existing_value(types[0]) or ""
                case_rows.append(
                    {
                        "case_stmt": {
                            "condition": type_value,
                            "body": case_body,
                        }
                    }
                )
            else:
                case_rows.append({"default_stmt": {"body": case_body}})
        statements.append(
            self.add_col_row_info(
                stmt,
                {"switch_stmt": {"condition": condition, "body": case_rows}},
            )
        )

    # ------------------------------------------------------------------
    # Loops
    # ------------------------------------------------------------------
    def _emit_For(self, stmt, statements: List[Dict[str, Any]]) -> None:
        index_name = (
            stmt.index.name if isinstance(stmt.index, ast.Local) else ""
        )
        for block in stmt.loopPreamble.blocks:
            self.emit_statement(block, statements)
        if index_name:
            self._emit_variable_decl(index_name, statements)
        receiver = self.emit_expression(stmt.iterator, statements)
        body: List[Dict[str, Any]] = []
        for block in stmt.bodyPreamble.blocks:
            self.emit_statement(block, body)
        for block in stmt.body.blocks:
            self.emit_statement(block, body)
        statements.append(
            self.add_col_row_info(
                stmt,
                {
                    "forin_stmt": {
                        "attrs": [],
                        "name": index_name,
                        "receiver": receiver,
                        "body": body,
                    }
                },
            )
        )

    def _emit_While(self, stmt, statements: List[Dict[str, Any]]) -> None:
        condition = self.emit_expression(stmt.condition.conditional, statements)
        body: List[Dict[str, Any]] = []
        for block in stmt.body.blocks:
            self.emit_statement(block, body)
        else_body: List[Dict[str, Any]] = []
        for block in stmt.else_.blocks:
            self.emit_statement(block, else_body)
        statements.append(
            self.add_col_row_info(
                stmt,
                {
                    "while_stmt": {
                        "condition": condition,
                        "body": body,
                        "else_body": else_body,
                    }
                },
            )
        )

    # ------------------------------------------------------------------
    # Try
    # ------------------------------------------------------------------
    def _emit_TryExceptFinally(
        self, stmt, statements: List[Dict[str, Any]]
    ) -> None:
        try_body: List[Dict[str, Any]] = []
        for block in stmt.body.blocks:
            self.emit_statement(block, try_body)
        catch_rows: List[Dict[str, Any]] = []
        for handler in getattr(stmt, "handlers", ()) or ():
            handler_type = ""
            if handler.type is not None:
                handler_type = self.emit_expression(handler.type, statements)
            handler_name = ""
            if handler.value is not None:
                handler_name = self.emit_expression(handler.value, statements)
            handler_body: List[Dict[str, Any]] = []
            for block in handler.body.blocks:
                self.emit_statement(block, handler_body)
            catch_clause: Dict[str, Any] = {
                "catch_clause": {"body": handler_body}
            }
            if handler_type:
                catch_clause["catch_clause"]["expcetion"] = handler_type
            if handler_name:
                catch_clause["catch_clause"]["as"] = handler_name
            catch_rows.append(catch_clause)
        if getattr(stmt, "defaultHandler", None) is not None:
            default_body: List[Dict[str, Any]] = []
            for block in stmt.defaultHandler.blocks:
                self.emit_statement(block, default_body)
            catch_rows.append(
                {"catch_clause": {"body": default_body}}
            )
        else_body: List[Dict[str, Any]] = []
        if getattr(stmt, "else_", None) is not None:
            for block in stmt.else_.blocks:
                self.emit_statement(block, else_body)
        final_body: List[Dict[str, Any]] = []
        if getattr(stmt, "finally_", None) is not None:
            for block in stmt.finally_.blocks:
                self.emit_statement(block, final_body)
        gir: Dict[str, Any] = {
            "try_stmt": {
                "name": "",
                "try_body": try_body,
                "catch_body": catch_rows,
                "else_body": else_body,
                "final_body": final_body,
            }
        }
        statements.append(self.add_col_row_info(stmt, gir))

    # ------------------------------------------------------------------
    # Functions / classes
    # ------------------------------------------------------------------
    def _emit_FunctionDef(self, stmt, statements: List[Dict[str, Any]]) -> None:
        preamble: List[Dict[str, Any]] = []
        method = self._function_decl_dict(stmt, preamble)
        statements.extend(preamble)
        statements.append(method)

    def _function_decl_dict(
        self,
        stmt,
        preamble_out: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        source = gir_source_node(stmt)
        source_function = source if isinstance(
            source, (python_ast.FunctionDef, python_ast.AsyncFunctionDef)
        ) else None
        if source_function is not None:
            modifiers = [
                python_ast.unparse(
                    decorator.func
                    if isinstance(decorator, python_ast.Call)
                    else decorator
                )
                for decorator in source_function.decorator_list
            ]
        else:
            modifiers = self._function_modifiers(stmt)
        if isinstance(source_function, python_ast.AsyncFunctionDef):
            modifiers.append("async")
        parameters, preamble = self._code_parameters(stmt.code, source_function)
        body: List[Dict[str, Any]] = []
        for block in stmt.code.ast.blocks:
            self.emit_statement(block, body)
        method_decl: Dict[str, Any] = {
            "method_decl": {
                "attrs": modifiers,
                "data_type": (
                    python_ast.unparse(source_function.returns)
                    if source_function is not None
                    and source_function.returns is not None
                    else None
                ),
                "name": stmt.name,
                "parameters": parameters,
                "body": body,
            }
        }
        row = self._row_of(stmt)
        if source_function is not None:
            location_node: python_ast.AST = source_function
            if source_function.decorator_list:
                location_node = source_function.decorator_list[0]
            row = max(0, int(getattr(location_node, "lineno", 1)) - 1)
        method_decl["method_decl"]["decorators"] = row if row is not None else 0
        result = self.add_col_row_info(stmt, method_decl)
        # Lian evaluates non-literal defaults before the method declaration.
        if preamble and preamble_out is not None:
            preamble_out.extend(preamble)
        return result

    def _function_modifiers(self, stmt) -> List[str]:
        modifiers: List[str] = []
        for decorator in getattr(stmt, "decorators", ()) or ():
            name = ""
            if isinstance(decorator, ast.Local):
                name = decorator.name
            elif isinstance(decorator, ast.GetAttr):
                name = self.emit_expression(decorator.name, [])
            else:
                name = self.emit_expression(decorator, [])
            if name:
                modifiers.append(name)
        return modifiers

    def _code_parameters(
        self,
        code: "Optional[ast.Code]",
        source_function: Optional[
            python_ast.FunctionDef | python_ast.AsyncFunctionDef
        ] = None,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Build ``parameter_decl`` rows plus a preamble for default values."""
        parameters: List[Dict[str, Any]] = []
        preamble: List[Dict[str, Any]] = []
        if code is None:
            return parameters, preamble
        cp = code.codeparameters
        self._warn_unrepresented_type_params(
            getattr(cp, "type_params", None), "function"
        )
        posonly = list(getattr(cp, "posonlyparams", ()) or ())
        params = list(getattr(cp, "params", ()) or ())
        paramnames = list(getattr(cp, "paramnames", ()) or ())
        defaults = list(getattr(cp, "defaults", ()) or ())
        all_params = posonly + params
        source_args: Dict[str, python_ast.arg] = {}
        source_defaults: Dict[str, Optional[python_ast.expr]] = {}
        if source_function is not None:
            positional_source_args = [
                *source_function.args.posonlyargs,
                *source_function.args.args,
            ]
            for argument in (
                *positional_source_args,
                *source_function.args.kwonlyargs,
            ):
                source_args[argument.arg] = argument
            default_offset = len(positional_source_args) - len(
                source_function.args.defaults
            )
            for index, argument in enumerate(positional_source_args):
                source_defaults[argument.arg] = (
                    source_function.args.defaults[index - default_offset]
                    if index >= default_offset
                    else None
                )
            for argument, default in zip(
                source_function.args.kwonlyargs,
                source_function.args.kw_defaults,
            ):
                source_defaults[argument.arg] = default
            if source_function.args.vararg is not None:
                source_args[source_function.args.vararg.arg] = (
                    source_function.args.vararg
                )
            if source_function.args.kwarg is not None:
                source_args[source_function.args.kwarg.arg] = (
                    source_function.args.kwarg
                )
        default_offset = len(all_params) - len(defaults)
        for index, param in enumerate(all_params):
            name = param.name if isinstance(param, ast.Local) else ""
            attrs: List[str] = []
            if index < len(posonly):
                attrs = [LIAN_INTERNAL.POSITIONAL_ONLY_PARAMETER]
            else:
                paramname_index = index - len(posonly)
                if (
                    paramname_index < len(paramnames)
                    and paramnames[paramname_index]
                    and paramnames[paramname_index].startswith(KWONLY_PARAM_PREFIX)
                ):
                    attrs = [LIAN_INTERNAL.KEYWORLD_ONLY_PARAMETER]
            default_value: Optional[str] = None
            source_default = source_defaults.get(name)
            if source_default is not None:
                if isinstance(source_default, python_ast.Constant):
                    default_value = self._python_literal(source_default)
                else:
                    default_value = default_value_variable(self.counter)
                    preamble.append(
                        {"variable_decl": {"name": default_value}}
                    )
                    source_value = self._emit_python_expression(
                        source_default, preamble
                    )
                    preamble.append(
                        {
                            "assign_stmt": {
                                "target": default_value,
                                "operand": source_value,
                            }
                        }
                    )
            elif source_function is None and defaults and index >= default_offset:
                default_expr = defaults[index - default_offset]
                if not self._is_missing_default(default_expr):
                    default_value = self.emit_expression(default_expr, preamble)
            parameter = {
                "parameter_decl": {
                        "data_type": (
                            python_ast.unparse(source_args[name].annotation)
                            if name in source_args
                            and source_args[name].annotation is not None
                            else None
                        ),
                        "name": name,
                        "attrs": attrs,
                        "default_value": default_value,
                    }
            }
            if name in source_args:
                parameter = self._add_python_col_row_info(
                    source_args[name], parameter
                )
            parameters.append(parameter)
        if getattr(cp, "vparam", None) is not None:
            name = cp.vparam.name if isinstance(cp.vparam, ast.Local) else ""
            parameter = {
                "parameter_decl": {
                        "data_type": (
                            python_ast.unparse(source_args[name].annotation)
                            if name in source_args
                            and source_args[name].annotation is not None
                            else None
                        ),
                        "name": name,
                        "attrs": [LIAN_INTERNAL.PACKED_POSITIONAL_PARAMETER],
                        "default_value": None,
                    }
            }
            if name in source_args:
                parameter = self._add_python_col_row_info(
                    source_args[name], parameter
                )
            parameters.append(parameter)
        if getattr(cp, "kparam", None) is not None:
            name = cp.kparam.name if isinstance(cp.kparam, ast.Local) else ""
            parameter = {
                "parameter_decl": {
                        "data_type": (
                            python_ast.unparse(source_args[name].annotation)
                            if name in source_args
                            and source_args[name].annotation is not None
                            else None
                        ),
                        "name": name,
                        "attrs": [LIAN_INTERNAL.PACKED_NAMED_PARAMETER],
                        "default_value": None,
                    }
            }
            if name in source_args:
                parameter = self._add_python_col_row_info(
                    source_args[name], parameter
                )
            parameters.append(parameter)
        return parameters, preamble

    @staticmethod
    def _warn_unrepresented_type_params(type_params: Any, owner: str) -> None:
        if type_params is None or not getattr(type_params, "params", ()):
            return
        warnings.warn(
            f"PEP 695 {owner} type parameters are not represented by "
            "upstream Lian GIR and were omitted",
            GirCompatibilityWarning,
            stacklevel=3,
        )

    @staticmethod
    def _is_missing_default(expr: Any) -> bool:
        pyobj = getattr(getattr(expr, "object", None), "pyobj", None)
        return type(pyobj).__name__ == "_MissingDefault"

    def _emit_ClassDef(self, stmt, statements: List[Dict[str, Any]]) -> None:
        preamble: List[Dict[str, Any]] = []
        class_decl = self._class_decl_dict(stmt, preamble)
        statements.extend(preamble)
        statements.append(class_decl)

    def _class_decl_dict(
        self,
        stmt,
        preamble_out: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        source = gir_source_node(stmt)
        source_class = source if isinstance(source, python_ast.ClassDef) else None
        supers: List[str] = []
        if source_class is not None:
            for base in source_class.bases:
                if isinstance(base, python_ast.Subscript):
                    supers.append(python_ast.unparse(base))
                else:
                    supers.append(self._emit_python_expression(base, []))
        else:
            for base in getattr(stmt, "bases", ()) or ():
                supers.append(self.emit_expression(base, []))
        methods: List[Dict[str, Any]] = []
        fields: List[Dict[str, Any]] = []
        nested: List[Dict[str, Any]] = []
        static_init: List[Dict[str, Any]] = []
        for block in getattr(stmt.body, "blocks", ()) or ():
            if isinstance(block, ast.FunctionDef):
                method_preamble: List[Dict[str, Any]] = []
                methods.append(self._function_decl_dict(block, method_preamble))
                if preamble_out is not None:
                    preamble_out.extend(method_preamble)
            elif isinstance(block, ast.ClassDef):
                nested.append(self._class_decl_dict(block, preamble_out))
            elif isinstance(block, ast.AnnAssign):
                source_node = gir_source_node(block)
                target = block.target
                if isinstance(target, ast.Local):
                    field_decl: Dict[str, Any] = {
                        "variable_decl": {
                            "data_type": (
                                python_ast.unparse(source_node.annotation)
                                if isinstance(source_node, python_ast.AnnAssign)
                                else None
                            ),
                            "name": target.name,
                        }
                    }
                    if isinstance(source_node, python_ast.AnnAssign):
                        field_decl = self._add_python_col_row_info(
                            source_node, field_decl
                        )
                    fields.append(field_decl)
                    if block.value is not None:
                        value = self.emit_expression(block.value, static_init)
                        field_write: Dict[str, Any] = {
                            "field_write": {
                                "receiver_object": LIAN_INTERNAL.CLASS,
                                "field": target.name,
                                "source": value,
                            }
                        }
                        if isinstance(source_node, python_ast.AnnAssign):
                            field_write = self._add_python_col_row_info(
                                source_node, field_write
                            )
                        static_init.append(field_write)
            elif isinstance(block, ast.Assign) and getattr(block, "lcls", None):
                source_node = gir_source_node(block)
                for target in block.lcls:
                    if isinstance(target, ast.Local):
                        field_decl = {
                            "variable_decl": {
                                "data_type": None,
                                "name": target.name,
                            }
                        }
                        if isinstance(source_node, python_ast.Assign):
                            field_decl = self._add_python_col_row_info(
                                source_node, field_decl
                            )
                        fields.append(field_decl)
                        source = self.emit_expression(block.expr, static_init)
                        field_write = {
                            "field_write": {
                                "receiver_object": LIAN_INTERNAL.CLASS,
                                "field": target.name,
                                "source": source,
                            }
                        }
                        if isinstance(source_node, python_ast.Assign):
                            field_write = self._add_python_col_row_info(
                                source_node, field_write
                            )
                        static_init.append(field_write)
            elif isinstance(block, ast.Discard):
                # Lian's class parser keeps only declarations and assignments
                # from non-definition class-body statements.
                continue
            else:
                source_node = gir_source_node(block)
                if not isinstance(source_node, python_ast.Pass):
                    self.emit_statement(block, static_init)
        gir: Dict[str, Any] = {
            "class_decl": {
                "attrs": [],
                "methods": methods,
                "fields": fields,
                "supers": supers,
                "nested": nested,
                "name": stmt.name,
            }
        }
        if source_class is not None and getattr(source_class, "type_params", None):
            gir["class_decl"]["type_parameters"] = ", ".join(
                python_ast.unparse(parameter)
                for parameter in source_class.type_params
            )
        if static_init:
            methods.insert(
                0,
                {
                    "method_decl": {
                        "name": LIAN_INTERNAL.CLASS_STATIC_INIT,
                        "body": static_init,
                    }
                }
            )
        return self.add_col_row_info(stmt, gir)

    def _emit_MakeFunction(self, expr, statements: List[Dict[str, Any]]) -> str:
        code = expr.code
        if code is None:
            return ""
        method_name = tmp_method(self.counter)
        parameters, preamble = self._code_parameters(code)
        body: List[Dict[str, Any]] = []
        for block in code.ast.blocks:
            self.emit_statement(block, body)
        statements.extend(preamble)
        statements.append(
            self.add_col_row_info(
                expr,
                {
                    "method_decl": {
                        "attrs": [],
                        "data_type": None,
                        "name": method_name,
                        "parameters": parameters,
                        "body": body,
                    }
                },
            )
        )
        return method_name

    def _emit_UnpackSequence(
        self, stmt, statements: List[Dict[str, Any]]
    ) -> None:
        source = self.emit_expression(stmt.expr, statements)
        for index, target in enumerate(getattr(stmt, "targets", ()) or ()):
            if not isinstance(target, ast.Local):
                continue
            array_read_tmp = tmp_variable(self.counter)
            statements.append(
                self.add_col_row_info(
                    stmt,
                    {
                        "array_read": {
                            "target": array_read_tmp,
                            "array": source,
                            "index": str(index),
                        }
                    },
                )
            )
            self._emit_variable_decl(target.name, statements)
            statements.append(
                {
                    "assign_stmt": {
                        "target": target.name,
                        "operand": array_read_tmp,
                    }
                }
            )

    # ------------------------------------------------------------------
    # Misc statements
    # ------------------------------------------------------------------
    @staticmethod
    def _emit_Phi(stmt, statements: List[Dict[str, Any]]) -> None:
        target = stmt.target.name if isinstance(stmt.target, ast.Local) else ""
        statements.append({"phi_stmt": {"target": target}})

    def _emit_Discard(self, stmt, statements: List[Dict[str, Any]]) -> None:
        # Expression statements (``risky()``, ``x[0]``, ...) arrive as
        # Discard(expr); emit the inner expression so side effects survive.
        if stmt.expr is not None:
            self.emit_expression(stmt.expr, statements)

    @staticmethod
    def _emit_Print(stmt, statements: List[Dict[str, Any]]) -> None:
        pass

    @staticmethod
    def _emit_Load(stmt, statements: List[Dict[str, Any]]) -> None:
        pass

    @staticmethod
    def _emit_Store(stmt, statements: List[Dict[str, Any]]) -> None:
        pass

    @staticmethod
    def _emit_Allocate(stmt, statements: List[Dict[str, Any]]) -> None:
        pass

    @staticmethod
    def _emit_Check(stmt, statements: List[Dict[str, Any]]) -> None:
        pass

    @staticmethod
    def _emit_InputBlock(stmt, statements: List[Dict[str, Any]]) -> None:
        pass

    @staticmethod
    def _emit_OutputBlock(stmt, statements: List[Dict[str, Any]]) -> None:
        pass

    @staticmethod
    def _emit_EndFinally(stmt, statements: List[Dict[str, Any]]) -> None:
        pass

    # ------------------------------------------------------------------
    # Statement dispatch
    # ------------------------------------------------------------------
    def emit_statement(self, stmt, statements: List[Dict[str, Any]]) -> None:
        source = gir_source_node(stmt)
        if isinstance(source, python_ast.stmt) and self._emit_python_statement(
            source, statements
        ):
            return
        # The frontend wraps some constructs (AugAssign, With, Match, ...) in
        # tagged Suites that do not flatten into their parent; recurse.
        if isinstance(stmt, ast.Suite):
            for block in stmt.blocks:
                self.emit_statement(block, statements)
            return
        handler = getattr(self, f"_emit_{type(stmt).__name__}", None)
        if handler is not None:
            handler(stmt, statements)
            return
        # Discard is an expression-less wrapper in pyflow; emit its expr.
        if isinstance(stmt, ast.Discard) and stmt.expr is not None:
            self.emit_expression(stmt.expr, statements)
