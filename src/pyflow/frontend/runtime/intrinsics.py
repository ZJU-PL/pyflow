"""IR models for built-in operations and interpreter helpers."""

import operator
from collections.abc import Mapping, Sequence

from pyflow.language.python import ast as pyflow_ast
from pyflow.language.python.annotations import CodeAnnotation


class IntrinsicManager:
    """Manage PyFlow IR models for built-in interpreter operations.

    These are executable-semantics models, not ``.pyi`` type stubs.
    """

    def __init__(self, compiler):
        self.compiler = compiler
        self.stubs = self._create_stubs()

    def _create_stubs(self):
        """Create stub functions for built-in operations."""
        return self._create_minimal_stubs()

    def _create_minimal_stubs(self):
        """Create minimal stub functions as fallback.

        These stubs include lightweight dynamic folding so arithmetic and
        comparison operators still propagate concrete return types during
        analysis. The goal is to keep the fallback fast while maintaining
        enough fidelity for downstream tests.
        """

        def params_for(op_name):
            """Return CodeParameters tailored to the stub signature."""

            def make_params(params_list, varg=None, kwarg=None):
                return pyflow_ast.CodeParameters(
                    selfparam=None,
                    posonlyparams=[],
                    posonlynames=[],
                    params=params_list,
                    paramnames=[p.name for p in params_list if hasattr(p, "name")],
                    defaults=[],
                    vparam=varg,
                    kparam=kwarg,
                    returnparams=[pyflow_ast.Local("internal_return")],
                    type_params=None,
                )

            if op_name == "interpreter_call":
                return make_params(
                    [pyflow_ast.Local("func")],
                    varg=pyflow_ast.Local("vargs"),
                    kwarg=pyflow_ast.DoNotCare(),
                )

            if op_name in ("convertToBool", "invertedConvertToBool"):
                return make_params([pyflow_ast.Local("x")])

            if op_name in (
                "interpreter_enter",
                "interpreter_aenter",
                "interpreter_aiter",
                "interpreter_join_str",
            ):
                return make_params([pyflow_ast.Local("value")])

            if op_name in ("interpreter_exit", "interpreter_aexit"):
                return make_params(
                    [
                        pyflow_ast.Local("manager"),
                        pyflow_ast.Local("exception_type"),
                        pyflow_ast.Local("exception"),
                        pyflow_ast.Local("traceback"),
                    ]
                )

            if op_name == "interpreter_format":
                return make_params(
                    [
                        pyflow_ast.Local("value"),
                        pyflow_ast.Local("conversion"),
                        pyflow_ast.Local("format_spec"),
                    ]
                )

            if op_name in (
                "interpreter__neg__",
                "interpreter__pos__",
                "interpreter__invert__",
                "interpreter_make_generator",
                "interpreter_match_rest",
                "interpreter_exception_type",
            ):
                return make_params([pyflow_ast.Local("a")])

            if op_name == "interpreter_match_mapping_rest":
                return make_params([pyflow_ast.Local("subject"), pyflow_ast.Local("keys")])

            if op_name == "interpreter_unpack_check":
                return make_params(
                    [
                        pyflow_ast.Local("value"),
                        pyflow_ast.Local("count"),
                        pyflow_ast.Local("star_index"),
                    ]
                )

            if op_name == "interpreter_setattr":
                return make_params(
                    [
                        pyflow_ast.Local("obj"),
                        pyflow_ast.Local("name"),
                        pyflow_ast.Local("value"),
                    ]
                )

            if op_name == "interpreter_setitem":
                return make_params(
                    [
                        pyflow_ast.Local("obj"),
                        pyflow_ast.Local("subscript"),
                        pyflow_ast.Local("value"),
                    ]
                )

            if op_name == "interpreter_match_class_arg":
                return make_params(
                    [
                        pyflow_ast.Local("subject"),
                        pyflow_ast.Local("cls"),
                        pyflow_ast.Local("index"),
                    ]
                )

            if op_name == "interpreter_ifexp":
                return make_params(
                    [
                        pyflow_ast.Local("cond"),
                        pyflow_ast.Local("t"),
                        pyflow_ast.Local("f"),
                    ]
                )

            if op_name == "interpreter_build_map":
                return make_params(
                    [
                        pyflow_ast.Local("pairs"),
                        pyflow_ast.Local("mappings"),
                    ]
                )

            if op_name in (
                "interpreter_build_list",
                "interpreter_build_tuple",
                "interpreter_build_set",
            ):
                return make_params([pyflow_ast.Local("items")])

            return make_params([pyflow_ast.Local("a"), pyflow_ast.Local("b")])

        def _checked_unpack(value, count, star_index):
            """Return None or raise ValueError like CPython's sequence unpack."""
            try:
                length = len(value)
            except TypeError:
                # Iterators without __len__ cannot be validated statically.
                return None
            minimum = count - 1 if star_index >= 0 else count
            if length < minimum or (star_index < 0 and length != count):
                raise ValueError(
                    "not enough values to unpack"
                    if length < minimum
                    else "too many values to unpack"
                )
            return None

        def _safe_merge_varargs(a, b):
            try:
                return list(a) + list(b)
            except Exception:
                return []

        def _is_match_sequence(value):
            return isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray))

        def _safe_merge_kwargs(a, b):
            out = {}
            try:
                out.update(dict(a))
            except Exception:
                pass
            try:
                out.update(dict(b))
            except Exception:
                pass
            return out

        def _safe_aiter(obj):
            try:
                return obj.__aiter__()
            except Exception:
                try:
                    return iter(obj)
                except Exception:
                    return iter(())

        def _safe_aenter(cm):
            try:
                return cm.__aenter__()
            except Exception:
                return cm

        def _safe_aexit(cm, et, ev, tb):
            try:
                fn = getattr(cm, "__aexit__", None)
                if callable(fn):
                    return fn(et, ev, tb)
            except Exception:
                pass
            return False

        def _safe_format(value, conversion, format_spec):
            try:
                if conversion == ord("s"):
                    value = str(value)
                elif conversion == ord("r"):
                    value = repr(value)
                elif conversion == ord("a"):
                    value = ascii(value)
                spec = "" if format_spec is None else str(format_spec)
                return format(value, spec)
            except Exception:
                return str(value)

        def _safe_build_map(pairs, mappings):
            out = {}
            try:
                for pair in pairs:
                    if isinstance(pair, (list, tuple)) and len(pair) == 3 and pair[0] == "item":
                        _, key, value = pair
                        out[key] = value
                    elif (
                        isinstance(pair, (list, tuple)) and len(pair) == 2 and pair[0] == "mapping"
                    ):
                        out.update(dict(pair[1]))
                    elif isinstance(pair, (list, tuple)) and len(pair) == 2:
                        key, value = pair
                        out[key] = value
            except Exception:
                pass

            try:
                for mapping in mappings:
                    out.update(dict(mapping))
            except Exception:
                pass

            return out

        def _safe_build_sequence(items, factory):
            """Build a list/tuple/set from tagged display items.

            ``items`` follows the same protocol as ``interpreter_build_map``:
            ``("item", value)`` appends one element and ``("spread", iterable)``
            extends with the iterable's elements, in source order.  Untagged
            values are accepted as plain elements for compatibility.
            """
            elements = []
            try:
                for item in items:
                    if isinstance(item, (list, tuple)) and len(item) == 2 and item[0] == "spread":
                        elements.extend(list(item[1]))
                    elif isinstance(item, (list, tuple)) and len(item) == 2 and item[0] == "item":
                        elements.append(item[1])
                    else:
                        elements.append(item)
            except Exception:
                pass
            return factory(elements)

        def _safe_build_list(items):
            return _safe_build_sequence(items, list)

        def _safe_build_tuple(items):
            return _safe_build_sequence(items, tuple)

        def _safe_build_set(*args):
            # Accept the tagged-item display form as well as legacy varargs.
            if len(args) == 1 and isinstance(args[0], (list, tuple)):
                try:
                    return _safe_build_sequence(args[0], set)
                except Exception:
                    return set()
            return set(args)

        # Map stub names to simple Python callables used for dynamic folding.
        dynfold = {
            "interpreter_getattribute": getattr,
            "interpreter_setattr": setattr,
            "interpreter__mul__": operator.mul,
            "interpreter__matmul__": operator.matmul,
            "interpreter__add__": operator.add,
            "interpreter__sub__": operator.sub,
            "interpreter__div__": operator.truediv,
            "interpreter__truediv__": operator.truediv,
            "interpreter__mod__": operator.mod,
            "interpreter__pow__": operator.pow,
            "interpreter__and__": operator.and_,
            "interpreter__or__": operator.or_,
            "interpreter__xor__": operator.xor,
            "interpreter__lshift__": operator.lshift,
            "interpreter__rshift__": operator.rshift,
            "interpreter__floordiv__": operator.floordiv,
            "interpreter__iadd__": operator.iadd,
            "interpreter__isub__": operator.isub,
            "interpreter__imul__": operator.imul,
            "interpreter__imatmul__": operator.imatmul,
            "interpreter__itruediv__": operator.itruediv,
            "interpreter__ifloordiv__": operator.ifloordiv,
            "interpreter__imod__": operator.imod,
            "interpreter__ipow__": operator.ipow,
            "interpreter__iand__": operator.iand,
            "interpreter__ior__": operator.ior,
            "interpreter__ixor__": operator.ixor,
            "interpreter__ilshift__": operator.ilshift,
            "interpreter__irshift__": operator.irshift,
            "interpreter__eq__": operator.eq,
            "interpreter__ne__": operator.ne,
            "interpreter__lt__": operator.lt,
            "interpreter__le__": operator.le,
            "interpreter__gt__": operator.gt,
            "interpreter__ge__": operator.ge,
            "interpreter__is__": operator.is_,
            "interpreter__is_not__": operator.is_not,
            "interpreter__contains__": operator.contains,
            "interpreter__neg__": operator.neg,
            "interpreter__pos__": operator.pos,
            "interpreter__invert__": operator.invert,
            "interpreter_getitem": operator.getitem,
            "interpreter_unpack_check": _checked_unpack,
            "interpreter_setitem": operator.setitem,
            "interpreter_delitem": operator.delitem,
            "interpreter_call": lambda func, *args, **kwargs: func(*args, **kwargs),
            "interpreter_booland": lambda a, b: a and b,
            "interpreter_boolor": lambda a, b: a or b,
            "interpreter_ifexp": lambda cond, t, f: t if cond else f,
            "object__getattribute__": getattr,
            "convertToBool": bool,
            "invertedConvertToBool": lambda x: not bool(x),
            # Context manager protocol
            "interpreter_enter": lambda cm: cm.__enter__(),
            "interpreter_exit": lambda cm, et, ev, tb: cm.__exit__(et, ev, tb),
            "interpreter_aenter": _safe_aenter,
            "interpreter_aexit": _safe_aexit,
            "interpreter_aiter": _safe_aiter,
            # String formatting
            "interpreter_format": _safe_format,
            "interpreter_join_str": lambda parts: "".join(str(p) for p in parts),
            "interpreter_build_map": _safe_build_map,
            "interpreter_build_list": _safe_build_list,
            "interpreter_build_tuple": _safe_build_tuple,
            # Container helpers
            "interpreter_list_append": lambda lst, item: lst.append(item),
            "interpreter_build_set": _safe_build_set,
            # Pattern matching helpers (no simple Python equivalent)
            "interpreter_match_sequence_len": lambda seq, n: bool(
                _is_match_sequence(seq) and len(seq) == n
            ),
            "interpreter_match_sequence_len_min": lambda seq, n: bool(
                _is_match_sequence(seq) and len(seq) >= n
            ),
            "interpreter_match_mapping_len": lambda mapping, n: bool(
                isinstance(mapping, Mapping) and len(mapping) >= n
            ),
            "interpreter_match_mapping_rest": lambda subject, keys: (
                {
                    key: value
                    for key, value in getattr(subject, "items", lambda: [])()
                    if key not in set(keys)
                }
                if hasattr(subject, "items")
                else subject
            ),
            "interpreter_match_class": isinstance,
            "interpreter_match_class_arg": lambda subject, cls, index: getattr(
                subject,
                getattr(cls, "__match_args__", ())[index],
            ),
            "interpreter_match_rest": lambda subject: subject,
            "interpreter_exception_group_extract": lambda exc_group, exc_type: (
                exc_group.split(exc_type)[0] if hasattr(exc_group, "split") else exc_group
            ),
            # ``except*`` handlers are independent: every matching clause runs
            # for a single exception group.  A non-group exception matches by
            # ``isinstance`` just like it does for a plain ``except``.
            "interpreter_exception_group_matches": lambda exc, exc_type: (
                any(isinstance(item, exc_type) for item in exc.exceptions)
                if getattr(exc, "exceptions", None) is not None
                else isinstance(exc, exc_type)
            ),
            "interpreter_exception_type": type,
            "interpreter_make_generator": lambda value: iter((value,)),
            "interpreter_getattr": getattr,
            "interpreter_hasattr": hasattr,
            "interpreter_merge_varargs": _safe_merge_varargs,
            "interpreter_merge_kwargs": _safe_merge_kwargs,
            "interpreter_set_add": lambda s, item: s.add(item),
            "interpreter_unsupported_expr": lambda node, detail: None,
            "interpreter_unsupported_stmt": lambda node, detail: None,
            "interpreter_unknown_augassign": lambda op, rhs: rhs,
        }

        def create_stub_code(name):
            # Create a minimal code object that satisfies the type requirements
            params = params_for(name)
            body = pyflow_ast.Suite([])
            code = pyflow_ast.Code(name, params, body)
            dyn_fold = dynfold.get(name)
            code.annotation = CodeAnnotation(
                descriptive=False,
                primitive=False,
                staticFold=None,
                dynamicFold=dyn_fold,
                origin=[f"stub_{name}"],
                lowered=False,
                runtime=False,
                interpreter=True,
            )
            return code

        return type(
            "Stubs",
            (),
            {
                "exports": {
                    "interpreter_getattribute": create_stub_code("interpreter_getattribute"),
                    "interpreter_setattr": create_stub_code("interpreter_setattr"),
                    "interpreter__mul__": create_stub_code("interpreter__mul__"),
                    "interpreter__matmul__": create_stub_code("interpreter__matmul__"),
                    "interpreter__add__": create_stub_code("interpreter__add__"),
                    "interpreter__sub__": create_stub_code("interpreter__sub__"),
                    "interpreter__div__": create_stub_code("interpreter__div__"),
                    "interpreter__truediv__": create_stub_code("interpreter__truediv__"),
                    "interpreter__mod__": create_stub_code("interpreter__mod__"),
                    "interpreter__pow__": create_stub_code("interpreter__pow__"),
                    "interpreter__and__": create_stub_code("interpreter__and__"),
                    "interpreter__or__": create_stub_code("interpreter__or__"),
                    "interpreter__xor__": create_stub_code("interpreter__xor__"),
                    "interpreter__lshift__": create_stub_code("interpreter__lshift__"),
                    "interpreter__rshift__": create_stub_code("interpreter__rshift__"),
                    "interpreter__floordiv__": create_stub_code("interpreter__floordiv__"),
                    "interpreter__iadd__": create_stub_code("interpreter__iadd__"),
                    "interpreter__isub__": create_stub_code("interpreter__isub__"),
                    "interpreter__imul__": create_stub_code("interpreter__imul__"),
                    "interpreter__imatmul__": create_stub_code("interpreter__imatmul__"),
                    "interpreter__itruediv__": create_stub_code("interpreter__itruediv__"),
                    "interpreter__ifloordiv__": create_stub_code("interpreter__ifloordiv__"),
                    "interpreter__imod__": create_stub_code("interpreter__imod__"),
                    "interpreter__ipow__": create_stub_code("interpreter__ipow__"),
                    "interpreter__iand__": create_stub_code("interpreter__iand__"),
                    "interpreter__ior__": create_stub_code("interpreter__ior__"),
                    "interpreter__ixor__": create_stub_code("interpreter__ixor__"),
                    "interpreter__ilshift__": create_stub_code("interpreter__ilshift__"),
                    "interpreter__irshift__": create_stub_code("interpreter__irshift__"),
                    "interpreter__eq__": create_stub_code("interpreter__eq__"),
                    "interpreter__ne__": create_stub_code("interpreter__ne__"),
                    "interpreter__lt__": create_stub_code("interpreter__lt__"),
                    "interpreter__le__": create_stub_code("interpreter__le__"),
                    "interpreter__gt__": create_stub_code("interpreter__gt__"),
                    "interpreter__ge__": create_stub_code("interpreter__ge__"),
                    "interpreter__is__": create_stub_code("interpreter__is__"),
                    "interpreter__is_not__": create_stub_code("interpreter__is_not__"),
                    "interpreter__contains__": create_stub_code("interpreter__contains__"),
                    "interpreter__neg__": create_stub_code("interpreter__neg__"),
                    "interpreter__pos__": create_stub_code("interpreter__pos__"),
                    "interpreter__invert__": create_stub_code("interpreter__invert__"),
                    "interpreter_getitem": create_stub_code("interpreter_getitem"),
                    "interpreter_setitem": create_stub_code("interpreter_setitem"),
                    "interpreter_delitem": create_stub_code("interpreter_delitem"),
                    "interpreter_call": create_stub_code("interpreter_call"),
                    "interpreter_booland": create_stub_code("interpreter_booland"),
                    "interpreter_boolor": create_stub_code("interpreter_boolor"),
                    "interpreter_ifexp": create_stub_code("interpreter_ifexp"),
                    "convertToBool": create_stub_code("convertToBool"),
                    "invertedConvertToBool": create_stub_code("invertedConvertToBool"),
                    "object__getattribute__": create_stub_code("object__getattribute__"),
                    "object__setattribute__": create_stub_code("object__setattribute__"),
                    "object__call__": create_stub_code("object__call__"),
                    "function__get__": create_stub_code("function__get__"),
                    "function__call__": create_stub_code("function__call__"),
                    "method__get__": create_stub_code("method__get__"),
                    "method__call__": create_stub_code("method__call__"),
                    "methoddescriptor__get__": create_stub_code("methoddescriptor__get__"),
                    "methoddescriptor__call__": create_stub_code("methoddescriptor__call__"),
                    # Context manager protocol stubs
                    "interpreter_enter": create_stub_code("interpreter_enter"),
                    "interpreter_exit": create_stub_code("interpreter_exit"),
                    "interpreter_aenter": create_stub_code("interpreter_aenter"),
                    "interpreter_aexit": create_stub_code("interpreter_aexit"),
                    "interpreter_aiter": create_stub_code("interpreter_aiter"),
                    # String formatting stubs
                    "interpreter_format": create_stub_code("interpreter_format"),
                    "interpreter_join_str": create_stub_code("interpreter_join_str"),
                    "interpreter_build_map": create_stub_code("interpreter_build_map"),
                    "interpreter_build_list": create_stub_code("interpreter_build_list"),
                    "interpreter_build_tuple": create_stub_code("interpreter_build_tuple"),
                    # Container helper stubs
                    "interpreter_list_append": create_stub_code("interpreter_list_append"),
                    "interpreter_build_set": create_stub_code("interpreter_build_set"),
                    "interpreter_set_add": create_stub_code("interpreter_set_add"),
                    "interpreter_merge_varargs": create_stub_code("interpreter_merge_varargs"),
                    "interpreter_merge_kwargs": create_stub_code("interpreter_merge_kwargs"),
                    "interpreter_unsupported_expr": create_stub_code(
                        "interpreter_unsupported_expr"
                    ),
                    "interpreter_unsupported_stmt": create_stub_code(
                        "interpreter_unsupported_stmt"
                    ),
                    "interpreter_unknown_augassign": create_stub_code(
                        "interpreter_unknown_augassign"
                    ),
                    # Pattern matching stubs (Python 3.10+)
                    "interpreter_match_sequence_len": create_stub_code(
                        "interpreter_match_sequence_len"
                    ),
                    "interpreter_match_sequence_len_min": create_stub_code(
                        "interpreter_match_sequence_len_min"
                    ),
                    "interpreter_match_mapping_len": create_stub_code(
                        "interpreter_match_mapping_len"
                    ),
                    "interpreter_match_mapping_rest": create_stub_code(
                        "interpreter_match_mapping_rest"
                    ),
                    "interpreter_match_class": create_stub_code("interpreter_match_class"),
                    "interpreter_match_class_arg": create_stub_code("interpreter_match_class_arg"),
                    "interpreter_match_rest": create_stub_code("interpreter_match_rest"),
                    "interpreter_exception_group_extract": create_stub_code(
                        "interpreter_exception_group_extract"
                    ),
                    "interpreter_exception_group_matches": create_stub_code(
                        "interpreter_exception_group_matches"
                    ),
                    "interpreter_exception_type": create_stub_code("interpreter_exception_type"),
                    "interpreter_make_generator": create_stub_code("interpreter_make_generator"),
                    # Generic attribute access helper
                    "interpreter_getattr": create_stub_code("interpreter_getattr"),
                    "interpreter_unpack_check": create_stub_code("interpreter_unpack_check"),
                    "interpreter_hasattr": create_stub_code("interpreter_hasattr"),
                }
            },
        )()


__all__ = ["IntrinsicManager"]
