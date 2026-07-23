"""IR models for built-in operations and interpreter helpers."""

import operator

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
                    paramnames=[p.name for p in params_list if hasattr(p, 'name')],
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

            if op_name == "interpreter_setattr":
                return make_params([
                    pyflow_ast.Local("obj"),
                    pyflow_ast.Local("name"),
                    pyflow_ast.Local("value"),
                ])

            if op_name == "interpreter_setitem":
                return make_params([
                    pyflow_ast.Local("obj"),
                    pyflow_ast.Local("subscript"),
                    pyflow_ast.Local("value"),
                ])

            if op_name == "interpreter_match_class_arg":
                return make_params([
                    pyflow_ast.Local("subject"),
                    pyflow_ast.Local("cls"),
                    pyflow_ast.Local("index"),
                ])

            if op_name == "interpreter_ifexp":
                return make_params([
                    pyflow_ast.Local("cond"),
                    pyflow_ast.Local("t"),
                    pyflow_ast.Local("f"),
                ])

            if op_name == "interpreter_build_map":
                return make_params([
                    pyflow_ast.Local("pairs"),
                    pyflow_ast.Local("mappings"),
                ])

            return make_params([pyflow_ast.Local("a"), pyflow_ast.Local("b")])

        def _safe_merge_varargs(a, b):
            try:
                left = list(a if isinstance(a, (list, tuple)) else [a])
                right = list(b if isinstance(b, (list, tuple)) else [b])
                return left + right
            except Exception:
                return []

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

        def _safe_build_map(pairs, mappings):
            out = {}
            try:
                for pair in pairs:
                    if isinstance(pair, (list, tuple)) and len(pair) == 2:
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

        # Map stub names to simple Python callables used for dynamic folding.
        dynfold = {
            "interpreter_getattribute": getattr,
            "interpreter_setattr": setattr,
            "interpreter__mul__": operator.mul,
            "interpreter__add__": operator.add,
            "interpreter__sub__": operator.sub,
            "interpreter__div__": operator.truediv,
            "interpreter__mod__": operator.mod,
            "interpreter__pow__": operator.pow,
            "interpreter__and__": operator.and_,
            "interpreter__or__": operator.or_,
            "interpreter__xor__": operator.xor,
            "interpreter__lshift__": operator.lshift,
            "interpreter__rshift__": operator.rshift,
            "interpreter__floordiv__": operator.floordiv,
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
            "interpreter_format": format,
            "interpreter_join_str": lambda parts: "".join(str(p) for p in parts),
            "interpreter_build_map": _safe_build_map,
            # Container helpers
            "interpreter_list_append": lambda lst, item: lst.append(item),
            "interpreter_build_set": lambda *args: set(args),
            # Pattern matching helpers (no simple Python equivalent)
            "interpreter_match_sequence_len": lambda seq, n: bool(
                hasattr(seq, "__len__") and len(seq) == n
            ),
            "interpreter_match_sequence_len_min": lambda seq, n: bool(
                hasattr(seq, "__len__") and len(seq) >= n
            ),
            "interpreter_match_mapping_len": lambda mapping, n: bool(
                hasattr(mapping, "__len__") and len(mapping) >= n
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
            "interpreter_exception_group_extract": lambda exc_group, exc_type: exc_group,
            "interpreter_exception_type": type,
            "interpreter_make_generator": lambda value: iter((value,)),
            "interpreter_getattr": getattr,
            "interpreter_merge_varargs": _safe_merge_varargs,
            "interpreter_merge_kwargs": _safe_merge_kwargs,
            "interpreter_set_add": lambda s, item: (s.add(item), s)[1],
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
                contexts=None,
                descriptive=False,
                primitive=False,
                staticFold=None,
                dynamicFold=dyn_fold,
                origin=[f"stub_{name}"],
                live=None,
                killed=None,
                codeReads=None,
                codeModifies=None,
                codeAllocates=None,
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
                    "interpreter_getattribute": create_stub_code(
                        "interpreter_getattribute"
                    ),
                    "interpreter_setattr": create_stub_code("interpreter_setattr"),
                    "interpreter__mul__": create_stub_code("interpreter__mul__"),
                    "interpreter__add__": create_stub_code("interpreter__add__"),
                    "interpreter__sub__": create_stub_code("interpreter__sub__"),
                    "interpreter__div__": create_stub_code("interpreter__div__"),
                    "interpreter__mod__": create_stub_code("interpreter__mod__"),
                    "interpreter__pow__": create_stub_code("interpreter__pow__"),
                    "interpreter__and__": create_stub_code("interpreter__and__"),
                    "interpreter__or__": create_stub_code("interpreter__or__"),
                    "interpreter__xor__": create_stub_code("interpreter__xor__"),
                    "interpreter__lshift__": create_stub_code("interpreter__lshift__"),
                    "interpreter__rshift__": create_stub_code("interpreter__rshift__"),
                    "interpreter__floordiv__": create_stub_code(
                        "interpreter__floordiv__"
                    ),
                    "interpreter__eq__": create_stub_code("interpreter__eq__"),
                    "interpreter__ne__": create_stub_code("interpreter__ne__"),
                    "interpreter__lt__": create_stub_code("interpreter__lt__"),
                    "interpreter__le__": create_stub_code("interpreter__le__"),
                    "interpreter__gt__": create_stub_code("interpreter__gt__"),
                    "interpreter__ge__": create_stub_code("interpreter__ge__"),
                    "interpreter__is__": create_stub_code("interpreter__is__"),
                    "interpreter__is_not__": create_stub_code("interpreter__is_not__"),
                    "interpreter__contains__": create_stub_code(
                        "interpreter__contains__"
                    ),
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
                    "object__getattribute__": create_stub_code(
                        "object__getattribute__"
                    ),
                    "object__setattribute__": create_stub_code(
                        "object__setattribute__"
                    ),
                    "object__call__": create_stub_code("object__call__"),
                    "function__get__": create_stub_code("function__get__"),
                    "function__call__": create_stub_code("function__call__"),
                    "method__get__": create_stub_code("method__get__"),
                    "method__call__": create_stub_code("method__call__"),
                    "methoddescriptor__get__": create_stub_code(
                        "methoddescriptor__get__"
                    ),
                    "methoddescriptor__call__": create_stub_code(
                        "methoddescriptor__call__"
                    ),
                    # Context manager protocol stubs
                    "interpreter_enter": create_stub_code("interpreter_enter"),
                    "interpreter_exit": create_stub_code("interpreter_exit"),
                    "interpreter_aenter": create_stub_code("interpreter_aenter"),
                    "interpreter_aexit": create_stub_code("interpreter_aexit"),
                    "interpreter_aiter": create_stub_code("interpreter_aiter"),
                    # String formatting stubs
                    "interpreter_format": create_stub_code("interpreter_format"),
                    "interpreter_join_str": create_stub_code("interpreter_join_str"),
                    "interpreter_build_map": create_stub_code(
                        "interpreter_build_map"
                    ),
                    # Container helper stubs
                    "interpreter_list_append": create_stub_code(
                        "interpreter_list_append"
                    ),
                    "interpreter_build_set": create_stub_code("interpreter_build_set"),
                    "interpreter_set_add": create_stub_code("interpreter_set_add"),
                    "interpreter_merge_varargs": create_stub_code(
                        "interpreter_merge_varargs"
                    ),
                    "interpreter_merge_kwargs": create_stub_code(
                        "interpreter_merge_kwargs"
                    ),
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
                    "interpreter_match_class": create_stub_code(
                        "interpreter_match_class"
                    ),
                    "interpreter_match_class_arg": create_stub_code(
                        "interpreter_match_class_arg"
                    ),
                    "interpreter_match_rest": create_stub_code(
                        "interpreter_match_rest"
                    ),
                    "interpreter_exception_group_extract": create_stub_code(
                        "interpreter_exception_group_extract"
                    ),
                    "interpreter_exception_type": create_stub_code(
                        "interpreter_exception_type"
                    ),
                    "interpreter_make_generator": create_stub_code(
                        "interpreter_make_generator"
                    ),
                    # Generic attribute access helper
                    "interpreter_getattr": create_stub_code("interpreter_getattr"),
                }
            },
        )()


__all__ = ["IntrinsicManager"]
