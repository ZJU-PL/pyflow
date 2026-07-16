#  This file is part of PyFlow.
#
#  SPDX-FileCopyrightText: 2019–2026 PyFlow Contributors
#
#  SPDX-License-Identifier: MIT
#

from __future__ import annotations

import pytest

from pyflow.analysis.typeinfo.docstring_parser import (
    expand_typestr,
    search_param_in_docstr,
    search_return_in_docstr,
    strip_rst_role,
)


# ---------------------------------------------------------------------------
# strip_rst_role
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("type_str", "expected"),
    [
        (":class:`ClassName`", "ClassName"),
        (":py:obj:`module.Object`", "module.Object"),
        (":func:`some_func`", "some_func"),
        ("PlainType", "PlainType"),
        ("", ""),
    ],
)
def test_strip_rst_role(type_str: str, expected: str) -> None:
    assert strip_rst_role(type_str) == expected


# ---------------------------------------------------------------------------
# expand_typestr
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("type_str", "expected"),
    [
        ("int", ["int"]),
        ("str", ["str"]),
        ("int or str", ["int", "str"]),
        ("int or str or float", ["int", "str", "float"]),
        ("list of int", ["list"]),
        ("dict of str", ["dict"]),
    ],
)
def test_expand_typestr_basic(type_str: str, expected: list[str]) -> None:
    assert expand_typestr(type_str) == expected


def test_expand_typestr_set_literal_ints() -> None:
    result = expand_typestr("{1, 2, 3}")
    assert "int" in result


def test_expand_typestr_set_literal_strings() -> None:
    result = expand_typestr("{'a', 'b', 'c'}")
    assert "str" in result


def test_expand_typestr_invalid_syntax() -> None:
    result = expand_typestr("{invalid")
    assert result == ["{invalid"]


# ---------------------------------------------------------------------------
# search_param_in_docstr — Sphinx / Epydoc
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("docstr", "param_name", "expected"),
    [
        (":type param: int", "param", ["int"]),
        ("@type param: int", "param", ["int"]),
        (":type foo: str", "foo", ["str"]),
        (":type bar: float", "bar", ["float"]),
        (":type param: :class:`threading.Thread`", "param", ["threading.Thread"]),
        (":type param: :py:obj:`module.Class`", "param", ["module.Class"]),
    ],
)
def test_search_param_in_docstr_found(
    docstr: str, param_name: str, expected: list[str]
) -> None:
    assert search_param_in_docstr(docstr, param_name) == expected


@pytest.mark.parametrize(
    ("docstr", "param_name"),
    [
        ("no document", "param"),
        (":type other: int", "param"),
        ("", "param"),
    ],
)
def test_search_param_in_docstr_not_found(
    docstr: str, param_name: str
) -> None:
    assert search_param_in_docstr(docstr, param_name) == []


def test_search_param_in_docstr_sphinx_param_with_type() -> None:
    """Sphinx :param Type name: description format."""
    result = search_param_in_docstr(
        ":param int param: some description", "param"
    )
    assert "int" in result


def test_search_param_in_docstr_multiline() -> None:
    docstr = """\
    My function.

    :type x: int
    :type y: str
    :rtype: bool
    """
    assert search_param_in_docstr(docstr, "x") == ["int"]
    assert search_param_in_docstr(docstr, "y") == ["str"]


# ---------------------------------------------------------------------------
# search_return_in_docstr
# ---------------------------------------------------------------------------


def test_search_return_in_docstr_sphinx() -> None:
    result = list(search_return_in_docstr(":rtype: int"))
    assert result == ["int"]


def test_search_return_in_docstr_epydoc() -> None:
    result = list(search_return_in_docstr("@rtype: str"))
    assert result == ["str"]


def test_search_return_in_docstr_rst_role() -> None:
    result = list(search_return_in_docstr(":rtype: :class:`MyClass`"))
    assert result == ["MyClass"]


def test_search_return_in_docstr_not_found() -> None:
    result = list(search_return_in_docstr("No return type here."))
    assert result == []


def test_search_return_in_docstr_multiline() -> None:
    docstr = """\
    Does something.

    :param x: the input
    :type x: int
    :returns: the result
    :rtype: bool
    """
    result = list(search_return_in_docstr(docstr))
    assert "bool" in result
