"""Extract type information from Python docstrings.

Supports three documentation styles:

* `Sphinx <http://sphinx-doc.org/markup/desc.html#info-field-lists>`_
* `Epydoc <http://epydoc.sourceforge.net/manual-fields.html>`_
* `Numpydoc <https://github.com/numpy/numpy/blob/master/doc/HOWTO_DOCUMENT.rst.txt>`_

The core parsing logic is adapted from Jedi's ``jedi.inference.docstrings``
(https://github.com/davidhalter/jedi), with type representation adapted
to PyFlow's :mod:`~pyflow.analysis.typeinfo.typesystem`.

SPDX-FileCopyrightText: 2025 David Halter and contributors
SPDX-FileCopyrightText: 2026 PyFlow Contributors
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import ast
import re
import warnings
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator


# ---------------------------------------------------------------------------
# Regex patterns for Sphinx and Epydoc docstring formats
# ---------------------------------------------------------------------------

# Pattern groups: %s is replaced with the parameter name via re.escape.
DOCSTRING_PARAM_PATTERNS: list[str] = [
    r"\s*:type\s+%s:\s*([^\n]+)",  # Sphinx :type param: Type
    r"\s*:param\s+(\w+)\s+%s:[^\n]*",  # Sphinx :param Type param: desc
    r"\s*@type\s+%s:\s*([^\n]+)",  # Epydoc @type param: Type
]

DOCSTRING_RETURN_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\s*:rtype:\s*([^\n]+)", re.MULTILINE),  # Sphinx :rtype: Type
    re.compile(r"\s*@rtype:\s*([^\n]+)", re.MULTILINE),  # Epydoc @rtype: Type
]

# Matches ReST roles like :class:`ClassName` or :py:obj:`module.Object`
REST_ROLE_PATTERN: re.Pattern[str] = re.compile(r":[^`]+:`([^`]+)`")

# ---------------------------------------------------------------------------
# Numpydoc integration (optional dependency)
# ---------------------------------------------------------------------------

_numpy_doc_string_cache: type | None = None
"""Cached reference to ``numpydoc.docscrape.NumpyDocString``, if available."""


def _get_numpy_doc_string_cls() -> type:
    """Lazily import ``numpydoc.docscrape.NumpyDocString``.

    Returns:
        The ``NumpyDocString`` class.

    Raises:
        ImportError: if ``numpydoc`` is not installed.
    """
    global _numpy_doc_string_cache
    if _numpy_doc_string_cache is not None:
        if isinstance(_numpy_doc_string_cache, (ImportError, SyntaxError)):
            raise _numpy_doc_string_cache
        return _numpy_doc_string_cache
    try:
        from numpydoc.docscrape import NumpyDocString  # type: ignore[import-untyped]
    except (ImportError, SyntaxError) as exc:
        _numpy_doc_string_cache = exc  # type: ignore[assignment]
        raise
    _numpy_doc_string_cache = NumpyDocString
    return NumpyDocString


# ---------------------------------------------------------------------------
# Type string expansion
# ---------------------------------------------------------------------------


def _expand_typestr(type_str: str) -> Iterator[str]:
    """Expand a type string from a docstring into possible type names.

    Handles:

    * ``int or str`` → yields ``int``, ``str``
    * ``list of int`` → yields ``list``
    * ``{'C', 'F', 'A'}`` → yields based on literal types
    * plain ``int`` → yields ``int``
    """
    # Alternative types separated by "or"
    if re.search(r"\bor\b", type_str):
        for part in type_str.split("or"):
            yield part.split("of")[0].strip()
        return

    # "container of element" pattern
    of_match = re.search(r"\bof\b", type_str)
    if of_match:
        yield type_str[: of_match.start()].strip()
        return

    # Set literal: infer type from element kind
    if type_str.startswith("{"):
        try:
            tree = ast.parse(type_str, mode="eval")
        except SyntaxError:
            yield type_str
            return
        node = tree.body
        if isinstance(node, ast.Set):
            for elt in node.elts:
                if isinstance(elt, ast.Constant):
                    val = elt.value
                    if isinstance(val, float) or (
                        isinstance(val, int) and "." in type_str
                    ):
                        yield "float"
                    elif isinstance(val, int):
                        yield "int"
                    elif isinstance(val, str):
                        # ast.Constant has no 'kind' attr in Python 3.8+
                        yield "str"
                # Ignore other element types
            return

    yield type_str


# ---------------------------------------------------------------------------
# ReST role stripping
# ---------------------------------------------------------------------------


def _strip_rst_role(type_str: str) -> str:
    """Strip ReST role markup from a type string.

    >>> _strip_rst_role(':class:`ClassName`')
    'ClassName'
    >>> _strip_rst_role(':py:obj:`module.Object`')
    'module.Object'
    >>> _strip_rst_role('ClassName')
    'ClassName'
    """
    match = REST_ROLE_PATTERN.match(type_str)
    if match:
        return match.group(1)
    return type_str


# ---------------------------------------------------------------------------
# Numpydoc helpers
# ---------------------------------------------------------------------------


def _search_param_in_numpydocstr(
    docstr: str, param_str: str
) -> list[str]:
    """Search a numpydoc-formatted docstring for type(s) of *param_str*.

    Requires the optional ``numpydoc`` package.
    """
    try:
        cls = _get_numpy_doc_string_cls()
    except ImportError:
        return []
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        try:
            params = cls(docstr)._parsed_data["Parameters"]
        except Exception:
            return []
    for p_name, p_type, _p_descr in params:
        if p_name == param_str:
            m = re.match(r"([^,]+(,[^,]+)*?)(,[ ]*optional)?$", p_type)
            if m:
                p_type = m.group(1)
            return list(_expand_typestr(p_type))
    return []


def _search_return_in_numpydocstr(docstr: str) -> Iterator[str]:
    """Search a numpydoc-formatted docstring for return type(s)."""
    try:
        cls = _get_numpy_doc_string_cls()
    except ImportError:
        return
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        try:
            doc = cls(docstr)
        except Exception:
            return
    try:
        returns = doc._parsed_data.get("Returns", [])
        returns += doc._parsed_data.get("Yields", [])
    except Exception:
        return
    for _r_name, r_type, _r_descr in returns:
        if not r_type:
            r_type = _r_name
        yield from _expand_typestr(r_type)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def search_param_in_docstr(docstr: str, param_name: str) -> list[str]:
    """Search *docstr* for the type annotation of *param_name*.

    Supports Sphinx (``:type``, ``:param``), Epydoc (``@type``), and
    Numpydoc conventions.  ReST roles like ``:class:`Name``` are stripped.

    Args:
        docstr: The full docstring text.
        param_name: The parameter name to search for.

    Returns:
        A list of type-name strings found for the parameter.  Returns an
        empty list if nothing is found.

    Examples:
        >>> search_param_in_docstr(':type param: int', 'param')
        ['int']
        >>> search_param_in_docstr('@type param: int', 'param')
        ['int']
        >>> search_param_in_docstr(
        ...     ':type param: :class:`threading.Thread`', 'param')
        ['threading.Thread']
        >>> bool(search_param_in_docstr('no document', 'param'))
        False
        >>> search_param_in_docstr(
        ...     ':param int param: some description', 'param')
        ['int']
    """
    patterns = [
        re.compile(p % re.escape(param_name))
        for p in DOCSTRING_PARAM_PATTERNS
    ]
    for pattern in patterns:
        match = pattern.search(docstr)
        if match:
            return [_strip_rst_role(match.group(1))]

    return _search_param_in_numpydocstr(docstr, param_name)


def search_return_in_docstr(docstr: str) -> Iterator[str]:
    """Search *docstr* for return-type annotations.

    Supports Sphinx ``:rtype:``, Epydoc ``@rtype``, and Numpydoc
    ``Returns`` / ``Yields`` sections.

    Args:
        docstr: The full docstring text.

    Yields:
        Type-name strings found for the return value.
    """
    for pattern in DOCSTRING_RETURN_PATTERNS:
        for match in pattern.finditer(docstr):
            yield _strip_rst_role(match.group(1))

    yield from _search_return_in_numpydocstr(docstr)


def expand_typestr(type_str: str) -> list[str]:
    """Expand a type string into its constituent type names.

    This is a public wrapper around :func:`_expand_typestr` that returns
    a list instead of an iterator.

    Args:
        type_str: A raw type string (e.g. ``"int or str"``).

    Returns:
        A list of type-name strings.
    """
    return list(_expand_typestr(type_str))


def strip_rst_role(type_str: str) -> str:
    """Public wrapper around :func:`_strip_rst_role`."""
    return _strip_rst_role(type_str)
