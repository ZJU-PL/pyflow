"""
Shared context for PyFlow query engines.
"""

import os
from typing import List, Optional, Union

from pyflow.application.errors import TemporaryLimitation


class QueryContext:
    """
    Encapsulates the state required for querying semantic facts.

    Holds references to the compiler and program, and provides
    common resolution logic.
    """

    def __init__(self, compiler, program):
        self.compiler = compiler
        self.program = program

    def require_ipa(self):
        """Ensure IPA analysis is available and return it."""
        if getattr(self.program, "ipa_analysis", None) is None:
            raise TemporaryLimitation("IPA analysis not available; run IPA first.")
        return self.program.ipa_analysis

    def resolve_function(self, function: Union[str, object]):
        """Resolve a function name or object to a code object."""
        if isinstance(function, str):
            code = self._find_function_by_name(function)
            if code is None:
                raise ValueError(f"Function '{function}' not found in live code.")
            return code
        if hasattr(function, "codeName"):
            return function
        raise TypeError("Expected a function name or a PyFlow code object.")

    def resolve_function_name(self, function: Union[str, object]) -> str:
        """Resolve a function name or object to a string name."""
        if function is None:
            raise ValueError("Function name is required.")
        if isinstance(function, str):
            return function
        if hasattr(function, "codeName"):
            return function.codeName()
        if hasattr(function, "__name__"):
            return function.__name__
        raise TypeError("Expected a function name or a PyFlow code object.")

    def code_identifier(self, code) -> Optional[str]:
        """Get a collision-resistant identifier for a code object."""
        if code is None:
            return None
        name = self.code_name(code)
        if name is None:
            return None

        filename, lineno = self._origin_location(code)
        if filename:
            location = f"{os.path.abspath(filename)}:{lineno if lineno is not None else '?'}"
            return f"{name}@{location}"
        return f"{name}@id:{id(code):x}"

    def code_aliases(self, code) -> List[str]:
        """Return aliases that may refer to a code object in public queries."""
        aliases: List[str] = []
        base = self.code_name(code)
        if base:
            aliases.append(base)
        identifier = self.code_identifier(code)
        if identifier and identifier not in aliases:
            aliases.append(identifier)
        return aliases

    def context_name(self, context) -> Optional[str]:
        """Get the name of the code associated with an IPA context."""
        code = getattr(context.signature, "code", None)
        return self.code_name(code)

    def code_name(self, code) -> Optional[str]:
        """Get the name of a code object."""
        if code is None:
            return None
        if hasattr(code, "codeName"):
            return code.codeName()
        if hasattr(code, "__name__"):
            return code.__name__
        return str(code)

    def _find_function_by_name(self, function_name: str):
        """Find a function code object by name in the program."""
        matches = []
        seen = set()

        def maybe_add(code):
            if code is None:
                return
            key = self._dedupe_key(code)
            if key in seen:
                return
            aliases = self.code_aliases(code)
            if function_name in aliases:
                seen.add(key)
                matches.append(code)

        for code in getattr(self.program, "liveCode", []):
            maybe_add(code)

        interface = getattr(self.program, "interface", None)
        if interface and hasattr(interface, "entryPoint"):
            for ep in interface.entryPoint:
                maybe_add(getattr(ep, "code", None))

        if not matches:
            return None
        if len(matches) > 1:
            choices = ", ".join(self.code_identifier(code) or "<unknown>" for code in matches[:5])
            if len(matches) > 5:
                choices += ", ..."
            raise ValueError(
                f"Function name '{function_name}' is ambiguous. Use one of: {choices}"
            )
        return matches[0]

    def _dedupe_key(self, code):
        name = self.code_name(code)
        filename, lineno = self._origin_location(code)
        if filename:
            return ("source", name, os.path.realpath(filename), lineno or "?")
        return ("id", id(code))

    def _origin_location(self, code) -> tuple[Optional[str], Optional[object]]:
        annotation = getattr(code, "annotation", None)
        origin = getattr(annotation, "origin", None)
        filename = getattr(origin, "filename", None)
        lineno = getattr(origin, "lineno", None)
        if filename:
            return filename, lineno

        if isinstance(origin, (tuple, list)):
            for item in origin:
                if not isinstance(item, str):
                    continue
                if item.startswith("source(") and item.endswith(")"):
                    payload = item[len("source(") : -1]
                    parsed_filename, _sep, parsed_lineno = payload.rpartition(":")
                    if parsed_filename:
                        return parsed_filename, parsed_lineno or "?"

        return None, None
