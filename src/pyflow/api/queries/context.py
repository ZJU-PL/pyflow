"""
Shared context for PyFlow query engines.
"""

from typing import Optional, Union

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
        for code in getattr(self.program, "liveCode", []):
            if hasattr(code, "codeName") and code.codeName() == function_name:
                return code

        interface = getattr(self.program, "interface", None)
        if interface and hasattr(interface, "entryPoint"):
            for ep in interface.entryPoint:
                if hasattr(ep.code, "codeName") and ep.code.codeName() == function_name:
                    return ep.code
        return None