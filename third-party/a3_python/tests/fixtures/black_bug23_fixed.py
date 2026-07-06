# Faithful recreation of fixed code pattern from black bug 23
# Key changes from buggy version:
# 1. GRAMMARS list with 4 grammar variants (no print, no exec, both, neither)
# 2. lib2to3_parse tries each grammar in sequence
# 3. On success, breaks out of the loop
# 4. Only raises ValueError after ALL grammars fail (for-else)
# 5. Files using exec() as function call now parse successfully
#
# The fix: try multiple grammar variants in a for loop so that
# exec-as-function-call is handled by a grammar that doesn't
# treat 'exec' as a keyword.

from typing import Dict, List, Optional


class ParseError(Exception):
    """Error raised when parsing fails."""
    def __init__(self, msg, type_val=None, value=None, context=None):
        super().__init__(msg)
        self.msg = msg
        self.type = type_val
        self.value = value
        self.context = context or ('', (0, 0))


class Grammar:
    """Simplified grammar representation."""
    def __init__(self, name: str, keywords: Optional[Dict[str, int]] = None):
        self.name = name
        self.keywords: Dict[str, int] = dict(keywords) if keywords else {}

    def copy(self) -> 'Grammar':
        return Grammar(self.name, self.keywords)


class Driver:
    """Simplified parser driver."""
    def __init__(self, grammar: Grammar, convert):
        self.grammar = grammar
        self.convert = convert

    def parse_string(self, text: str, debug: bool = False):
        """Parse source text using the configured grammar.

        Raises ParseError if the grammar can't handle the input.
        """
        if 'exec' in self.grammar.keywords and 'exec(' in text:
            raise ParseError(
                "bad input", type_val=1, value='exec',
                context=('', (1, 0))
            )
        return {"type": "file_input", "children": []}


def pytree_convert(grammar, raw_node):
    return raw_node


# ---- Module-level grammar definitions ----
python_grammar = Grammar("python", {"print": 1, "exec": 2})

python_grammar_no_print_statement = python_grammar.copy()
del python_grammar_no_print_statement.keywords["print"]

python_grammar_no_exec_statement = python_grammar.copy()
del python_grammar_no_exec_statement.keywords["exec"]

python_grammar_no_print_statement_no_exec_statement = python_grammar.copy()
del python_grammar_no_print_statement_no_exec_statement.keywords["print"]
del python_grammar_no_print_statement_no_exec_statement.keywords["exec"]


# FIXED: List of grammars to try, most permissive first
GRAMMARS = [
    python_grammar_no_print_statement_no_exec_statement,
    python_grammar_no_print_statement,
    python_grammar_no_exec_statement,
    python_grammar,
]


def lib2to3_parse(src_txt: str):
    """Given a string with source, return the lib2to3 Node.

    FIXED: Tries multiple grammars in sequence.  If one grammar fails
    to parse the input, the next grammar is tried.  Only after ALL
    grammars have been exhausted does the function raise ValueError.
    """
    if src_txt[-1] != '\n':
        nl = '\r\n' if '\r\n' in src_txt[:1024] else '\n'
        src_txt += nl
    for grammar in GRAMMARS:
        drv = Driver(grammar, pytree_convert)
        try:
            result = drv.parse_string(src_txt, True)
            break
        except ParseError as pe:
            lineno, column = pe.context[1]
            lines = src_txt.splitlines()
            try:
                faulty_line = lines[lineno - 1]
            except IndexError:
                faulty_line = "<line number missing in source>"
            exc = ValueError(f"Cannot parse: {lineno}:{column}: {faulty_line}")
    else:
        raise exc from None
    return result
