# Faithful recreation of buggy code pattern from black bug 23
# Key patterns:
# 1. Single grammar used for parsing (python_grammar_no_print_statement)
# 2. ParseError caught and transformed to ValueError
# 3. ValueError raised immediately without trying alternative grammars
# 4. Files using exec() as a function call fail to parse
#
# The actual bug: black couldn't format files containing exec() as a
# function call because the grammar treated 'exec' as a keyword/statement.
# The fix was to try multiple grammar variants in sequence.

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
        In particular, if 'exec' is a keyword in the grammar but
        the source uses exec() as a function call, parsing fails.
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


def lib2to3_parse(src_txt: str):
    """Given a string with source, return the lib2to3 Node.

    BUG: Uses only python_grammar_no_print_statement.
    If parsing fails with this single grammar, immediately raises ValueError.
    Does NOT try alternative grammars (e.g. one without 'exec' as keyword).

    For example, code with ``exec("cmd", globals(), locals())`` fails because
    the grammar still has 'exec' as a keyword (statement), so the parser
    can't handle exec-as-function-call syntax.
    """
    grammar = python_grammar_no_print_statement
    drv = Driver(grammar, pytree_convert)
    if src_txt[-1] != '\n':
        nl = '\r\n' if '\r\n' in src_txt[:1024] else '\n'
        src_txt += nl
    try:
        result = drv.parse_string(src_txt, True)
    except ParseError as pe:
        lineno, column = pe.context[1]
        lines = src_txt.splitlines()
        try:
            faulty_line = lines[lineno - 1]
        except IndexError:
            faulty_line = "<line number missing in source>"
        raise ValueError(f"Cannot parse: {lineno}:{column}: {faulty_line}") from None
    return result
