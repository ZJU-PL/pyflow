"""
AST-based encoding bug detector.

Detects encoding-related anti-patterns that lead to UnicodeDecodeError/UnicodeEncodeError:

1. Hardcoded ASCII encoding as default (should be UTF-8)
   - `encoding = 'ascii'` assignments used as defaults for file reading
2. File open() in write/append mode without explicit encoding parameter
   - `open(path, 'w')` without `encoding='utf-8'`

These patterns cause failures when processing non-ASCII content (e.g., Chinese,
Japanese, accented characters) and are a common source of real-world bugs.

When the source file is a diff fragment that cannot be parsed by the AST parser,
a regex-based fallback scanner is used to detect the same patterns.
"""

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


@dataclass
class EncodingBug:
    """An encoding-related bug found via AST pattern matching."""
    file_path: str
    line_number: int
    function_name: str
    pattern: str  # 'hardcoded_ascii' or 'open_without_encoding'
    reason: str
    confidence: float


def scan_file_for_encoding_bugs(file_path: Path) -> List[EncodingBug]:
    """Scan a single Python file for encoding anti-patterns.

    Uses AST-based analysis when possible, falling back to regex-based
    scanning for diff fragments that cannot be parsed.
    """
    try:
        source = file_path.read_text(encoding='utf-8', errors='ignore')
    except (OSError, UnicodeDecodeError):
        return []

    try:
        tree = ast.parse(source, filename=str(file_path))
    except SyntaxError:
        # File is likely a diff fragment; use regex fallback
        return _scan_source_regex(source, str(file_path))

    visitor = _EncodingBugVisitor(str(file_path))
    visitor.visit(tree)
    return visitor.bugs


def scan_project_for_encoding_bugs(root_path: Path) -> List[EncodingBug]:
    """Scan all Python files in a project for encoding anti-patterns."""
    bugs = []
    for py_file in root_path.rglob('*.py'):
        # Skip test files, setup files, and hidden directories
        parts = py_file.relative_to(root_path).parts
        if any(p.startswith('.') for p in parts):
            continue
        bugs.extend(scan_file_for_encoding_bugs(py_file))
    return bugs


class _EncodingBugVisitor(ast.NodeVisitor):
    """AST visitor that detects encoding anti-patterns."""

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.bugs: List[EncodingBug] = []
        self._current_function: Optional[str] = None
        self._current_class: Optional[str] = None

    def visit_ClassDef(self, node: ast.ClassDef):
        old_class = self._current_class
        self._current_class = node.name
        self.generic_visit(node)
        self._current_class = old_class

    def visit_FunctionDef(self, node: ast.FunctionDef):
        old_func = self._current_function
        if self._current_class:
            self._current_function = f"{self._current_class}.{node.name}"
        else:
            self._current_function = node.name
        self.generic_visit(node)
        self._current_function = old_func

    visit_AsyncFunctionDef = visit_FunctionDef

    # Pattern 1: encoding = 'ascii' assignment used as a default
    def visit_Assign(self, node: ast.Assign):
        for target in node.targets:
            if (isinstance(target, ast.Name)
                    and target.id == 'encoding'
                    and isinstance(node.value, ast.Constant)
                    and isinstance(node.value.value, str)
                    and node.value.value.lower() == 'ascii'):
                self.bugs.append(EncodingBug(
                    file_path=self.file_path,
                    line_number=node.lineno,
                    function_name=self._current_function or '<module>',
                    pattern='hardcoded_ascii',
                    reason=(
                        "Hardcoded encoding='ascii' will raise UnicodeDecodeError "
                        "on non-ASCII input (e.g., UTF-8 characters). "
                        "Use 'utf-8' as the default encoding."
                    ),
                    confidence=0.85,
                ))
        self.generic_visit(node)

    # Pattern 2: open() call for writing without encoding= keyword
    def visit_Call(self, node: ast.Call):
        func_name = _get_call_name(node)
        if func_name == 'open':
            self._check_open_call(node)
        self.generic_visit(node)

    # Pattern 3: open() in read mode without encoding, used with json/yaml parsing
    def visit_With(self, node: ast.With):
        for item in node.items:
            ctx = item.context_expr
            alias = item.optional_vars
            if (isinstance(ctx, ast.Call)
                    and _get_call_name(ctx) == 'open'
                    and alias is not None
                    and isinstance(alias, ast.Name)):
                mode = self._get_open_mode(ctx)
                if mode is None or 'b' in mode:
                    continue
                is_write_mode = any(c in mode for c in ('w', 'a', 'x'))
                if is_write_mode:
                    continue  # Already handled by visit_Call
                has_encoding = any(kw.arg == 'encoding' for kw in ctx.keywords)
                if has_encoding:
                    continue
                # Check if the file handle is passed to a data-parsing function
                if _body_uses_handle_for_parsing(node.body, alias.id):
                    self.bugs.append(EncodingBug(
                        file_path=self.file_path,
                        line_number=ctx.lineno,
                        function_name=self._current_function or '<module>',
                        pattern='open_read_without_encoding_data_parse',
                        reason=(
                            "open() in read mode without encoding= parameter passes "
                            "platform-dependent decoded text to a data parser "
                            "(json.load/yaml.load). On non-UTF-8 platforms this "
                            "causes ValueError. Specify encoding='utf-8'."
                        ),
                        confidence=0.80,
                    ))
        self.generic_visit(node)

    def _check_open_call(self, node: ast.Call):
        # Determine the mode argument
        mode = self._get_open_mode(node)
        if mode is None:
            return  # Can't determine mode; skip

        # Only flag write/append modes (read mode defaults are less dangerous
        # because tokenize.detect_encoding is often used for source files)
        is_write_mode = any(c in mode for c in ('w', 'a', 'x'))
        if not is_write_mode:
            return

        # Check if encoding= keyword is present
        has_encoding = any(
            kw.arg == 'encoding' for kw in node.keywords
        )
        if has_encoding:
            return  # encoding is explicitly specified

        # Binary mode doesn't need encoding
        if 'b' in mode:
            return

        self.bugs.append(EncodingBug(
            file_path=self.file_path,
            line_number=node.lineno,
            function_name=self._current_function or '<module>',
            pattern='open_without_encoding',
            reason=(
                "open() in write mode without encoding= parameter uses "
                "platform-dependent default encoding, which may fail to "
                "encode non-ASCII characters. Specify encoding='utf-8'."
            ),
            confidence=0.80,
        ))

    def _get_open_mode(self, node: ast.Call) -> Optional[str]:
        """Extract the mode string from an open() call."""
        mode_arg = None

        # Check positional arg (second argument)
        if len(node.args) >= 2:
            mode_arg = node.args[1]
        else:
            # Check keyword arg
            for kw in node.keywords:
                if kw.arg == 'mode':
                    mode_arg = kw.value
                    break

        if mode_arg is None:
            return 'r'  # Default mode is 'r' (read)

        if isinstance(mode_arg, ast.Constant) and isinstance(mode_arg.value, str):
            return mode_arg.value

        # Handle ternary: 'w' if cond else 'a' — both branches are write modes
        if isinstance(mode_arg, ast.IfExp):
            body_mode = self._extract_str_constant(mode_arg.body)
            else_mode = self._extract_str_constant(mode_arg.orelse)
            if body_mode is not None and else_mode is not None:
                # Return whichever has a write flag so the caller sees it
                for m in (body_mode, else_mode):
                    if any(c in m for c in ('w', 'a', 'x')):
                        return m
                return body_mode
        return None

    @staticmethod
    def _extract_str_constant(node: ast.expr) -> Optional[str]:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return None


# Data-parsing function names that expect text with a specific encoding
_DATA_PARSE_FUNCS = frozenset({
    'load', 'loads', 'safe_load', 'safe_load_all',
    'read', 'parse', 'decode',
})

# Module prefixes commonly associated with data-parsing
_DATA_PARSE_MODULES = frozenset({
    'json', 'yaml', 'toml', 'tomllib', 'configparser',
    'csv', 'xml', 'html',
})


def _body_uses_handle_for_parsing(body: List[ast.stmt], handle_name: str) -> bool:
    """Check if any statement in *body* passes *handle_name* to a data-parsing call."""
    for node in ast.walk(ast.Module(body=body, type_ignores=[])):
        if not isinstance(node, ast.Call):
            continue
        # Check if handle_name appears as an argument
        handle_used = any(
            isinstance(a, ast.Name) and a.id == handle_name
            for a in node.args
        )
        if not handle_used:
            continue
        # Check if function is a known data-parsing call (e.g., json.load)
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in _DATA_PARSE_FUNCS:
            if isinstance(func.value, ast.Name) and func.value.id in _DATA_PARSE_MODULES:
                return True
            # Also match e.g. `self.parser.load(handle)` — attr is still 'load'
            if func.attr in ('load', 'safe_load'):
                return True
        if isinstance(func, ast.Name) and func.id in _DATA_PARSE_FUNCS:
            return True
    return False


def _get_call_name(node: ast.Call) -> Optional[str]:
    """Extract the function name from a Call node."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


# ── Regex-based fallback for diff fragments ──────────────────────────────────

# Pattern 1: encoding = 'ascii' or encoding = "ascii"
_RE_HARDCODED_ASCII = re.compile(
    r'''encoding\s*=\s*['"]ascii['"]''',
    re.IGNORECASE,
)

# Pattern 2: open(..., 'w'/'a'/'x' ...) without encoding= keyword
# Matches open() calls with a write-mode argument and no encoding= keyword
_RE_OPEN_WRITE = re.compile(
    r'''open\s*\([^)]*(?:['"][waxWAX][^'"]*['"])[^)]*\)''',
)

# Pattern 3: open() in read mode (no mode or 'r') followed by json.load/yaml.load
# on the same indentation block, without encoding= keyword
_RE_OPEN_READ_NO_ENCODING = re.compile(
    r'''with\s+open\s*\(([^)]*)\)\s+as\s+(\w+)''',
)
_RE_DATA_PARSE_CALL = re.compile(
    r'''(?:json|yaml|toml|csv)\.(?:load|safe_load|parse|read)\s*\(''',
)

# Enclosing function heuristic: look for the nearest preceding `def` line
_RE_DEF_LINE = re.compile(r'^\s*def\s+(\w+)\s*\(', re.MULTILINE)


def _find_enclosing_function(source: str, match_start: int) -> str:
    """Return the name of the nearest `def` above *match_start*, or '<module>'."""
    preceding = source[:match_start]
    defs = list(_RE_DEF_LINE.finditer(preceding))
    if defs:
        return defs[-1].group(1)
    return '<module>'


def _scan_source_regex(source: str, file_path: str) -> List[EncodingBug]:
    """Regex-based fallback encoding bug scanner for unparseable fragments."""
    bugs: List[EncodingBug] = []

    for m in _RE_HARDCODED_ASCII.finditer(source):
        lineno = source[:m.start()].count('\n') + 1
        func = _find_enclosing_function(source, m.start())
        bugs.append(EncodingBug(
            file_path=file_path,
            line_number=lineno,
            function_name=func,
            pattern='hardcoded_ascii',
            reason=(
                "Hardcoded encoding='ascii' will raise UnicodeDecodeError "
                "on non-ASCII input (e.g., UTF-8 characters). "
                "Use 'utf-8' as the default encoding."
            ),
            confidence=0.85,
        ))

    for m in _RE_OPEN_WRITE.finditer(source):
        call_text = m.group(0)
        # Skip if encoding= is already specified
        if 'encoding' in call_text:
            continue
        # Skip binary modes
        if re.search(r"""['"][^'"]*b[^'"]*['"]""", call_text):
            continue
        lineno = source[:m.start()].count('\n') + 1
        func = _find_enclosing_function(source, m.start())
        bugs.append(EncodingBug(
            file_path=file_path,
            line_number=lineno,
            function_name=func,
            pattern='open_without_encoding',
            reason=(
                "open() in write mode without encoding= parameter uses "
                "platform-dependent default encoding, which may fail to "
                "encode non-ASCII characters. Specify encoding='utf-8'."
            ),
            confidence=0.80,
        ))

    # Pattern 3: open() in read mode without encoding + data parsing call nearby
    for m in _RE_OPEN_READ_NO_ENCODING.finditer(source):
        open_args = m.group(1)
        handle_name = m.group(2)
        # Skip if encoding= is already specified
        if 'encoding' in open_args:
            continue
        # Skip binary modes
        if re.search(r"""['"][^'"]*b[^'"]*['"]""", open_args):
            continue
        # Skip write modes (already handled by pattern 2)
        if re.search(r"""['"][^'"]*[waxWAX][^'"]*['"]""", open_args):
            continue
        # Look for data-parsing call using the handle in subsequent lines
        after_with = source[m.end():m.end() + 500]
        if handle_name in after_with and _RE_DATA_PARSE_CALL.search(after_with):
            lineno = source[:m.start()].count('\n') + 1
            func = _find_enclosing_function(source, m.start())
            bugs.append(EncodingBug(
                file_path=file_path,
                line_number=lineno,
                function_name=func,
                pattern='open_read_without_encoding_data_parse',
                reason=(
                    "open() in read mode without encoding= parameter passes "
                    "platform-dependent decoded text to a data parser "
                    "(json.load/yaml.load). On non-UTF-8 platforms this "
                    "causes ValueError. Specify encoding='utf-8'."
                ),
                confidence=0.80,
            ))

    return bugs
