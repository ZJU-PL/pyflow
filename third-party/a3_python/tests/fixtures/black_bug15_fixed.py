# Faithful recreation of fixed code pattern from black bug 15
# Key changes from buggy version:
# 1. FormatError/FormatOn/FormatOff exception classes removed entirely
# 2. UnformattedLines class removed entirely
# 3. EmptyLineTracker no longer checks isinstance(current_line, UnformattedLines)
# 4. Format on/off handling is done differently (not via exceptions)

import token
from typing import Iterator, List, Optional, Union

class Leaf:
    def __init__(self, type_val, value, prefix=""):
        self.type = type_val
        self.value = value
        self.prefix = prefix


class Node:
    def __init__(self, type_val, children):
        self.type = type_val
        self.children = children


def generate_comments(leaf: Leaf) -> Iterator[Leaf]:
    """Generate comments from a leaf's prefix.

    In the fixed version, this no longer raises exceptions for control flow.
    Format on/off is handled by the caller via direct string checks.
    """
    prefix = leaf.prefix
    nlines = 0
    for index, comment_text in enumerate(prefix.split("\n")):
        comment_text = comment_text.strip()
        if comment_text and comment_text.startswith("#"):
            yield Leaf(token.COMMENT, comment_text)
        nlines += 1


class Line:
    """Holds a list of leaves to be formatted."""

    def __init__(self) -> None:
        self.leaves: List[Leaf] = []
        self.comments: List[Leaf] = []
        self.depth: int = 0

    def append(self, leaf: Leaf, preformatted: bool = False) -> None:
        """Add a new leaf to the end of the line."""
        self.leaves.append(leaf)

    def append_comment(self, comment: Leaf) -> bool:
        """Add a comment to the line."""
        self.comments.append(comment)
        return True

    def maybe_remove_trailing_comma(self, closing: Leaf) -> bool:
        """Maybe remove trailing comma."""
        if self.leaves and self.leaves[-1].value == ",":
            self.leaves.pop()
            return True
        return False

    def maybe_increment_for_loop_variable(self, leaf: Leaf) -> bool:
        """Maybe handle for loop variable."""
        return False

    def __bool__(self) -> bool:
        return bool(self.leaves or self.comments)


class EmptyLineTracker:
    """Provides a stateful method that returns the number of potential extra
    empty lines needed before and after the currently processed line.
    """

    def __init__(self) -> None:
        self.previous_after = 0

    def maybe_empty_lines(self, current_line: Line) -> tuple:
        """Return the number of extra empty lines before and after the line.

        This is for separating def, async def and class with extra empty
        lines (two on module-level).
        """
        return self._maybe_empty_lines(current_line)

    def _maybe_empty_lines(self, current_line: Line) -> tuple:
        return 1, 0
