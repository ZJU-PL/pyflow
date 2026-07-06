# Faithful recreation of buggy code pattern from black bug 15
# Key patterns:
# 1. Exception subclasses used for control flow (FormatOn/FormatOff)
# 2. Subclass method catches exception, mutates self.leaves, then re-raises
# 3. generate_comments() raises exceptions as signals, not errors
# 4. UnformattedLines overrides with NotImplementedError / no-op returns

import token
from typing import Iterator, List, Optional, Type

class Leaf:
    def __init__(self, type_val, value, prefix=""):
        self.type = type_val
        self.value = value
        self.prefix = prefix


class FormatError(Exception):
    """Base exception for `# fmt: on` and `# fmt: off` handling.

    It holds the number of bytes of the prefix consumed before the format
    control comment appeared.
    """

    def __init__(self, consumed: int) -> None:
        super().__init__(consumed)
        self.consumed = consumed

    def trim_prefix(self, leaf: Leaf) -> None:
        leaf.prefix = leaf.prefix[self.consumed:]

    def leaf_from_consumed(self, leaf: Leaf) -> Leaf:
        """Returns a new Leaf from the consumed part of the prefix."""
        unformatted_prefix = leaf.prefix[:self.consumed]
        return Leaf(token.NEWLINE, unformatted_prefix)


class FormatOn(FormatError):
    """Found a comment like `# fmt: on` in the file."""


class FormatOff(FormatError):
    """Found a comment like `# fmt: off` in the file."""


def generate_comments(leaf: Leaf) -> Iterator[Leaf]:
    """Generate comments from a leaf's prefix.

    Raises FormatOn or FormatOff when a format control comment is found.
    """
    prefix = leaf.prefix
    nlines = 0
    for index, comment in enumerate(prefix.split("\n")):
        comment = comment.strip()
        if comment.startswith("# fmt: on"):
            raise FormatOn(index)
        elif comment.startswith("# fmt: off"):
            raise FormatOff(index)
        if comment and comment.startswith("#"):
            yield Leaf(token.COMMENT, comment)
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


class UnformattedLines(Line):
    """Just like Line but stores lines which aren't reformatted."""

    def append(self, leaf: Leaf, preformatted: bool = True) -> None:
        """Just add a new leaf to the end of the lines.

        The preformatted argument is ignored.

        Keeps track of indentation depth, which is useful when the user
        says # fmt: on. Otherwise, doesn't do anything with the leaf.
        """
        try:
            list(generate_comments(leaf))
        except FormatOn as f_on:
            self.leaves.append(f_on.leaf_from_consumed(leaf))
            raise

        self.leaves.append(leaf)
        if leaf.type == token.INDENT:
            self.depth += 1
        elif leaf.type == token.DEDENT:
            self.depth -= 1

    def __str__(self) -> str:
        """Render unformatted lines from leaves which were added with append().

        depth is not used for indentation in this case.
        """
        if not self:
            return "\n"

        res = ""
        for leaf in self.leaves:
            res += str(leaf)
        return res

    def append_comment(self, comment: Leaf) -> bool:
        """Not implemented in this class. Raises NotImplementedError."""
        raise NotImplementedError("Unformatted lines don't store comments separately.")

    def maybe_remove_trailing_comma(self, closing: Leaf) -> bool:
        """Does nothing and returns False."""
        return False

    def maybe_increment_for_loop_variable(self, leaf: Leaf) -> bool:
        """Does nothing and returns False."""
        return False


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
        if isinstance(current_line, UnformattedLines):
            return 0, 0

        return self._maybe_empty_lines(current_line)

    def _maybe_empty_lines(self, current_line: Line) -> tuple:
        return 1, 0
