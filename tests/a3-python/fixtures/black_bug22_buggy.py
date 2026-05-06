# Faithful recreation of buggy code pattern from black bug 22
# Key patterns:
# 1. Two parallel collections: self.leaves (List) and self.comments (Dict keyed by id())
# 2. self.leaves.pop() called WITHOUT updating self.comments
# 3. Comments referencing the removed leaf become stale/orphaned
# 4. is_comment uses bool(self) instead of len(self.leaves) == 1

from typing import Dict, List, Optional, Tuple, Iterator

STANDALONE_COMMENT = 256
COMMENT = 257
RBRACE = 258
RSQB = 259

LeafID = int
Priority = int


class Leaf:
    def __init__(self, type_val: int, value: str, prefix: str = ""):
        self.type = type_val
        self.value = value
        self.prefix = prefix
        self.parent = None

    def __str__(self):
        return self.prefix + self.value


class BracketTracker:
    def __init__(self):
        self.depth = 0
        self._open = 0

    def mark(self, leaf: Leaf):
        if leaf.value in ("(", "[", "{"):
            self._open += 1
            self.depth += 1
        elif leaf.value in (")", "]", "}"):
            self._open -= 1
            self.depth -= 1

    def any_open_brackets(self) -> bool:
        return self._open > 0


def is_delimiter(leaf: Leaf) -> bool:
    return leaf.value in (",", ";", ":")


class Line:
    """Holds leaves and associated comments for a line of code.

    BUG: self.comments is a Dict[LeafID, Leaf] keyed by id(leaf).
    When self.leaves.pop() removes a leaf, the comment keyed by
    id(removed_leaf) becomes stale — it references a freed object
    whose id may be reused.
    """

    def __init__(self):
        self.depth: int = 0
        self.leaves: List[Leaf] = []
        # BUG: Dict keyed by id() of leaves — becomes stale after .pop()
        self.comments: Dict[LeafID, Leaf] = {}
        self.bracket_tracker: BracketTracker = BracketTracker()
        self.inside_brackets: bool = False
        self.has_for: bool = False

    def append(self, leaf: Leaf, preformatted: bool = False) -> None:
        """Add a new leaf to the end of the line."""
        if not preformatted:
            self.bracket_tracker.mark(leaf)
            self.maybe_remove_trailing_comma(leaf)
            self.maybe_increment_for_loop_variable(leaf)
            if self.maybe_adapt_standalone_comment(leaf):
                return

        if not self.append_comment(leaf):
            self.leaves.append(leaf)

    @property
    def is_comment(self) -> bool:
        """Is this line a standalone comment?

        BUG: Uses bool(self) which is True when *any* leaves exist,
        but should check len(self.leaves) == 1 to ensure it's truly
        a standalone comment line (not a line that starts with a comment
        followed by other leaves).
        """
        return bool(self) and self.leaves[0].type == STANDALONE_COMMENT

    @property
    def is_decorator(self) -> bool:
        return bool(self) and self.leaves[0].value == "@"

    def maybe_remove_trailing_comma(self, closing: Leaf) -> bool:
        """Remove trailing comma if there is one and it's safe.

        BUG: Calls self.leaves.pop() directly without updating
        self.comments dict, leaving orphaned comment entries.
        """
        if not (
            self.leaves
            and self.leaves[-1].value == ","
        ):
            return False

        if closing.type == RBRACE:
            self.leaves.pop()  # BUG: comments not updated
            return True

        if closing.type == RSQB:
            comma = self.leaves[-1]
            if comma.parent and comma.parent.type == 333:  # syms.listmaker
                self.leaves.pop()  # BUG: comments not updated
                return True

        return False

    def maybe_increment_for_loop_variable(self, leaf: Leaf) -> bool:
        return False

    def maybe_adapt_standalone_comment(self, comment: Leaf) -> bool:
        """Hack a standalone comment to act as a trailing comment."""
        if not (
            comment.type == STANDALONE_COMMENT
            and self.bracket_tracker.any_open_brackets()
        ):
            return False
        comment.type = COMMENT
        comment.prefix = '\n' + '    ' * (self.depth + 1)
        return self.append_comment(comment)

    def append_comment(self, comment: Leaf) -> bool:
        """Add an inline comment to the line."""
        if comment.type != COMMENT:
            return False

        try:
            after = id(self.last_non_delimiter())
        except LookupError:
            comment.type = STANDALONE_COMMENT
            comment.prefix = ''
            return False
        else:
            if after in self.comments:
                self.comments[after].value += str(comment)
            else:
                self.comments[after] = comment
            return True

    def last_non_delimiter(self) -> Leaf:
        """Return the last non-delimiter on the line."""
        for i in range(len(self.leaves)):
            last = self.leaves[-i - 1]
            if not is_delimiter(last):
                return last
        raise LookupError("No non-delimiters found")

    def __str__(self) -> str:
        """Render the line."""
        if not self.leaves:
            return "\n"

        indent = "    " * self.depth
        leaves = iter(self.leaves)
        first = next(leaves)
        res = f'{first.prefix}{indent}{first.value}'
        for leaf in leaves:
            res += str(leaf)
        for comment in self.comments.values():
            res += str(comment)
        return res + '\n'

    def __bool__(self) -> bool:
        return bool(self.leaves or self.comments)
