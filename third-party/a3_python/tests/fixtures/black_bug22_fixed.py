# Faithful recreation of fixed code pattern from black bug 22
# Key fixes:
# 1. self.comments changed from Dict[LeafID, Leaf] to List[Tuple[Index, Leaf]]
# 2. self.leaves.pop() replaced with self.remove_trailing_comma() which syncs comments
# 3. is_comment checks len(self.leaves) == 1 instead of bool(self)
# 4. append_safe() added to prevent invalid standalone comment structures

from typing import Dict, List, Optional, Tuple, Iterator

STANDALONE_COMMENT = 256
COMMENT = 257
RBRACE = 258
RSQB = 259

Index = int
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

    FIXED: self.comments is now List[Tuple[Index, Leaf]] keyed by integer
    index into self.leaves. remove_trailing_comma() adjusts the indices
    when a leaf is removed.
    """

    def __init__(self):
        self.depth: int = 0
        self.leaves: List[Leaf] = []
        # FIXED: List of (index, comment) tuples — indices adjusted on removal
        self.comments: List[Tuple[Index, Leaf]] = []
        self.bracket_tracker: BracketTracker = BracketTracker()
        self.inside_brackets: bool = False
        self.has_for: bool = False

    def append(self, leaf: Leaf, preformatted: bool = False) -> None:
        """Add a new leaf to the end of the line."""
        if not preformatted:
            self.bracket_tracker.mark(leaf)
            self.maybe_remove_trailing_comma(leaf)
            self.maybe_increment_for_loop_variable(leaf)

        if not self.append_comment(leaf):
            self.leaves.append(leaf)

    def append_safe(self, leaf: Leaf, preformatted: bool = False) -> None:
        """Like append() but disallow invalid standalone comment structure."""
        if self.bracket_tracker.depth == 0:
            if self.is_comment:
                raise ValueError("cannot append to standalone comments")
            if self.leaves and leaf.type == STANDALONE_COMMENT:
                raise ValueError(
                    "cannot append standalone comments to a populated line"
                )
        self.append(leaf, preformatted=preformatted)

    @property
    def is_comment(self) -> bool:
        """Is this line a standalone comment?

        FIXED: Uses len(self.leaves) == 1 to ensure exactly one leaf.
        """
        return len(self.leaves) == 1 and self.leaves[0].type == STANDALONE_COMMENT

    @property
    def is_decorator(self) -> bool:
        return bool(self) and self.leaves[0].value == "@"

    @property
    def contains_standalone_comments(self) -> bool:
        """If so, needs to be split before emitting."""
        for leaf in self.leaves:
            if leaf.type == STANDALONE_COMMENT:
                return True
        return False

    def maybe_remove_trailing_comma(self, closing: Leaf) -> bool:
        """Remove trailing comma if there is one and it's safe.

        FIXED: Calls self.remove_trailing_comma() which adjusts comments.
        """
        if not (
            self.leaves
            and self.leaves[-1].value == ","
        ):
            return False

        if closing.type == RBRACE:
            self.remove_trailing_comma()  # FIXED
            return True

        if closing.type == RSQB:
            comma = self.leaves[-1]
            if comma.parent and comma.parent.type == 333:  # syms.listmaker
                self.remove_trailing_comma()  # FIXED
                return True

        return False

    def maybe_increment_for_loop_variable(self, leaf: Leaf) -> bool:
        return False

    def append_comment(self, comment: Leaf) -> bool:
        """Add an inline or standalone comment to the line."""
        if (
            comment.type == STANDALONE_COMMENT
            and self.bracket_tracker.any_open_brackets()
        ):
            comment.prefix = ''
            return False

        if comment.type != COMMENT:
            return False

        after = len(self.leaves) - 1
        if after == -1:
            comment.type = STANDALONE_COMMENT
            comment.prefix = ''
            return False
        else:
            self.comments.append((after, comment))
            return True

    def comments_after(self, leaf: Leaf) -> Iterator[Leaf]:
        """Generate comments that should appear directly after `leaf`."""
        for _leaf_index, _leaf in enumerate(self.leaves):
            if leaf is _leaf:
                break
        else:
            return

        for index, comment_after in self.comments:
            if _leaf_index == index:
                yield comment_after

    def remove_trailing_comma(self) -> None:
        """Remove the trailing comma and adjust comment indices."""
        comma_index = len(self.leaves) - 1
        for i in range(len(self.comments)):
            comment_index, comment = self.comments[i]
            if comment_index == comma_index:
                self.comments[i] = (comma_index - 1, comment)
        self.leaves.pop()

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
        for _, comment in self.comments:
            res += str(comment)
        return res + '\n'

    def __bool__(self) -> bool:
        return bool(self.leaves or self.comments)
