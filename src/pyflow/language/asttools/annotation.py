"""
Annotation utilities for AST nodes.

This module provides utilities for creating, merging, and manipulating
contextual annotations that can be attached to AST nodes. Annotations
support context-aware data that varies across different execution contexts.
"""

from pyflow.util import canonical
import collections

__all__ = [
    "noMod",
    "remapContextual",
    "makeContextualAnnotation",
    "annotationSet",
    "mergeContextualAnnotation",
    "ContextualAnnotation",
]

# Sentinel value indicating no modification
noMod = canonical.Sentinel("<no mod>")

# Named tuple for contextual annotations
# - merged: Combined annotation data from all contexts
# - context: Tuple of context-specific annotation data
ContextualAnnotation = collections.namedtuple("ContextualAnnotation", "merged context")


def annotationSet(data):
    """Create a normalized annotation set from data.

    Converts input data to a sorted tuple for use as an annotation set.
    This ensures consistent representation and enables efficient comparison.

    Args:
        data: Iterable of annotation items.

    Returns:
        Sorted tuple of annotation items. If items are not sortable,
        returns a tuple sorted by id() as a fallback.
    """
    try:
        return tuple(sorted(data))
    except TypeError:
        # Fallback for non-sortable items (e.g., ObjectNode instances)
        # Use id() as a stable sorting key
        return tuple(sorted(data, key=lambda x: (type(x).__name__, id(x))))


def makeContextualAnnotation(cdata):
    """Create a contextual annotation from context-specific data.

    Merges data from multiple contexts into a single contextual annotation.
    Uses caching to pool identical annotation sets for memory efficiency.

    Args:
        cdata: List of sets/iterables, one per context.

    Returns:
        ContextualAnnotation with merged data and context-specific data.

    Example:
        cdata = [{'x', 'y'}, {'y', 'z'}]
        ann = makeContextualAnnotation(cdata)
        # ann.merged = ('x', 'y', 'z')
        # ann.context = (('x', 'y'), ('y', 'z'))
    """
    merged = set()
    for data in cdata:
        merged.update(data)
    merged = annotationSet(merged)

    # Cache used to pool identical data for memory efficiency
    cache = {}
    return ContextualAnnotation(
        cache.setdefault(merged, merged),
        tuple([cache.setdefault(data, data) for data in cdata]),
    )


def mergeAnnotationSet(a, b):
    """Merge two annotation sets.

    Args:
        a: First annotation set (iterable).
        b: Second annotation set (iterable).

    Returns:
        New annotation set containing items from both inputs.
    """
    s = set(a)
    s.update(b)
    return annotationSet(s)


def mergeContextualAnnotation(a, b):
    """Merge two contextual annotations.

    Combines annotations from two contextual annotations, merging
    corresponding contexts. Handles None inputs gracefully.

    Args:
        a: First contextual annotation, or None.
        b: Second contextual annotation, or None.

    Returns:
        Merged contextual annotation, or the non-None input if one is None.
    """
    if a is None:
        return b
    elif b is None:
        return a
    else:
        return makeContextualAnnotation(
            [mergeAnnotationSet(ca, cb) for ca, cb in zip(a.context, b.context)]
        )


def remapContextual(cdata, remap, translator=None):
    """Remap contextual annotation data according to a mapping.

    Transforms contextual annotations by remapping contexts according to
    the provided mapping. Supports merging multiple source contexts into
    a single target context, and optional translation of annotation items.

    Args:
        cdata: ContextualAnnotation to remap, or None.
        remap: List of remapping specifications. Each element can be:
            - An integer >= 0: Map from source context at that index
            - A tuple/list of integers: Merge multiple source contexts
            - An integer < 0: Create empty context
        translator: Optional function to translate annotation items.

    Returns:
        New ContextualAnnotation with remapped contexts, or None if input is None.

    Example:
        # Original: contexts [{'a'}, {'b'}, {'c'}]
        # Remap: [0, (1, 2), -1]
        # Result: contexts [{'a'}, {'b', 'c'}, {}]
    """
    if cdata is None:
        return None

    cout = []

    for i in remap:
        if isinstance(i, (tuple, list)):
            if len(i) == 0:
                # No contexts to map - create empty context
                cout.append(())
                continue
            elif len(i) > 1:
                # Merge multiple source contexts into one target context
                data = set()
                for src in i:
                    if src >= 0:
                        if translator:
                            data.update([translator(item) for item in cdata[1][src]])
                        else:
                            data.update(cdata[1][src])
                data = annotationSet(data)
                cout.append(data)
                continue
            else:
                # Single context in tuple - extract it
                i = i[0]
                # Fall through to single context handling

        # Handle single context mapping
        if i >= 0:
            data = cdata[1][i]
            if translator:
                data = annotationSet([translator(item) for item in data])
        else:
            # Negative index means empty context
            data = ()

        cout.append(data)

    return makeContextualAnnotation(cout)


class Annotation(object):
    """Base class for AST node annotations.

    Annotations are immutable objects that can be attached to AST nodes
    to store metadata. They support rewriting to create new annotations
    with modified fields.

    Subclasses should define __slots__ with the annotation field names.
    Only single-level inheritance is supported (due to __slots__ limitations).
    """

    __slots__ = ()

    def rewrite(self, **kwds):
        """Create a new annotation with modified fields.

        Creates a new annotation instance of the same type with specified
        fields updated. Unspecified fields retain their current values.

        Args:
            **kwds: Keyword arguments specifying fields to modify.

        Returns:
            New annotation instance with modified fields.

        Raises:
            AssertionError: If an unknown field name is specified.

        Example:
            ann = MyAnnotation(x=1, y=2)
            new_ann = ann.rewrite(x=3)  # Creates MyAnnotation(x=3, y=2)
        """
        # Assume only one level of inheritance. (__slots__ gets masked otherwise)
        slots = self.__slots__

        # Make sure extraneous keywords were not given.
        for name in kwds.keys():
            assert name in slots, name

        # Fill in unspecified names with the old values
        for name in slots:
            if name not in kwds:
                kwds[name] = getattr(self, name)

        return type(self)(**kwds)

    def __repr__(self):
        """Get string representation of annotation.

        Returns:
            String showing annotation type and all field values.
        """
        parts = []
        slots = self.__slots__
        for name in slots:
            parts.append("%s=%r" % (name, getattr(self, name)))

        return "%s(%s)" % (type(self).__name__, ", ".join(parts))
