"""Backward-compatible import for the former monolithic transfer mixin.

New code should compose the focused binding, expression-resolution, and heap
mutation mixins directly, as :mod:`.engine` does.
"""

from .bindings import _BindingTransferMixin
from .expression_resolution import _ExpressionResolverMixin
from .mutations import _HeapMutationMixin


class _TransferOpsMixin(
    _ExpressionResolverMixin,
    _BindingTransferMixin,
    _HeapMutationMixin,
):
    """Compatibility composition for the former operation transfer mixin."""
