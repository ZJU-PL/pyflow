from .domain.orders import *  # noqa: F403 - intentional star import for resolver regression


def supported_exports() -> list[str]:
    # Purposefully references imported names so star import is semantically relevant.
    return [name for name in ("Order", "LineItem", "allocate", "total_units")]
