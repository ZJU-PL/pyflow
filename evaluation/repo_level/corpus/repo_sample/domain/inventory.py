from dataclasses import dataclass


@dataclass
class InventoryItem:
    sku: str
    available: int


def reserve(item: InventoryItem, qty: int) -> bool:
    if qty <= 0:
        return False
    if item.available < qty:
        return False
    item.available -= qty
    return True
