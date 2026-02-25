from dataclasses import dataclass
from typing import Iterable

from .inventory import InventoryItem, reserve


@dataclass
class LineItem:
    sku: str
    qty: int


@dataclass
class Order:
    order_id: str
    lines: list[LineItem]
    user_id: str


def allocate(order: Order, stock: dict[str, InventoryItem]) -> bool:
    for line in order.lines:
        if line.sku not in stock:
            return False
        if not reserve(stock[line.sku], line.qty):
            return False
    return True


def total_units(lines: Iterable[LineItem]) -> int:
    return sum(max(0, item.qty) for item in lines)
