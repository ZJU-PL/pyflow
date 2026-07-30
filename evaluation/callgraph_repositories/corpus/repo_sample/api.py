from __future__ import annotations

from dataclasses import asdict

from .config import load_settings
from .auth import verify_token
from .storage import JsonStore
from .domain.orders import LineItem, Order, allocate, total_units
from .domain.inventory import InventoryItem


def create_order(request: dict) -> dict:
    settings = load_settings()
    user = verify_token(request.get("token", ""), settings.token_secret)
    if user is None:
        return {"ok": False, "error": "unauthorized"}

    store = JsonStore(settings.data_dir)
    stock_data = store.read("stock", default={"A-1": {"available": 10}})
    stock = {
        sku: InventoryItem(sku=sku, available=int(data["available"]))
        for sku, data in stock_data.items()
    }
    lines = [LineItem(sku=x["sku"], qty=int(x["qty"])) for x in request.get("lines", [])]
    order = Order(order_id=request["order_id"], lines=lines, user_id=user)

    if not allocate(order, stock):
        return {"ok": False, "error": "out_of_stock"}

    store.write("stock", {k: asdict(v) for k, v in stock.items()})
    store.write(
        f"order-{order.order_id}",
        {
            "order_id": order.order_id,
            "user_id": order.user_id,
            "total_units": total_units(order.lines),
            "lines": [asdict(li) for li in order.lines],
        },
    )
    return {"ok": True, "order_id": order.order_id}
