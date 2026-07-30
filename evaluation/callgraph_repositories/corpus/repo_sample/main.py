from __future__ import annotations

import asyncio

from .worker import process_queue


def run() -> int:
    demo_messages = [
        {"order_id": "o-100", "lines": [{"sku": "A-1", "qty": 2}]},
        {"order_id": "o-101", "lines": [{"sku": "A-1", "qty": 20}]},
    ]
    results = asyncio.run(process_queue(demo_messages))
    failures = [r for r in results if not r.get("ok")]
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(run())
