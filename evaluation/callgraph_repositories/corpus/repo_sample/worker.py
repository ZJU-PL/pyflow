from __future__ import annotations

import asyncio

from .api import create_order
from .auth import issue_token
from .config import load_settings
from .utils import retry


async def process_queue(messages: list[dict]) -> list[dict]:
    settings = load_settings()
    token = issue_token("worker-user", settings.token_secret, ttl_seconds=120)
    out: list[dict] = []
    for msg in messages:
        request = dict(msg)
        request["token"] = token

        def run_once() -> dict:
            return create_order(request)

        result = retry(run_once, retries=settings.max_retries)
        out.append(result)
        await asyncio.sleep(0)
    return out
