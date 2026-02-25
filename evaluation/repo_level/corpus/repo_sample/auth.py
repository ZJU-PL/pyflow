import hashlib
import hmac
import time


def _digest(data: str, secret: str) -> str:
    return hmac.new(secret.encode("utf-8"), data.encode("utf-8"), hashlib.sha256).hexdigest()


def issue_token(user_id: str, secret: str, ttl_seconds: int = 3600) -> str:
    exp = int(time.time()) + ttl_seconds
    payload = f"{user_id}:{exp}"
    signature = _digest(payload, secret)
    return f"{payload}:{signature}"


def verify_token(token: str, secret: str) -> str | None:
    try:
        user_id, exp_s, signature = token.split(":", 2)
        payload = f"{user_id}:{exp_s}"
        if not hmac.compare_digest(_digest(payload, secret), signature):
            return None
        if int(exp_s) < int(time.time()):
            return None
        return user_id
    except Exception:
        return None
