from __future__ import annotations

from pyflow.checker.llm.llm_utils import LLMClient, LLMConfig, LLMResponse, retry_llm_call


def test_call_simple_returns_single_error_prefix(monkeypatch):
    client = LLMClient(LLMConfig(api_key="test"))
    monkeypatch.setattr(
        client,
        "call",
        lambda messages, **kwargs: LLMResponse(
            content="Error: boom", usage={}, model="demo", success=False
        ),
    )

    assert client.call_simple("hello") == "Error: boom"


def test_llm_client_call_wraps_transport_errors():
    client = LLMClient(LLMConfig(api_key="test"))

    class _Session:
        def post(self, *args, **kwargs):
            raise RuntimeError("network down")

    client._session = _Session()
    response = client.call([{"role": "user", "content": "hello"}])

    assert response.success is False
    assert response.content == "Error: network down"


def test_retry_llm_call_retries_before_success():
    attempts = {"count": 0}

    @retry_llm_call(max_retries=3, delay=0)
    def flaky():
        attempts["count"] += 1
        if attempts["count"] < 3:
            raise RuntimeError("retry me")
        return "ok"

    assert flaky() == "ok"
    assert attempts["count"] == 3
