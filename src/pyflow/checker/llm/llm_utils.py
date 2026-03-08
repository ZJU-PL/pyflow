"""
Independent LLM utilities for API communication and common operations.
No dependencies on pyflow framework.
"""

import json
import time
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass


@dataclass
class LLMConfig:
    """Configuration for LLM API calls."""

    api_key: str
    model: str = "gpt-3.5-turbo"
    temperature: float = 0.7
    max_tokens: int = 1000
    base_url: str = "https://api.openai.com/v1"


@dataclass
class LLMResponse:
    """Standardized response from LLM APIs."""

    content: str
    usage: Dict[str, int]
    model: str
    success: bool = True


class LLMClient:
    """Independent LLM client for API communication."""

    def __init__(self, config: LLMConfig):
        self.config = config
        self._session = None

    def _get_session(self):
        """Lazy import and setup of requests session."""
        if self._session is None:
            try:
                import requests

                self._session = requests.Session()
                self._session.headers.update(
                    {
                        "Authorization": f"Bearer {self.config.api_key}",
                        "Content-Type": "application/json",
                    }
                )
            except ImportError:
                raise ImportError("requests library required for LLM API calls")
        return self._session

    def call(self, messages: List[Dict[str, str]], **kwargs) -> LLMResponse:
        """Make a call to the LLM API."""
        session = self._get_session()

        payload = {
            "model": kwargs.get("model", self.config.model),
            "messages": messages,
            "temperature": kwargs.get("temperature", self.config.temperature),
            "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
        }

        try:
            response = session.post(
                f"{self.config.base_url}/chat/completions", json=payload, timeout=30
            )
            response.raise_for_status()

            data = response.json()
            return LLMResponse(
                content=data["choices"][0]["message"]["content"],
                usage=data["usage"],
                model=data["model"],
                success=True,
            )
        except Exception as e:
            return LLMResponse(
                content=f"Error: {str(e)}",
                usage={},
                model=self.config.model,
                success=False,
            )

    def call_simple(self, prompt: str, **kwargs) -> str:
        """Simple call with single prompt."""
        messages = [{"role": "user", "content": prompt}]
        response = self.call(messages, **kwargs)
        return response.content


def retry_llm_call(max_retries: int = 3, delay: float = 1.0):
    """Decorator for retrying LLM calls on failure."""

    def decorator(func):
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    if attempt == max_retries - 1:
                        raise e
                    time.sleep(delay * (2**attempt))  # Exponential backoff
            return None

        return wrapper

    return decorator


def format_bug_report(report: Dict[str, Any]) -> str:
    """Format a bug report for LLM processing."""
    return f"""
Bug Report:
Title: {report.get('title', 'N/A')}
Description: {report.get('description', 'N/A')}
Severity: {report.get('severity', 'N/A')}
Component: {report.get('component', 'N/A')}
Steps to Reproduce: {report.get('steps', 'N/A')}
Expected Result: {report.get('expected', 'N/A')}
Actual Result: {report.get('actual', 'N/A')}
"""


def format_code_snippet(code: str, language: str = "python") -> str:
    """Format code snippet for LLM processing."""
    return f"```{language}\n{code}\n```"
