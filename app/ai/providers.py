"""AgentRouter adapter: OpenAI-compatible chat completions over httpx.

The API key travels only in the Authorization header. Errors never echo it.
Retry policy (R4): one backoff retry on 429/5xx/transport errors, then the
caller falls back to the next model in the role's chain.
"""
import json
import time
from dataclasses import dataclass

import httpx

from app.ai.config import AIConfig

RETRYABLE_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})


@dataclass(frozen=True, slots=True)
class Completion:
    content: str
    model: str
    input_tokens: int
    output_tokens: int


class ProviderError(RuntimeError):
    pass


class RetryableError(ProviderError):
    pass


def _strip_fences(text: str) -> str:
    stripped = text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        stripped = "\n".join(lines)
    return stripped


def complete(
    config: AIConfig,
    model: str,
    system: str,
    user: str,
    transport: httpx.BaseTransport | None = None,
    backoff_seconds: float = 1.0,
) -> Completion:
    if not config.configured:
        raise ProviderError("AGENTROUTER_API_KEY is not set; AI generation is disabled.")
    payload = {
        "model": model,
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        "temperature": 0.2,
        "response_format": {"type": "json_object"},
    }
    attempts = 0
    while True:
        attempts += 1
        try:
            with httpx.Client(base_url=config.base_url, timeout=config.request_timeout_seconds, transport=transport) as client:
                response = client.post(
                    "/chat/completions",
                    headers={"Authorization": f"Bearer {config.api_key}"},  # key stays in the header; never logged
                    json=payload,
                )
        except httpx.HTTPError as error:
            if attempts < 2:
                time.sleep(backoff_seconds)
                continue
            raise RetryableError(f"Provider request failed: {type(error).__name__}") from error
        if response.status_code in RETRYABLE_STATUS:
            if attempts < 2:
                time.sleep(backoff_seconds)
                continue
            raise RetryableError(f"Provider returned HTTP {response.status_code}.")
        if response.status_code >= 400:
            raise ProviderError(f"Provider returned HTTP {response.status_code}.")
        break
    try:
        document = response.json()
        content = document["choices"][0]["message"]["content"]
        usage = document.get("usage", {})
    except (ValueError, KeyError, IndexError, TypeError) as error:
        raise ProviderError("Provider returned an unreadable response.") from error
    if not isinstance(content, str):
        raise ProviderError("Provider returned a non-text completion.")
    return Completion(
        content=_strip_fences(content),
        model=document.get("model", model),
        input_tokens=int(usage.get("prompt_tokens", 0)),
        output_tokens=int(usage.get("completion_tokens", 0)),
    )


def parse_structured(content: str, required: tuple[str, ...]) -> dict[str, object]:
    try:
        document = json.loads(content)
    except ValueError as error:
        raise ProviderError("Completion was not valid JSON.") from error
    if not isinstance(document, dict):
        raise ProviderError("Completion JSON was not an object.")
    missing = [key for key in required if key not in document]
    if missing:
        raise ProviderError(f"Completion is missing required keys: {sorted(missing)}.")
    return document
