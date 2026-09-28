"""AI provider configuration from the environment. Keys are never logged."""
import os
from dataclasses import dataclass

from dotenv import load_dotenv


def _models(name: str, default: str) -> tuple[str, ...]:
    raw = os.environ.get(name, default)
    return tuple(part.strip() for part in raw.split(",") if part.strip())


@dataclass(frozen=True, slots=True)
class AIConfig:
    """All values overridable via environment; no secrets stored here."""

    api_key: str = ""
    base_url: str = "https://agentrouter.org/v1"
    volume_model: str = "deepseek-chat"
    premium_model: str = "claude-3-5-sonnet-latest"
    verify_models: tuple[str, ...] = ("deepseek-chat", "claude-3-5-sonnet-latest", "gpt-4o-mini")
    global_budget_usd: float = 50.0
    request_timeout_seconds: float = 90.0

    @property
    def configured(self) -> bool:
        return bool(self.api_key)


def load_config() -> AIConfig:
    load_dotenv()  # repo-root .env if present; real env vars always win
    try:
        budget = float(os.environ.get("AIPEN_GLOBAL_BUDGET_USD", "50.0"))
    except ValueError:
        budget = 50.0
    try:
        timeout = float(os.environ.get("AIPEN_AI_TIMEOUT_S", "90.0"))
    except ValueError:
        timeout = 90.0
    return AIConfig(
        api_key=os.environ.get("AGENTROUTER_API_KEY", ""),
        base_url=os.environ.get("AGENTROUTER_BASE_URL", "https://agentrouter.org/v1"),
        volume_model=os.environ.get("AIPEN_VOLUME_MODEL", "deepseek-chat"),
        premium_model=os.environ.get("AIPEN_PREMIUM_MODEL", "claude-3-5-sonnet-latest"),
        verify_models=_models("AIPEN_VERIFY_MODELS", "deepseek-chat,claude-3-5-sonnet-latest,gpt-4o-mini"),
        global_budget_usd=budget,
        request_timeout_seconds=timeout,
    )


# Conservative per-1M-token USD estimates by model-name fragment. Real billing
# comes from the provider; ledger rows are cost-control estimates, not invoices.
PRICE_TABLE: tuple[tuple[str, float, float], ...] = (
    ("deepseek", 0.14, 0.28),
    ("gpt-4o-mini", 0.15, 0.60),
    ("gpt-4o", 2.50, 10.00),
    ("claude-3-5-sonnet", 3.00, 15.00),
    ("claude-sonnet", 3.00, 15.00),
    ("claude-3-5-haiku", 0.80, 4.00),
)


def estimate_usd(model: str, input_tokens: int, output_tokens: int) -> float:
    lowered = model.lower()
    for fragment, price_in, price_out in PRICE_TABLE:
        if fragment in lowered:
            return input_tokens / 1_000_000 * price_in + output_tokens / 1_000_000 * price_out
    return (input_tokens + output_tokens) / 1_000_000 * 1.00
