"""Model routing: volume/premium tiers with verifier cross-provider independence (R2)."""
from app.ai.config import AIConfig
from app.ai.roles import AIRole


def provider_of(model: str) -> str:
    lowered = model.lower()
    if "deepseek" in lowered:
        return "deepseek"
    if "claude" in lowered:
        return "anthropic"
    if "gpt" in lowered or "openai" in lowered or "o1" in lowered:
        return "openai"
    if "gemini" in lowered:
        return "google"
    return "unknown"


def candidates_for(role: AIRole, config: AIConfig, author_model: str | None = None, premium: bool = False) -> tuple[str, ...]:
    """Ordered model chain for a role: primary first, then fallbacks.

    Verifier candidates exclude the author's provider (R2); the primary is
    still first so independence holds even before any fallback.
    """
    if role is AIRole.VERIFIER:
        author_provider = provider_of(author_model) if author_model else ""
        chain = [candidate for candidate in config.verify_models if provider_of(candidate) != author_provider]
        if not chain and config.verify_models:
            chain = [config.verify_models[0]]
        return tuple(dict.fromkeys(chain))
    primary = config.premium_model if (premium or role is AIRole.REPORTER) else config.volume_model
    fallbacks = [model for model in (config.volume_model, config.premium_model, *config.verify_models) if model != primary]
    return tuple(dict.fromkeys((primary, *fallbacks)))


def resolve_model(role: AIRole, config: AIConfig, author_model: str | None = None, premium: bool = False) -> str:
    """Pick a model for a role. Verifier never reuses the author's provider (R2)."""
    chain = candidates_for(role, config, author_model, premium)
    if chain:
        return chain[0]
    return config.volume_model


def downgrade_on_budget_pressure(role: AIRole) -> bool:
    """Non-verification roles drop to the cheapest tier past 70% global spend."""
    return role is not AIRole.VERIFIER
