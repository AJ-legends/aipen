"""Role-based AI gateway: routing, structured-output enforcement, cost ledger."""
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

import httpx

from app.ai.config import AIConfig, estimate_usd, load_config
from app.ai.roles import AIRole
from app.ai.router import (  # noqa: F401  # resolve_model re-exported
    candidates_for,
    downgrade_on_budget_pressure,
    resolve_model,
)
from app.core.db import connection, json_value

__all__ = ["AIGateway", "AIRole", "BudgetContext"]


@dataclass(frozen=True, slots=True)
class BudgetContext:
    run_budget_usd: float
    spent_usd: float

    def can_spend(self, estimate_usd: float) -> bool:
        return self.spent_usd + estimate_usd <= self.run_budget_usd


class AIGateway:
    def __init__(self, database_path: Path | None = None, config: AIConfig | None = None) -> None:
        from app.core.config import settings as default_settings

        self.database_path = database_path or default_settings.data_dir / default_settings.database_name
        self.config = config or load_config()

    def global_spent_usd(self) -> float:
        with connection(self.database_path) as db:
            row = db.execute("SELECT COALESCE(SUM(usd), 0) AS total FROM cost_ledger").fetchone()
        return float(row["total"]) if row else 0.0

    def generate(
        self,
        role: AIRole,
        prompt: str,
        schema: dict[str, Any],
        budget: BudgetContext,
        run_id: UUID | None = None,
        author_model: str | None = None,
        premium: bool = False,
        transport: httpx.BaseTransport | None = None,
    ) -> dict[str, Any]:
        from app.ai import providers as provider_adapter

        if not budget.can_spend(0):
            raise RuntimeError("AI budget is exhausted.")
        if not self.config.configured:
            raise provider_adapter.ProviderError("AGENTROUTER_API_KEY is not set; AI generation is disabled.")
        chain = candidates_for(role, self.config, author_model, premium)
        if not chain:
            chain = (self.config.volume_model,)
        if self.global_spent_usd() > 0.7 * self.config.global_budget_usd and downgrade_on_budget_pressure(role):
            chain = (self.config.volume_model, *[model for model in chain if model != self.config.volume_model])
        required = tuple(schema.get("required", []))
        system = f"You are the {role.value} role. Respond with a single JSON object containing exactly: {', '.join(required)}."
        last_error: Exception | None = None
        for attempt, model in enumerate(chain):
            if attempt > 0:
                self._audit(run_id, "provider_fallback", {"role": role.value, "from": chain[attempt - 1], "to": model})
            try:
                completion = provider_adapter.complete(self.config, model, system, prompt, transport)
            except provider_adapter.ProviderError as error:
                last_error = error
                continue
            try:
                document = provider_adapter.parse_structured(completion.content, required)
            except provider_adapter.ProviderError:
                try:
                    retry = provider_adapter.complete(self.config, model, system, prompt + "\n\nRespond with JSON only.", transport)
                    document = provider_adapter.parse_structured(retry.content, required)
                except provider_adapter.ProviderError as error:
                    last_error = error
                    continue
                completion = retry
            cost = estimate_usd(completion.model, completion.input_tokens, completion.output_tokens)
            self._record_cost(run_id, role, completion.model, completion.input_tokens, completion.output_tokens, cost)
            return {"model": completion.model, "cost_usd": cost, "output": document}
        raise provider_adapter.ProviderError(f"All provider candidates failed: {last_error}") from last_error

    def _audit(self, run_id: UUID | None, event: str, detail: dict[str, object]) -> None:
        with connection(self.database_path) as db:
            db.execute(
                "INSERT INTO audit_log (ts, actor, event, detail) VALUES (?, ?, ?, ?)",
                (datetime.now(UTC).isoformat(), "system", event, json_value({"run_id": str(run_id) if run_id else None, **detail})),
            )

    def _record_cost(self, run_id: UUID | None, role: AIRole, model: str, input_tokens: int, output_tokens: int, cost: float) -> None:
        provider = model.split("/")[0] if "/" in model else model.split("-")[0]
        with connection(self.database_path) as db:
            db.execute(
                "INSERT INTO cost_ledger (ts, run_id, role, provider, model, input_tokens, output_tokens, usd) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (datetime.now(UTC).isoformat(), str(run_id) if run_id else None, role.value, provider, model, input_tokens, output_tokens, cost),
            )
