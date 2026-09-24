from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class AIRole(StrEnum):
    PLANNER = "planner"
    ANALYST = "analyst"
    VERIFIER = "verifier"
    REPORTER = "reporter"
    CLASSIFIER = "classifier"


@dataclass(frozen=True, slots=True)
class BudgetContext:
    run_budget_usd: float
    spent_usd: float

    def can_spend(self, estimate_usd: float) -> bool:
        return self.spent_usd + estimate_usd <= self.run_budget_usd


class AIGateway:
    """Contract only: provider calls are deliberately not wired until credentials/routing are configured."""

    def generate(self, role: AIRole, prompt: str, schema: dict[str, Any], budget: BudgetContext) -> dict[str, Any]:
        if not budget.can_spend(0):
            raise RuntimeError("AI budget is exhausted.")
        raise NotImplementedError("Configure an approved provider adapter before enabling AI generation.")
