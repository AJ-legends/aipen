from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, HttpUrl, field_validator


class RiskTier(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class DecisionType(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    NEEDS_APPROVAL = "needs_approval"


class RunState(StrEnum):
    CREATED = "created"
    RECON = "recon"
    DISCOVERY = "discovery"
    SIGNALS = "signals"
    ANALYZE = "analyze"
    PLAN = "plan"
    ACT = "act"
    VERIFY = "verify"
    REPORTING = "reporting"
    PAUSED = "paused"
    ABORTED = "aborted"
    COMPLETED = "completed"


class ScopeConfig(BaseModel):
    allowed_domains: list[str] = Field(min_length=1)
    allowed_ips: list[str] = Field(default_factory=list)
    allowed_ports: list[int] = Field(default_factory=lambda: [80, 443])
    allowed_path_prefixes: list[str] = Field(default_factory=lambda: ["/"])
    excluded_paths: list[str] = Field(default_factory=list)
    rate_limit_per_second: float = Field(default=10, gt=0, le=100)
    allowed_test_types: list[str] = Field(default_factory=lambda: ["recon", "discovery"])
    forbidden_actions: list[str] = Field(default_factory=lambda: ["state_change"])

    @field_validator("allowed_domains")
    @classmethod
    def normalize_domains(cls, values: list[str]) -> list[str]:
        return [value.lower().strip().rstrip(".") for value in values]


class TargetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    base_urls: list[HttpUrl] = Field(min_length=1)
    scope: ScopeConfig
    hitl_enabled: bool = True
    budget_cap_usd: float = Field(default=0.50, gt=0, le=100)


class TargetSummary(BaseModel):
    id: UUID
    name: str
    base_urls: list[str]
    archived: bool
    created_at: datetime


class ProposedAction(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    target_url: HttpUrl
    method: str = Field(default="GET")
    path: str = "/"
    test_type: str
    risk_tier: RiskTier
    state_changing: bool = False
    reason: str = ""
    expected_effect: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class PolicyDecision(BaseModel):
    decision: DecisionType
    reason: str
    risk_tier: RiskTier


class RunSummary(BaseModel):
    id: UUID
    target_id: UUID
    state: RunState
    iteration: int
    budget_spent_usd: float
    created_at: datetime


class AppProfile(BaseModel):
    id: UUID
    target_id: UUID
    tech_stack: list[str] = Field(default_factory=list)
    entry_points: list[str] = Field(default_factory=list)
    auth_surfaces: list[str] = Field(default_factory=list)
    api_indicators: list[str] = Field(default_factory=list)
    notes: str = ""
    model: str | None = None
    prompt_version: str
    created_at: datetime
