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


class Session(BaseModel):
    """A named auth session (headers) for cross-account testing. Secrets stay server-side."""

    name: str = Field(min_length=1, max_length=60)
    headers: dict[str, str] = Field(default_factory=dict)


class TargetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    base_urls: list[HttpUrl] = Field(min_length=1)
    scope: ScopeConfig
    hitl_enabled: bool = True
    budget_cap_usd: float = Field(default=0.50, gt=0, le=100)
    sessions: list[Session] = Field(default_factory=list, max_length=5)


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


class TestAction(BaseModel):
    id: UUID
    run_id: UUID | None = None
    target_id: UUID
    hypothesis_id: UUID | None = None
    type: str
    payload: dict[str, Any] = Field(default_factory=dict)
    risk_tier: RiskTier
    policy_decision: DecisionType
    approval_state: str = "pending"
    executed_at: datetime


class HypothesisStatus(StrEnum):
    OPEN = "open"
    VERIFIED = "verified"
    REJECTED = "rejected"
    STALE = "stale"


class VerificationVote(StrEnum):
    CONFIRM = "confirm"
    REJECT = "reject"
    UNCERTAIN = "uncertain"


class Signal(BaseModel):
    id: UUID
    run_id: UUID | None = None
    target_id: UUID
    endpoint_url: str
    tool: str
    template_id: str | None = None
    name: str
    severity_hint: str | None = None
    raw_ref: str | None = None
    created_at: datetime


class Hypothesis(BaseModel):
    id: UUID
    run_id: UUID | None = None
    target_id: UUID
    endpoint_url: str
    vuln_class: str
    rationale: str
    confidence: float = 0.0
    author: str
    prompt_version: str
    status: HypothesisStatus = HypothesisStatus.OPEN
    evidence_ids: list[UUID] = Field(default_factory=list)
    followups: int = 0
    created_at: datetime


class Verification(BaseModel):
    id: UUID
    hypothesis_id: UUID
    voter: str
    vote: VerificationVote
    reason: str
    evidence_ids: list[UUID] = Field(default_factory=list)
    created_at: datetime


class Finding(BaseModel):
    id: UUID
    run_id: UUID | None = None
    target_id: UUID
    hypothesis_id: UUID
    verification_id: UUID
    title: str
    severity: str
    endpoint_url: str
    description: str
    repro: dict[str, Any] = Field(default_factory=dict)
    impact: str = ""
    remediation: str = ""
    confidence: float = 0.0
    created_at: datetime


class ApprovalState(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class Approval(BaseModel):
    id: UUID
    run_id: UUID | None = None
    target_id: UUID
    test_action_id: UUID | None = None
    action: dict[str, Any] = Field(default_factory=dict)
    risk_tier: RiskTier
    reason: str = ""
    expected_effect: str = ""
    state: ApprovalState = ApprovalState.PENDING
    decided_at: datetime | None = None
