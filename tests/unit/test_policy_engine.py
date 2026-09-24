from app.core.schemas import DecisionType, ProposedAction, RiskTier, ScopeConfig
from app.policy.engine import check_action


def scope() -> ScopeConfig:
    return ScopeConfig(allowed_domains=["*.example.test"], allowed_ports=[443], allowed_test_types=["recon"])


def action(**overrides: object) -> ProposedAction:
    values: dict[str, object] = {"target_url": "https://api.example.test/health", "path": "/health", "test_type": "recon", "risk_tier": RiskTier.LOW}
    values.update(overrides)
    return ProposedAction(**values)


def test_allows_in_scope_low_risk_action() -> None:
    assert check_action(action(), scope(), hitl_enabled=True).decision is DecisionType.ALLOW


def test_denies_out_of_scope_host() -> None:
    assert check_action(action(target_url="https://outside.test/"), scope(), hitl_enabled=False).decision is DecisionType.DENY


def test_denies_default_protected_path() -> None:
    assert check_action(action(path="/logout"), scope(), hitl_enabled=False).decision is DecisionType.DENY


def test_medium_risk_needs_approval_with_hitl() -> None:
    assert check_action(action(risk_tier=RiskTier.MEDIUM), scope(), hitl_enabled=True).decision is DecisionType.NEEDS_APPROVAL
