"""Pure policy decisions. This module must remain free of network and AI calls."""
from fnmatch import fnmatch
from urllib.parse import urlparse

from app.core.schemas import DecisionType, PolicyDecision, ProposedAction, RiskTier, ScopeConfig

DEFAULT_DENIED_PATHS = ("/logout*", "/password-reset*", "/payment*", "/delete*", "/admin/*")
DESTRUCTIVE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _domain_allowed(hostname: str, allowed_domains: list[str]) -> bool:
    return any(fnmatch(hostname, pattern) for pattern in allowed_domains)


def _path_allowed(path: str, scope: ScopeConfig) -> bool:
    return any(path.startswith(prefix) for prefix in scope.allowed_path_prefixes)


def check_action(action: ProposedAction, scope: ScopeConfig, hitl_enabled: bool) -> PolicyDecision:
    """Return a deterministic decision; approval never overrides scope or forbidden-action denial."""
    parsed = urlparse(str(action.target_url))
    hostname = (parsed.hostname or "").lower().rstrip(".")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = action.path if action.path.startswith("/") else f"/{action.path}"

    if not _domain_allowed(hostname, scope.allowed_domains) and hostname not in scope.allowed_ips:
        return PolicyDecision(decision=DecisionType.DENY, reason="Host is outside configured scope.", risk_tier=action.risk_tier)
    if port not in scope.allowed_ports:
        return PolicyDecision(decision=DecisionType.DENY, reason="Port is outside configured scope.", risk_tier=action.risk_tier)
    if not _path_allowed(path, scope):
        return PolicyDecision(decision=DecisionType.DENY, reason="Path is outside configured scope.", risk_tier=action.risk_tier)
    if any(fnmatch(path, pattern) for pattern in (*DEFAULT_DENIED_PATHS, *scope.excluded_paths)):
        return PolicyDecision(decision=DecisionType.DENY, reason="Path is protected by the deny-list.", risk_tier=action.risk_tier)
    if action.test_type not in scope.allowed_test_types:
        return PolicyDecision(decision=DecisionType.DENY, reason="Test type is not permitted by scope.", risk_tier=action.risk_tier)
    if action.state_changing or action.method.upper() in DESTRUCTIVE_METHODS:
        return PolicyDecision(decision=DecisionType.DENY, reason="State-changing actions are forbidden by scope.", risk_tier=RiskTier.HIGH)
    if action.test_type in scope.forbidden_actions:
        return PolicyDecision(decision=DecisionType.DENY, reason="Action is forbidden by scope.", risk_tier=action.risk_tier)
    if action.risk_tier is RiskTier.HIGH:
        return PolicyDecision(decision=DecisionType.NEEDS_APPROVAL, reason="High-risk actions always need operator approval.", risk_tier=action.risk_tier)
    if action.risk_tier is RiskTier.MEDIUM and hitl_enabled:
        return PolicyDecision(decision=DecisionType.NEEDS_APPROVAL, reason="HITL is enabled for medium-risk actions.", risk_tier=action.risk_tier)
    return PolicyDecision(decision=DecisionType.ALLOW, reason="Action is within scope and policy.", risk_tier=action.risk_tier)
