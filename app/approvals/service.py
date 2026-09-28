"""Human-in-the-loop approvals. Requested by executors, decided by the operator."""
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

from app.core.db import connection, json_value
from app.core.schemas import ApprovalState, RiskTier


class ApprovalService:
    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path

    def request(
        self,
        target_id: UUID,
        action: dict[str, object],
        risk_tier: RiskTier,
        reason: str,
        expected_effect: str,
        run_id: UUID | None = None,
        test_action_id: UUID | None = None,
    ) -> UUID:
        approval_id = uuid4()
        now = datetime.now(UTC).isoformat()
        with connection(self.database_path) as db:
            db.execute(
                "INSERT INTO approvals (id, run_id, target_id, test_action_id, action, risk_tier, reason, expected_effect, state) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending')",
                (str(approval_id), str(run_id) if run_id else None, str(target_id), str(test_action_id) if test_action_id else None, json_value(action), risk_tier.value, reason, expected_effect),
            )
            db.execute("INSERT INTO audit_log (ts, actor, event, detail) VALUES (?, ?, ?, ?)", (now, "system", "approval_requested", json_value({"approval_id": str(approval_id), "run_id": str(run_id) if run_id else None})))
        return approval_id

    def decide(self, approval_id: UUID, approved: bool) -> ApprovalState:
        now = datetime.now(UTC).isoformat()
        with connection(self.database_path) as db:
            row = db.execute("SELECT state FROM approvals WHERE id = ?", (str(approval_id),)).fetchone()
            if row is None:
                raise LookupError("Approval does not exist.")
            if row["state"] != ApprovalState.PENDING.value:
                raise ValueError(f"Approval is already {row['state']}.")
            state = ApprovalState.APPROVED if approved else ApprovalState.REJECTED
            db.execute("UPDATE approvals SET state = ?, decided_at = ? WHERE id = ?", (state.value, now, str(approval_id)))
            db.execute("INSERT INTO audit_log (ts, actor, event, detail) VALUES (?, ?, ?, ?)", (now, "operator", "approval_decided", json_value({"approval_id": str(approval_id), "state": state.value})))
        return state

    def pending(self, run_id: UUID | None = None) -> list[dict[str, object]]:
        with connection(self.database_path) as db:
            if run_id is not None:
                rows = db.execute("SELECT * FROM approvals WHERE run_id = ? AND state = 'pending' ORDER BY rowid", (str(run_id),)).fetchall()
            else:
                rows = db.execute("SELECT * FROM approvals WHERE state = 'pending' ORDER BY rowid").fetchall()
        return [dict(row) for row in rows]

    def approved_action_ids(self, run_id: UUID) -> set[str]:
        with connection(self.database_path) as db:
            rows = db.execute("SELECT test_action_id FROM approvals WHERE run_id = ? AND state = 'approved' AND test_action_id IS NOT NULL", (str(run_id),)).fetchall()
        return {str(row["test_action_id"]) for row in rows}
