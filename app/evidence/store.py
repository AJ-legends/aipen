from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

from app.core.db import connection, json_value


class EvidenceStore:
    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path

    def append_audit(self, actor: str, event: str, detail: dict[str, object]) -> None:
        with connection(self.database_path) as db:
            db.execute("INSERT INTO audit_log (ts, actor, event, detail) VALUES (?, ?, ?, ?)", (datetime.now(UTC).isoformat(), actor, event, json_value(detail)))

    def append_evidence(self, test_action_id: UUID, kind: str, analysis: dict[str, object], artifact_ref: str | None = None) -> UUID:
        evidence_id = uuid4()
        with connection(self.database_path) as db:
            db.execute("INSERT INTO evidence (id, test_action_id, kind, artifact_ref, analysis, created_at) VALUES (?, ?, ?, ?, ?, ?)", (str(evidence_id), str(test_action_id), kind, artifact_ref, json_value(analysis), datetime.now(UTC).isoformat()))
        return evidence_id
