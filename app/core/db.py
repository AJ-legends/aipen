import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS targets (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, base_urls TEXT NOT NULL,
    scope_config TEXT NOT NULL, hitl_enabled INTEGER NOT NULL, budget_cap_usd REAL NOT NULL,
    created_at TEXT NOT NULL, archived INTEGER NOT NULL DEFAULT 0, sessions TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY, target_id TEXT NOT NULL REFERENCES targets(id), state TEXT NOT NULL,
    iteration INTEGER NOT NULL DEFAULT 0, budget_spent_usd REAL NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL, started_at TEXT, ended_at TEXT, config TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor TEXT NOT NULL,
    event TEXT NOT NULL, detail TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY, test_action_id TEXT NOT NULL, kind TEXT NOT NULL,
    artifact_ref TEXT, analysis TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS hosts (
    id TEXT PRIMARY KEY, target_id TEXT NOT NULL REFERENCES targets(id), ip TEXT NOT NULL,
    hostname TEXT, source TEXT NOT NULL, first_seen TEXT NOT NULL,
    UNIQUE(target_id, ip, source)
);
CREATE TABLE IF NOT EXISTS services (
    id TEXT PRIMARY KEY, host_id TEXT NOT NULL REFERENCES hosts(id), port INTEGER NOT NULL,
    protocol TEXT NOT NULL, name TEXT, product TEXT, version TEXT, banner TEXT,
    UNIQUE(host_id, port, protocol)
);
CREATE TABLE IF NOT EXISTS endpoints (
    id TEXT PRIMARY KEY, target_id TEXT NOT NULL REFERENCES targets(id), url TEXT NOT NULL,
    method TEXT NOT NULL DEFAULT 'GET', params TEXT NOT NULL DEFAULT '[]', form_fields TEXT NOT NULL DEFAULT '[]',
    is_api INTEGER NOT NULL DEFAULT 0, auth_required INTEGER, source TEXT NOT NULL, first_seen TEXT NOT NULL,
    UNIQUE(target_id, url, method)
);
CREATE TABLE IF NOT EXISTS tool_runs (
    id TEXT PRIMARY KEY, run_id TEXT REFERENCES runs(id), tool TEXT NOT NULL, command TEXT NOT NULL,
    status TEXT NOT NULL, artifact_ref TEXT, started_at TEXT NOT NULL, ended_at TEXT, error TEXT
);
CREATE TABLE IF NOT EXISTS app_profiles (
    id TEXT PRIMARY KEY, target_id TEXT NOT NULL REFERENCES targets(id),
    tech_stack TEXT NOT NULL DEFAULT '[]', entry_points TEXT NOT NULL DEFAULT '[]',
    auth_surfaces TEXT NOT NULL DEFAULT '[]', api_indicators TEXT NOT NULL DEFAULT '[]',
    notes TEXT NOT NULL DEFAULT '', model TEXT, prompt_version TEXT NOT NULL,
    created_at TEXT NOT NULL, UNIQUE(target_id)
);
CREATE INDEX IF NOT EXISTS idx_endpoints_target ON endpoints(target_id);
CREATE INDEX IF NOT EXISTS idx_tool_runs_run ON tool_runs(run_id);
CREATE INDEX IF NOT EXISTS idx_hosts_target ON hosts(target_id);
CREATE TABLE IF NOT EXISTS test_actions (
    id TEXT PRIMARY KEY, run_id TEXT REFERENCES runs(id), target_id TEXT NOT NULL REFERENCES targets(id),
    hypothesis_id TEXT, type TEXT NOT NULL, payload TEXT NOT NULL DEFAULT '{}',
    risk_tier TEXT NOT NULL, policy_decision TEXT NOT NULL, approval_state TEXT NOT NULL DEFAULT 'pending',
    executed_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_test_actions_run ON test_actions(run_id);
CREATE TABLE IF NOT EXISTS http_probes (
    id TEXT PRIMARY KEY, target_id TEXT NOT NULL REFERENCES targets(id), url TEXT NOT NULL,
    status_code INTEGER, title TEXT, webserver TEXT, technologies TEXT NOT NULL DEFAULT '[]',
    source TEXT NOT NULL DEFAULT 'httpx', first_seen TEXT NOT NULL,
    UNIQUE(target_id, url)
);
CREATE INDEX IF NOT EXISTS idx_probes_target ON http_probes(target_id);
CREATE TABLE IF NOT EXISTS signals (
    id TEXT PRIMARY KEY, run_id TEXT REFERENCES runs(id), target_id TEXT NOT NULL REFERENCES targets(id),
    endpoint_url TEXT NOT NULL, tool TEXT NOT NULL, template_id TEXT, name TEXT NOT NULL,
    severity_hint TEXT, raw_ref TEXT, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_signals_run ON signals(run_id);
CREATE TABLE IF NOT EXISTS hypotheses (
    id TEXT PRIMARY KEY, run_id TEXT REFERENCES runs(id), target_id TEXT NOT NULL REFERENCES targets(id),
    endpoint_url TEXT NOT NULL, vuln_class TEXT NOT NULL, rationale TEXT NOT NULL,
    confidence REAL NOT NULL DEFAULT 0, author TEXT NOT NULL, prompt_version TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open', evidence_ids TEXT NOT NULL DEFAULT '[]',
    followups INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_hypotheses_run ON hypotheses(run_id);
CREATE TABLE IF NOT EXISTS verifications (
    id TEXT PRIMARY KEY, hypothesis_id TEXT NOT NULL REFERENCES hypotheses(id),
    voter TEXT NOT NULL, vote TEXT NOT NULL, reason TEXT NOT NULL,
    evidence_ids TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY, run_id TEXT REFERENCES runs(id), target_id TEXT NOT NULL REFERENCES targets(id),
    hypothesis_id TEXT NOT NULL UNIQUE REFERENCES hypotheses(id), verification_id TEXT NOT NULL REFERENCES verifications(id),
    title TEXT NOT NULL, severity TEXT NOT NULL, endpoint_url TEXT NOT NULL, description TEXT NOT NULL,
    repro TEXT NOT NULL DEFAULT '{}', impact TEXT NOT NULL DEFAULT '', remediation TEXT NOT NULL DEFAULT '',
    confidence REAL NOT NULL DEFAULT 0, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS cost_ledger (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, run_id TEXT REFERENCES runs(id),
    role TEXT NOT NULL, provider TEXT NOT NULL, model TEXT NOT NULL,
    input_tokens INTEGER NOT NULL DEFAULT 0, output_tokens INTEGER NOT NULL DEFAULT 0, usd REAL NOT NULL DEFAULT 0
);
CREATE TRIGGER IF NOT EXISTS finding_needs_confirm BEFORE INSERT ON findings
BEGIN
    -- I1: exactly one CONFIRM verification, belonging to this hypothesis, citing >=1 evidence row.
    SELECT CASE WHEN NEW.verification_id NOT IN (
        SELECT id FROM verifications
        WHERE vote = 'confirm'
          AND hypothesis_id = NEW.hypothesis_id
          AND json_array_length(evidence_ids) > 0
          AND EXISTS (SELECT 1 FROM evidence WHERE id IN (SELECT value FROM json_each(evidence_ids)))
    )
    THEN RAISE(ABORT, 'Findings require a CONFIRM verification for this hypothesis with cited evidence') END;
END;
CREATE TRIGGER IF NOT EXISTS evidence_no_update BEFORE UPDATE ON evidence
BEGIN SELECT RAISE(ABORT, 'Evidence is append-only'); END;
CREATE TRIGGER IF NOT EXISTS evidence_no_delete BEFORE DELETE ON evidence
BEGIN SELECT RAISE(ABORT, 'Evidence is append-only'); END;
CREATE TABLE IF NOT EXISTS approvals (
    id TEXT PRIMARY KEY, run_id TEXT REFERENCES runs(id), target_id TEXT NOT NULL REFERENCES targets(id),
    test_action_id TEXT REFERENCES test_actions(id), action TEXT NOT NULL DEFAULT '{}',
    risk_tier TEXT NOT NULL, reason TEXT NOT NULL DEFAULT '', expected_effect TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL DEFAULT 'pending', decided_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_approvals_run ON approvals(run_id);
CREATE INDEX IF NOT EXISTS idx_approvals_state ON approvals(state);
CREATE TABLE IF NOT EXISTS oob_callbacks (
    id TEXT PRIMARY KEY, token TEXT NOT NULL, source_ip TEXT, received_at TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_oob_token ON oob_callbacks(token);
"""

# Additive migrations for databases created before a column existed.
# Only ADD COLUMN is used here; destructive migrations are out of scope.
MIGRATIONS: tuple[tuple[str, str, str], ...] = (
    ("targets", "sessions", "TEXT NOT NULL DEFAULT '[]'"),
)


def ensure_column(path: Path, table: str, column: str, definition: str) -> bool:
    """Add a column if missing. Returns True when the schema changed."""
    with sqlite3.connect(path) as database:
        existing = {row[1] for row in database.execute(f"PRAGMA table_info({table})").fetchall()}
        if column in existing:
            return False
        database.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
        return True


def initialise_database(path: Path) -> None:
    import os

    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as database:
        database.executescript(SCHEMA)
    for table, column, definition in MIGRATIONS:
        ensure_column(path, table, column, definition)
    # Session headers live in targets.sessions: owner-only file mode. Best
    # effort on Windows; enforced on POSIX. Full-disk encryption stays the
    # operator control for findings data (see docs, §9.4 equivalent).
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


@contextmanager
def connection(path: Path) -> Iterator[sqlite3.Connection]:
    database = sqlite3.connect(path)
    database.row_factory = sqlite3.Row
    try:
        yield database
        database.commit()
    finally:
        database.close()


def json_value(value: object) -> str:
    return json.dumps(value, separators=(",", ":"), default=str)
