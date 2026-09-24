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
    created_at TEXT NOT NULL, archived INTEGER NOT NULL DEFAULT 0
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
CREATE TRIGGER IF NOT EXISTS evidence_no_update BEFORE UPDATE ON evidence
BEGIN SELECT RAISE(ABORT, 'Evidence is append-only'); END;
CREATE TRIGGER IF NOT EXISTS evidence_no_delete BEFORE DELETE ON evidence
BEGIN SELECT RAISE(ABORT, 'Evidence is append-only'); END;
"""


def initialise_database(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as connection:
        connection.executescript(SCHEMA)


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
