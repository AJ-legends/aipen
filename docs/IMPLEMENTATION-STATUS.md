# AIPEN implementation status

## Delivered scaffold (Phase 1 foundation)

- Python package, dependency manifest, lint/type/test configuration.
- Localhost FastAPI application, health endpoint, OpenAPI docs, and dashboard shell.
- SQLite database initialised with WAL mode and tables for targets, runs, audit logs, and evidence.
- Target creation/listing API and persisted, archive-aware run creation.
- Pure policy engine covering host, port, path, test-type, protected-path, state-change, risk-tier, and HITL decisions.
- Append-only evidence table enforced by SQLite triggers.
- Provider-neutral AI gateway contract and versioned analyst/verifier prompt contracts.
- Clear module boundaries for recon, discovery, signals, testing, evidence, reporting, and orchestration.
- Initial unit tests for policy decisions.
- Phase 2 reconnaissance foundation: fixed-argument Nmap/httpx adapters, timeout/output-limited
  execution, XML/JSONL parsers, raw artifacts, host/service/endpoint persistence, and parser tests.
- Discovery foundation: fixed-argument Katana/ffuf adapters, parser fixtures, policy checks, raw
  output capture, tool audit records, and endpoint-inventory persistence.
- S2 completion (M2 eyes and memory): deterministic `build_profile()` heuristics plus
  `prompts/recon_summary.v1.yaml`, `app_profiles` table with `ReconService.summarize()`,
  orchestrator `CREATED→RECON→DISCOVERY→SIGNALS` with per-run DB backup in
  `data/backups/`, `tool_runs.run_id` linkage, `POST /api/runs/{id}/recon|discovery` and
  `GET /hosts|/endpoints|/profiles/latest`, and 10 new unit/API tests (17 passed).

## Deliberately deferred

HTTP test execution, payload libraries, AI-provider credentials/adapters, model routing, approval
queue UI, reporting, and live event streaming are later sprint work (S3+).

## Validation note

The project host did not expose a `python` executable or Python launcher at scaffold time, so
runtime tests could not be executed here. Once Python 3.12 is installed, follow the commands in
the repository README and run `pytest -q`.
