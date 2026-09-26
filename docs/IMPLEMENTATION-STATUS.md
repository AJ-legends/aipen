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
- Early-fix hardening (pre-S3): `test_actions` + `http_probes` tables (`TestAction` schema),
  ffuf wordlist allow-list (`data/wordlists/`, traversal guard, existence check),
  full httpx probe persistence feeding `summarize()` tech_stack, crash-safe SQLite backup
  API (replaces file copy), non-blocking `POST recon|discovery` via BackgroundTasks with
  `GET /runs/{id}` polling, typed `_TargetContext` (mypy strict clean), `httpx/httpx2`
  dev extras for Starlette TestClient. 23 tests passing; `ruff check .` and `mypy app` clean.
- S3 completion (M3 hands): async differential HTTP executor (`app/testing/executor.py`,
  per-host token-bucket limiter, baseline-vs-mutated diffs, 15s timeout, 2MB cap),
  curated SQLi (error + time, 8 probes) and XSS (5 canary probes + context classifier)
  libraries, thin sqlmap escalation adapter (fixed argv, single-param scope), policy-gated
  `TestingService` (per-probe `check_action` + audit, `test_actions` rows before evidence,
  max 2 sqlmap escalations), orchestrator `SIGNALS→ACT→VERIFY`, `PATCH /targets/{id}/scope`
  (blocked while runs active), `POST /api/runs/{id}/test` (queued) and
  `GET /targets/{id}/evidence`. `httpx` promoted to runtime dependency.
  32 tests passing; `ruff check .` and `mypy app` (strict) clean.
- S4 completion (M4 brain): `signals/hypotheses/verifications/findings/cost_ledger`
  tables with a `finding_needs_confirm` trigger (I1 at the data layer), thin Nuclei
  adapter + policy-gated `SignalService` (signals seed hypotheses, never findings),
  deterministic analyst (`app/ai/analyst.py`, evidence/signal grouping) and verifier
  (`app/ai/verifier.py`, CONFIRM/REJECT/UNCERTAIN with max 2 follow-ups then stale),
  `LoopService.analyze_run()` closing observe→reason→verify→finding, live AgentRouter
  adapter (`app/ai/providers.py`, OpenAI-compatible, key via `AGENTROUTER_API_KEY`
  only, never logged) with cross-provider verifier routing (R2), JSON validation +
  1 retry, per-call cost ledger and 70%-of-global-budget downgrade, orchestrator
  `SIGNALS→(signals)→ACT→VERIFY→ANALYZE→REPORTING`, `POST /runs/{id}/signals|analyze`
  (queued) and `GET hypotheses|findings|signals`. 42 tests passing; `ruff check .`
  and `mypy app` (strict) clean.

## Deliberately deferred

HTTP test execution, payload libraries, AI-provider credentials/adapters, model routing, approval
queue UI, reporting, and live event streaming are later sprint work (S3+).

## Validation note

The project host did not expose a `python` executable or Python launcher at scaffold time, so
runtime tests could not be executed here. Once Python 3.12 is installed, follow the commands in
the repository README and run `pytest -q`.
