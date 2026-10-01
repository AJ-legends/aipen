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
  (queued) and   `GET hypotheses|findings|signals`. 42 tests passing; `ruff check .`
  and `mypy app` (strict) clean.
- Issue-resolution pass (no S5 required): gateway R4 (one backoff retry on
  429/5xx/transport errors, then fallback down the role chain with a
  `provider_fallback` audit row), strict `TestRequest` validation (known modules
  only, `max_probes` 1–200, else 422), repo-root `.env` loading via python-dotenv
  (real env still wins; `.env` stays gitignored), adaptive timing threshold
  (`max(1500ms, 3x baseline)` so slow hosts stop false-positiving time probes).
  46 tests passing; `ruff check .` and `mypy app` (strict) clean.
- S5 completion (M5 product): `approvals` + `oob_callbacks` tables, `targets.sessions`
  via additive `ensure_column()` migrator, `ApprovalService` (request/decide/pending),
  HITL in `TestingService` (NEEDS_APPROVAL → approval row + skip; `PAUSED` runs resume
  via `continue_testing` → `execute_approved`), IDOR module (sequential/unauth +
  two-session cross-account, MEDIUM), SSRF module (tokenized canaries, localhost
  `POST /api/oob/{token}` listener, callback-only CONFIRM), API module (BOLA-query,
  verbose-errors, unauthenticated, HITL-gated mass-assignment indicators), pure risk
  classifier, session-aware executor (names persist, header secrets stay in memory),
  analyst/verifier/loop branches for idor/ssrf/api, operator dashboard (targets, run
  pipeline, approvals queue, findings/hypotheses, SSE decision log),
  `POST /runs/{id}/test/continue`, `GET /approvals`, `POST /approvals/{id}/decision`,
  strict `TestRequest` modules, adaptive timing already landed.   54 tests passing;
  `ruff check .` and `mypy app` (strict) clean.
- Review-fix pass: approved probes now rebuild with original kind/session/strip_auth/
  risk and re-check current policy (DENY skips, approval satisfies NEEDS_APPROVAL);
  `finding_needs_confirm` trigger also enforces same-hypothesis + cited-evidence;
  DB file 0600 + backups dir 0700 (full-disk encryption stays the operator control);
  loop wired to the gateway behind opt-in `use_ai` (validated AI drafts/votes, model
  authors tracked for R2, per-run budget from target cap, deterministic fallback);
  Juice Shop bound to 127.0.0.1; README rewritten for the current system.
- Kali transfer bundle: `scripts/kali-setup.sh` (venv, deps, tool check, Juice Shop
  via Docker, full test suite, `.env` guidance). Live AI validation moved to Kali
  after Windows-network findings: `agentrouter.org` blackholes POST bodies from this
  host (GETs fine), and its ALB needs `AIPEN_TLS_MAX=1.2` under Windows Store
  Python's OpenSSL (opt-in `tls_verify_setting()`; system TLS by default).
- S6 completion (reporting + evaluation): unified the in-tree 9/29 report attempt
  onto one design — `app/reports/renderer.py` (target- or run-scoped Markdown/HTML/
  JSON with curl PoCs, hypotheses ledger, empty states) as the single engine;
  unified `compute_metrics()` (run or target scope, flat keys, recall via detailed
  ground-truth list or `planted_total`); `python -m app.reports.cli report|evaluate`;
  `GET /runs/{id}/report|metrics` plus target-scoped twins; dashboard report buttons;
  `docs/runbook-juiceshop.md` benchmark protocol with anti-overfit rules. 68 tests
  passing; `ruff check .` and `mypy app` (strict) clean. Live benchmark + v1.0 tag
  remain operator-side on Kali.

- S6 completion (M6 evidence of value): `app/reports/renderer.py` (deterministic
  `build_report` + Markdown/HTML/JSON, severity-ordered, curl PoCs from recorded
  mutated URLs, hypotheses ledger + evidence appendix),
  `app/reports/metrics.py` (§8.2 from stored tables: FP rate, precision proxy,
  recall with planted total, $/finding, TTFVF, loop efficiency, verifier
  agreement, safety out-of-scope executions, override rate),
  `GET /targets/{id}/report?run_id=&format=json|md|html` (audited
  `report_generated`), `GET /runs/{id}/metrics` + `GET /targets/{id}/metrics`,
  `scripts/evaluate.py` CLI, dashboard report/metrics buttons,
  `docs/runbook-juiceshop.md` + `docs/evaluation/README.md` with FP-tuning
  notes. 64 tests passing; `ruff check .` and `mypy app` (strict) clean.

## Deliberately deferred (beyond S6)

Live Juice Shop benchmark numbers with §8 metrics table, second-target
generalisation check, and the v1.0 release tag. Live model-backed loop
validation stays on Kali (Windows host blackholes the provider's POST path).

## Validation note

`pytest -q`, `ruff check .`, and `mypy app` (strict) run green in the project
venv on every change; see the per-phase entries above for counts.
