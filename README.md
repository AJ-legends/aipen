# AIPEN

AIPEN is a local, single-operator platform for evidence-led web-application security testing.

Every outbound action — scans, probes, and AI calls — passes a deterministic policy
engine first, is recorded in an append-only audit log, and only becomes a finding
after independent verification against stored evidence. **No evidence, no finding.**

## Run locally (Windows dev)

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000`. The server binds to localhost by default.

## Run on Kali (production)

See `scripts/kali-setup.sh` — one-shot setup (venv, deps, tool check, Juice Shop,
test suite), then create `.env` with `AGENTROUTER_API_KEY` (never commit it):

```bash
bash scripts/kali-setup.sh
nano .env   # AGENTROUTER_API_KEY=<key>
.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
```

## Pipeline

Create a target → run `recon` → `discovery` → `signals` → `test` → (approve
medium-risk probes) → `continue` → `analyze` (add `use_ai: true` to spend model
budget) → findings → `GET /targets/{id}/report?format=md|html|json` +
`GET /runs/{id}/metrics` (or `python scripts/evaluate.py --run <id>`).
All long phases run as background jobs; poll `GET /runs/{id}`.

## Current structure

- `app/policy` — deterministic scope, risk, approval, and rate-limit decisions (pure).
- `app/orchestrator` — persisted run state machine through `REPORTING`, with pause/resume.
- `app/evidence` — SQLite schema, append-only store, and audit helpers.
- `app/ai` — AgentRouter provider adapter (budget/routing/ledger), deterministic
  analyst/verifier, and the hypothesis → verification → finding loop service.
- `app/api` — FastAPI JSON API, operator dashboard, approvals queue, SSE decision log.
- `app/recon` — policy-gated Nmap/httpx adapters, bounded runner, parsers, persistence.
- `app/discovery` — policy-gated Katana/ffuf adapters, parsers, endpoint inventory.
- `app/signals` — policy-gated Nuclei ingestion (signals seed hypotheses, never findings).
- `app/testing` — differential HTTP executor, SQLi/XSS/IDOR/SSRF/API modules, sqlmap
  escalation, HITL approvals integration.
- `app/approvals` — human-in-the-loop approval queue.
- `app/reports` — deterministic report renderer (MD/HTML/JSON) + §8.2 metrics.
- `prompts` — versioned structured-output prompt contracts.

See `docs/AIPEN-Project-Requirements-and-Design.md` for the approved design and
`docs/IMPLEMENTATION-STATUS.md` for the delivery log.

## Safety contracts

- **Policy first:** every tool invocation and test probe is checked against the
  target's stored scope; denials and approvals are written to `audit_log`.
- **Evidence is append-only** (SQLite triggers); corrections are new linked records.
- **Findings require a CONFIRM verification** citing real evidence (DB trigger + service).
- **Secrets:** API keys come from the environment only; session headers are stored
  with owner-only file permissions — full-disk encryption remains the operator control.
