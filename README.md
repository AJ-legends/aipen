# AIPEN

AIPEN is a local, single-operator platform for evidence-led web-application security testing.

The scaffold implements the Phase 1 safety boundary and application shell. It deliberately does
**not** execute scanners or active test payloads yet. Every future outbound action must pass the
policy engine first.

## Run locally

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000`. The server binds to localhost by default.

## Current structure

- `app/policy` — deterministic scope, risk, approval, and rate-limit decision logic.
- `app/orchestrator` — persisted run state and safe phase transition skeleton.
- `app/evidence` — SQLite schema and append-only audit/evidence store foundation.
- `app/ai` — provider-neutral roles, budget guard, and no-network gateway contract.
- `app/api` — FastAPI JSON API and minimal server-rendered dashboard.
- `app/recon` — policy-gated Nmap/httpx command builders, bounded tool runner, parsers, and persistence.
- `app/discovery` — policy-gated Katana/ffuf command builders, parsers, and endpoint inventory storage.
- `app/{signals,testing}` — adapter/module boundaries, intentionally inert.
- `prompts` — versioned structured-output prompt contracts.

See `docs/AIPEN-Project-Requirements-and-Design.md` for the approved design.

## Reconnaissance safety contract

Reconnaissance is available only through `ReconService`. It checks the selected target's stored
scope before a command is built or executed, records the policy decision, uses a fixed argument
list (never a shell command), applies time/output caps, stores raw output as an artifact, and
persists only parsed host/service/HTTP metadata. It is not exposed as a web endpoint yet.
