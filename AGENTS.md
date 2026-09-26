# AIPEN agent guide

## Purpose and safety boundary

AIPEN is a local, single-operator, evidence-led web-application security-testing platform.
Work only on explicitly authorised targets and preserve this invariant: **no evidence, no finding**.
Do not add autonomous exploitation, persistence, data exfiltration, malware delivery, or bypasses
for scope, policy, rate limits, approvals, or budgets.

## Runtime environment

- The production environment is Kali Linux and Python 3.12+.
- Treat Nmap, httpx, Katana, ffuf, Nuclei, ZAP, and sqlmap as external CLI dependencies; do not
  reimplement them.
- Invoke tools only through thin adapters with fixed argument lists, `subprocess` without a shell,
  explicit timeouts, output-size limits, structured parsing, raw-artifact capture, and graceful
  failure reporting.
- Keep the application server bound to `127.0.0.1` by default.

## Architecture rules

- Every outbound HTTP request or CLI tool invocation must pass `app.policy.check_action` first.
  Record every allow, deny, and approval decision in `audit_log`.
- Keep `app/policy` pure: no filesystem, database, network, subprocess, clock, or AI calls.
- Evidence is append-only. Never update/delete it; store corrections as new, linked records.
- Scanner output is a signal only. Create a finding only from evidence-backed independent
  verification.
- Route every model request through `app.ai`; provider SDKs do not belong in other modules.
- Keep API/UI code thin. Place business logic in the appropriate service/module layer.

## Python conventions

- Use typed Python 3.12+, `pathlib.Path`, Pydantic at component boundaries, and explicit domain
  models for tool/parser output.
- Prefer async I/O for HTTP and orchestration. Keep parsers deterministic and side-effect free.
- Add unit tests with recorded fixtures for every parser and policy/executor decision. Do not make
  unit tests depend on Kali tools or external targets.
- Before completing a change, run `pytest -q`, `ruff check .`, and the relevant type checks when
  the environment is available.

## Scope of current work

The project is being delivered sprint-by-sprint. Do not expose live recon, discovery, or testing
through a public route until its policy, audit, persistence, and approval path are implemented.
Preserve the existing package boundaries under `app/` and update `docs/IMPLEMENTATION-STATUS.md`
when completing a material phase.
