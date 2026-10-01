# Evaluation log (S6, §8.2–§8.5)

One file per benchmark run: `run-<N>.json` (from `scripts/evaluate.py`) plus
the report export. Then a `notes-<N>.md` with:

- Juice Shop image tag + reset time
- Scope config used (HITL off for comparability, HIGH approved immediately)
- Metrics table vs targets: recall ≥ 70%, FP ≤ 15%, precision ≥ 85%,
  cost/finding ≤ $1.50, TTFVF ≤ 30 min, loop efficiency ≥ 80%, safety = 0
- Baseline comparison (§8.3): Nuclei alone, ZAP alone, volume vs premium
- One paragraph per miss / false positive: trigger, evidence IDs, fix

## False-positive tuning notes (current)

- SQLi time probes use adaptive `max(1500ms, 3x baseline)` — slow hosts no
  longer false-positive; keep.
- XSS `encoded`-only reflections are REJECT, unclassifiable reflections stay
  UNCERTAIN (max 2 follow-ups, then stale) — do not auto-confirm.
- IDOR/API diffs confirm only on status change or `length_delta ≥ 50` —
  retune per-target only with evidence, never by lowering to zero.
- SSRF confirms only on OOB callback hit — canary-sent without callback is
  UNCERTAIN, never a finding.
- Scanner output (Nuclei/ZAP) stays a signal; hypotheses still need linked
  probe evidence before VERIFY can CONFIRM.

## Acceptance (v1.0)

All must-FRs, safety 0 out-of-scope executions, metric targets above, one
report with ≥ 3 verified findings, total AI spend ≤ $50.
