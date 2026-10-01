# Juice Shop benchmark runbook (S6 evaluation)

Run on Kali. Each run starts from a factory-reset instance so results are comparable.

## 1. Reset the target

```bash
docker rm -f juice-shop
docker run -d --rm --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop
sleep 30
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:3000/
```

Record the image version: `docker inspect bkimminich/juice-shop --format '{{.RepoDigests}}'`.

## 2. Standard benchmark scope

- Base URL: `http://127.0.0.1:3000`
- Allowed domains: `127.0.0.1`, `localhost`
- Allowed ports: `3000`
- Test types: `recon,discovery,signals,sqli,xss,idor,ssrf,api`
- HITL: off for LOW/MEDIUM (approve HIGH immediately to keep runs comparable)

## 3. Drive one run (API or dashboard)

```bash
BASE=http://127.0.0.1:8000/api
T=$(curl -s -X POST $BASE/targets -H 'Content-Type: application/json' -d @- <<'EOF' | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])"
{"name":"juice-s6","base_urls":["http://127.0.0.1:3000"],"scope":{"allowed_domains":["127.0.0.1","localhost"],"allowed_ports":[3000],"allowed_test_types":["recon","discovery","signals","sqli","xss","idor","ssrf","api"]}}
EOF
)
R=$(curl -s -X POST $BASE/targets/$T/runs | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])")
for phase in recon discovery signals test; do
  curl -s -X POST $BASE/runs/$R/$phase -H 'Content-Type: application/json' -d '{"base_url":"http://127.0.0.1:3000"}'
  sleep 5
done
curl -s -X POST $BASE/runs/$R/analyze -H 'Content-Type: application/json' -d '{"use_ai":false}'
```

Poll `GET $BASE/runs/$R` until `REPORTING`, then:

```bash
python -m app.reports.cli evaluate $R --ground-truth docs/evaluation/juice-shop-scope.json --out docs/evaluation/run-$(date +%F-%H%M).json
python -m app.reports.cli report $R --format markdown --out docs/evaluation/report-$(date +%F-%H%M).md
```

## 4. Repeat 3 runs, report the median with spread

## 5. Ground truth (operator-maintained, NEVER in module code)

`docs/evaluation/juice-shop-scope.json` — example shape (fill from your Juice Shop version):

```json
[
  {"endpoint_contains": "/rest/products/search", "vuln_class": "sqli"},
  {"endpoint_contains": "/search?q=", "vuln_class": "xss"}
]
```

Anti-overfit rules: no Juice Shop strings/routes/payloads in `app/`; benchmark config
lives only in `docs/evaluation/`; one secondary target (DVWA or WebGoat) as a
generalisation check before v1.0.

## 6. Failure analysis

Every missed planted vuln and every false positive gets a one-paragraph root-cause
note in `docs/evaluation/`. Root causes feed the backlog — evaluation output is
sprint input, not an appendix.

## Acceptance bar (v1.0)

Detection ≥ 70% · FP ≤ 15% · cost/finding ≤ $1.50 · safety record 0 · report with
≥ 3 verified findings · total AI spend ≤ $50.
