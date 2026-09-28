#!/usr/bin/env bash
# AIPEN Kali setup: venv, deps, tool check, Juice Shop, test suite.
# Run once from the repo root:  bash scripts/kali-setup.sh
# The API key is NEVER handled here. Create .env yourself (see step 5).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "==> 1/6 Python >= 3.12"
if command -v python3.12 >/dev/null 2>&1; then PYBIN=python3.12; else PYBIN=python3; fi
"$PYBIN" -c "import sys; assert sys.version_info >= (3, 12), sys.version; print('  python:', sys.version.split()[0])"

echo "==> 2/6 virtualenv + dependencies"
if [ ! -d .venv ]; then "$PYBIN" -m venv .venv; fi
.venv/bin/pip install --upgrade pip >/dev/null
.venv/bin/pip install -e ".[dev]"

echo "==> 3/6 external CLI tools (missing ones only warn; install with apt as needed)"
MISSING=0
for tool in nmap httpx katana ffuf nuclei sqlmap docker; do
  if command -v "$tool" >/dev/null 2>&1; then
    echo "  ok: $tool"
  else
    echo "  MISSING: $tool"
    MISSING=1
  fi
done
if [ "$MISSING" -eq 1 ]; then
  echo "  hint: sudo apt update && sudo apt install -y nmap sqlmap docker.io"
  echo "  hint: httpx/katana/ffuf/nuclei come from ProjectDiscovery (apt or github releases)"
fi

echo "==> 4/6 database + static checks + unit tests"
.venv/bin/python -c "from pathlib import Path; from app.core.db import initialise_database; initialise_database(Path('data/aipen.db')); print('  db ready')"
.venv/bin/ruff check .
.venv/bin/mypy app
.venv/bin/python -m pytest -q

echo "==> 5/6 .env (API key)"
if [ -f .env ]; then
  echo "  .env exists; verifying (key never printed):"
  .venv/bin/python -c "from app.ai.config import load_config; c = load_config(); print('  configured:', c.configured, '| base:', c.base_url, '| volume:', c.volume_model)"
else
  echo "  No .env found. Create it now with EXACTLY this line (paste key via editor, never echo it):"
  echo "    AGENTROUTER_API_KEY=<your key>"
  echo "  Optional overrides: AGENTROUTER_BASE_URL, AIPEN_VOLUME_MODEL, AIPEN_PREMIUM_MODEL,"
  echo "  AIPEN_VERIFY_MODELS, AIPEN_GLOBAL_BUDGET_USD, AIPEN_OOB_BASE, AIPEN_TLS_MAX"
fi

echo "==> 6/6 Juice Shop benchmark target (Docker, detached)"
if ! command -v docker >/dev/null 2>&1; then
  echo "  docker not found; attempting install (needs sudo)..."
  sudo apt update && sudo apt install -y docker.io
  sudo systemctl enable --now docker 2>/dev/null || true
fi
if docker ps --format '{{.Names}}' >/dev/null 2>&1; then
  if docker ps --format '{{.Names}}' | grep -q '^juice-shop$'; then
    echo "  juice-shop already running"
  else
    # Localhost-bound: this is a deliberately vulnerable app, never expose it.
    docker run -d --rm --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop >/dev/null
    echo "  juice-shop starting on http://127.0.0.1:3000 (give it ~30s)"
  fi
else
  echo "  docker daemon not reachable from your user. Run once, then re-run this step:"
  echo "    sudo usermod -aG docker \"$USER\" && newgrp docker"
  echo "    docker run -d --rm --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop"
  echo "  (setup steps 1-5 already passed; nothing else is blocked)"
fi

echo ""
echo "Done. Start the server with:  .venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000"
echo "Live AI ping (sub-cent) once .env is set:"
echo "  .venv/bin/python -c \"from app.ai.gateway import AIGateway, AIRole, BudgetContext; g = AIGateway(); r = g.generate(AIRole.VERIFIER, 'Reply with this exact JSON only.', {'required': ['vote','reason','evidence_ids']}, BudgetContext(0.50, 0.0)); print(r['model'], r['cost_usd'], r['output'])\""
