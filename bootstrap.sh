#!/usr/bin/env bash
# Install the three historical toolchains on a new checkout, without launching work.
set -euo pipefail
cd "$(dirname "$0")"
bash generation/bootstrap.sh runs/tasksmith-runtime

python3 -B openenv_pipeline/run.py verify
if [[ ! -d .local/openenv ]]; then
  python3 -B openenv_pipeline/run.py bootstrap
fi
python3 -B - <<'PY'
from pathlib import Path
import sys

sys.path.insert(0, "openenv_pipeline")
from run import check_checkout

check_checkout(Path(".local/openenv").resolve())
PY
uv sync --project .local/openenv --frozen --group dev --python 3.13
uv pip install --python .local/openenv/.venv/bin/python -r openenv_pipeline/runtime-overlay.requirements.txt

bash tasksmith_final/bootstrap.sh
if [[ ! -d .sources/qwen ]]; then
  python3 -B qwen_pipeline/run.py cache
fi
python3 -B qwen_pipeline/run.py verify-cache
bash verify.sh
