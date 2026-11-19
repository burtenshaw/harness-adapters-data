#!/usr/bin/env bash
# Offline check of the three installed runtimes and the shipped operator sources.
set -euo pipefail
cd "$(dirname "$0")"
umask 077
verify_dir=$(mktemp -d)
trap 'rm -rf -- "$verify_dir"' EXIT

python3 -B -m unittest benchmarks.test_prepare
.local/openenv/.venv/bin/python -B -m unittest discover -s openenv_pipeline -p 'test_*.py'
python3 -B openenv_pipeline/run.py verify
python3 -B openenv_pipeline/run.py smoke --output "$verify_dir/openenv"
python3 -B qwen_pipeline/run.py verify-cache
python3 -B qwen_pipeline/run.py cache --output "$verify_dir/qwen" --archive "$verify_dir/no-private-receipts"

runs/tasksmith-runtime/Repo2RLEnv/.venv/bin/python -B - <<'PY'
import sys
from pathlib import Path

sys.path.insert(0, "generation")
import campaign
from repo2rlenv.execution.artifacts import check_runtime_wheel

campaign.check_runtime()
wheel = Path("runs/tasksmith-runtime/dist/repo2rlenv-0.9.5-py3-none-any.whl")
if check_runtime_wheel(wheel) != campaign.WHEEL_SHA256:
    raise ValueError("Tasksmith wheel differs from the original worker")
print("Verified the generated Tasksmith worker wheel")
PY
.sources/tasksmith-final-venv/bin/python -B - <<'PY'
import sys
sys.path.insert(0, "tasksmith_final")
import pipeline
pipeline.live_environment()
print("Verified the Harbor separate-verifier runtime")
PY
.sources/tasksmith-final-venv/bin/python -B tasksmith_final/smoke.py --check-budget --mock-publish "$@"
