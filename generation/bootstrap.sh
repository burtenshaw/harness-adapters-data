#!/usr/bin/env bash
# Install the November 10 Tasksmith controller, worker wheel and author runtime.
set -euo pipefail
if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: bash generation/bootstrap.sh DIRECTORY [REPO2RLENV_GIT_SOURCE]" >&2
  exit 2
fi
pin=61903fe0ed805ea5418811b0fcf399e4144e95e4
source_repo=${2:-https://github.com/huggingface/Repo2RLEnv.git}
mkdir -p -- "$1"
runtime_root=$(cd -- "$1" && pwd)
checkout="$runtime_root/Repo2RLEnv"
if [[ ! -e "$checkout" ]]; then
  git clone --quiet --no-checkout -- "$source_repo" "$checkout"
  git -C "$checkout" checkout --quiet --detach "$pin"
fi
if [[ "$(git -C "$checkout" rev-parse HEAD)" != "$pin" || -n "$(git -C "$checkout" status --porcelain)" ]]; then
  echo "Expected a clean Repo2RLEnv checkout at $pin in $checkout" >&2
  exit 1
fi
uvx --from uv==0.13.7 uv sync --project "$checkout" --python 3.12 --frozen --extra tasksmith --extra modal --extra harbor --no-dev
uvx --from uv==0.13.7 uv build --wheel --out-dir "$runtime_root/dist" "$checkout"
py="$checkout/.venv/bin/python"
wheel="$runtime_root/dist/repo2rlenv-0.9.5-py3-none-any.whl"
"$py" -IB - "$wheel" "$runtime_root/runtime.json" <<'PY'
import json
from pathlib import Path
import sys

from repo2rlenv.execution.artifacts import check_runtime_wheel
from repo2rlenv.tasksmith.runtime import directory, install, sources

wheel, receipt = map(Path, sys.argv[1:])
digest = check_runtime_wheel(wheel)
if digest != "49589871dc0acf0286bfa11a2c8a4a84eae2aedd775f13d05cc78ae23b6236c6":
    raise SystemExit("Worker wheel differs from the historical campaign")
cache = directory()
packages = json.loads((sources() / "package.json").read_bytes())["dependencies"]
lock = sources() / "package-lock.json"

def installed():
    if not (cache / lock.name).is_file() or (cache / lock.name).read_bytes() != lock.read_bytes():
        return False
    for name, version in packages.items():
        manifest = cache / "node_modules" / name / "package.json"
        if not manifest.is_file() or json.loads(manifest.read_bytes())["version"] != version:
            return False
    return True

if not installed():
    install()
if not installed():
    raise SystemExit("Author runtime does not match the pinned dependency versions")
receipt.write_text(json.dumps({"repo2rlenv_commit":"61903fe0ed805ea5418811b0fcf399e4144e95e4",
                              "wheel_sha256":digest,"author_dependencies":packages},indent=2)+"\n")
print("Worker wheel SHA256", digest)
PY
