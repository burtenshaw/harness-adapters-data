#!/usr/bin/env bash
# Install the OpenEnv separate-verifier runtime for Tasksmith.
set -euo pipefail
if [[ $# -gt 2 ]]; then
  echo "usage: bash tasksmith_final/bootstrap.sh [DIRECTORY [OPENENV_GIT_SOURCE]]" >&2
  exit 2
fi
stage_dir=$(cd -- "$(dirname -- "$0")" && pwd)
mkdir -p -- "${1:-$stage_dir/../.sources}"
runtime_root=$(cd -- "${1:-$stage_dir/../.sources}" && pwd)
checkout="$runtime_root/openenv-tasksmith"
venv="$runtime_root/tasksmith-final-venv"
source_repo=${2:-https://github.com/openenv/OpenEnv.git}
if [[ -d "$source_repo" ]]; then
  source_repo=$(cd -- "$source_repo" && pwd)
fi
pin=f802ee4d99136b30041e4dd0b09be3ce6e1062ae
if [[ ! -e "$checkout" ]]; then
  staging=$(mktemp -d "$runtime_root/.tasksmith-checkout.XXXXXXXX")
  trap 'rm -rf -- "$staging"' EXIT
  git -C "$staging" init --quiet
  git -C "$staging" remote add origin "$source_repo"
  if ! git -C "$staging" fetch --quiet --depth=1 origin "$pin"; then
    git -C "$staging" fetch --quiet --depth=1 origin refs/pull/1632/head
  fi
  git -C "$staging" checkout --quiet --detach "$pin"
  mv -- "$staging" "$checkout"
  trap - EXIT
fi
if [[ "$(git -C "$checkout" rev-parse HEAD)" != "$pin" || -n "$(git -C "$checkout" status --porcelain)" ]]; then
  echo "Expected a clean separate-verifier checkout at $pin in $checkout" >&2
  exit 1
fi
if [[ ! -e "$venv" ]]; then
  uv venv --python 3.13.14 "$venv"
fi
py="$venv/bin/python"
"$py" -B -c 'import sys; assert sys.version_info[:3] == (3, 13, 14), sys.version'
uv pip install --python "$py" -c "$stage_dir/runtime-constraints.txt" -e "$checkout" \
  'harbor[hf-sandbox]==0.25.0' 'litellm==1.109.1' 'huggingface_hub==1.33.0' \
  'PyYAML==6.0.3' 'pyarrow==26.0.1'
uv pip check --python "$py"
PYTHONPATH="$stage_dir" "$py" -B -c 'from pipeline import live_environment; live_environment()'
echo "Verified the separate-verifier runtime at $py"
