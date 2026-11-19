# Register accepted tasks for Qwen acquisition

The OpenEnv stage produces `plan.json` and `files/`. The Qwen intake reads a registered accepted split from an immutable Hugging Face dataset revision. This publisher connects the two stages. Choose an existing private dataset under a new owner/name. The historical repository and its public alias are excluded.

Use the Python environment with the pinned OpenEnv dependencies. From the project root, set `STAGE` to the local output of `openenv_pipeline/run.py stage`, `SOURCE_REPO` to your private destination and `PLAN_SHA` to the reviewed SHA256 of its `plan.json`. These examples assume the default local checkout. If using a different checkout or environment, use its interpreter and source path.

```sh
PY="$PWD/.local/openenv/.venv/bin/python"
export PYTHONPATH="$PWD/.local/openenv/src"
"$PY" -B openenv_pipeline/publish_stage.py check "$STAGE" \
  --repo "$SOURCE_REPO" --plan-sha256 "$PLAN_SHA"
```

The local check verifies the split registration, accepted task IDs, every staged file against both inventories, and the recorded Python file modes. Run the following command when ready to publish. It uses the active Hugging Face token and checks the destination identity and private visibility before writing.

```sh
"$PY" -B openenv_pipeline/publish_stage.py publish "$STAGE" \
  --repo "$SOURCE_REPO" --plan-sha256 "$PLAN_SHA"
```

The historical card merger enforces one accepted registration per task and the 40-task cap per canonical repository across accepted Scale800 configs. It appends the exact JSONL path to `scale800_gate_v1` (Go) or `scale800_py_gate_v1` (Python). Other config values, default selection and card body are preserved. Each new file is captured in memory. A conflicting existing path stops the operation. One commit uses the checked parent SHA. Byte-for-byte immutable readback covers the registered index, all staged files and the updated README.

`$STAGE/registration.json` contains the destination, revision, accepted split path and readback status. Feed that revision and `--source-repo "$SOURCE_REPO"` to the Qwen acquisition command. If a commit response is interrupted, the receipt retains `commit_uncertain` and a second `publish` refuses to submit again. Once the commit revision is known, the following read-only recovery verifies the package and updates the local receipt.

```sh
"$PY" -B openenv_pipeline/publish_stage.py verify "$STAGE" \
  --repo "$SOURCE_REPO" --plan-sha256 "$PLAN_SHA" --revision "$COMMIT"
```
