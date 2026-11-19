# Measure accepted Scale800 tasks

These commands reproduce the target-only Qwen tool-calling protocol. Repo2RLEnv-generated tasks use the [Terminus-2 scoring route](../tasksmith_final/README.md). Run from the project root with the [Scale800 OpenEnv environment](../openenv_pipeline/README.md).

The evaluator uses Qwen/Qwen3.8-27B with thinking disabled, temperature 0.7, a 48-turn limit, 65,536 maximum output tokens, a two-million-token total budget and a 1,800-second attempt timeout. The original stratified sample used eight attempts (R3). Other frozen population members used four (A4). Preserve the individual protocols when deriving scores. Retain incomplete and missing outcomes.

## Capture the population

Register the gate-accepted source split in a private dataset. Set `SOURCE_REPO` and its immutable `SOURCE_REV` to that registration. Set `RESULTS_REPO` to a private destination for worker inputs, manifests and summaries. They may be the same private dataset. A working Hub token is needed for private reads. [Source registration](../openenv_pipeline/PUBLISH.md)

```sh
PY="$PWD/.local/openenv/.venv/bin/python"
CAMPAIGN="$PWD/runs/my-scale800"
mkdir -m 700 -p "$CAMPAIGN"
python3 openenv_pipeline/run.py accepted --source-repo "$SOURCE_REPO" \
  --revision "$SOURCE_REV" --output "$CAMPAIGN/accepted.json"
"$PY" -B qwen_pipeline/population.py "$CAMPAIGN/population.json" \
  --source-repo "$SOURCE_REPO" --revision "$SOURCE_REV"
python3 qwen_pipeline/draw.py "$CAMPAIGN/population.json" "$CAMPAIGN/draw"
```

The population builder resolves canonical upstream repository identities and verifies native inventories, source digests and image receipts before ranking any task. The draw selects up to six tasks per repository with a recorded seed. Freeze once and reuse the same draw for all measurements in that population. Persist the seed and sample as described in the [population guide](population.md) to obtain an immutable sample manifest for the derived dataset. The original draw covered 825 units, with 158 in the sample and 667 outside. A separate authority admitted 22 later additions outside that original sample.

## Acquire and prepare one task

On a clean checkout run the cache command once. It verifies and expands the bundled operator sources. For Go, the historical cost projection also checks two private receipts. The default cache command picks these up from `~/.local/share/openenv-qwen-difficulty/bulk-v1/` when available. On another machine use `--archive PATH` where `PATH/bulk-v1/` contains the original `retest-cost.json` and `retest-cost-receipts.json`. Python preparation uses the bundled projection and needs neither receipt. This workspace has the cache installed.

```sh
python3 qwen_pipeline/run.py cache
```

Choose a native task ID from `accepted.json`. For Go, also pass `--image-receipts "$RUNTIME_IMAGES"` to acquisition. That directory contains the publication receipts for the task’s pinned starter build. The intake checks the registered row against the private source revision and replays the relevant native gate and image evidence. For Python, the adapter, restore helper, image and gate must match the historical supported version. The generic Go path covers the reviewed text-workspace transfer. Binary or composed Go tasks and Python tasks that require a separate fixture-specific worker need the corresponding qualified adapter. Intake records the blocking reason. Keep the output directory.

```sh
"$PY" -B qwen_pipeline/acquire.py "$CAMPAIGN/accepted.json" "$TASK_ID" \
  "$CAMPAIGN/intake-$TASK_ID" --source-repo "$SOURCE_REPO" --revision "$SOURCE_REV"
RUN="$CAMPAIGN/measure-$TASK_ID"
"$PY" -B qwen_pipeline/run.py prepare \
  "$CAMPAIGN/intake-$TASK_ID/incoming/$TASK_ID" "$RUN" \
  --source-repo "$SOURCE_REPO" --results-repo "$RESULTS_REPO" --draw "$CAMPAIGN/draw"
```

Some older V1/V2 Python acquisitions use both reviewed helper versions, including the historical Conan V1 authority. Supply `--helper-authority PATH_TO_ACQUISITION` for any missing catalog. The compiler verifies source hashes. Operator identity, source gate, complete file inventory, model config, plan and bundle are bound in the build and preparation receipts. The fresh working copy compiles the repository identity selected by `--source-repo` into the gate. The archive keeps its original bytes. Omit `--draw` only for a deliberately eight-attempt R3 preparation. The historical 22 later additions need the archived `--outside-additions PATH` with the original draw.

The installed examples include a [Go four-attempt receipt](../runs/qwen-go-a4/prepared.json) and a [Python eight-attempt receipt](../runs/qwen-python-r3/prepared.json). Both were compiled from real acquisitions and passed the native batch estimator locally. Their results-repo name is an example value. Create fresh runs for actual publication.

## Estimate, submit and collect

Use one shared spend ledger for the campaign. Initialize the ledger once with the owner-approved total allocation. The pinned OpenEnv spend module records reservations atomically across all participating runs. A fresh estimate writes only to the run directory.

```sh
LEDGER="$CAMPAIGN/spend.json"
PYTHONPATH="$PWD/.local/openenv" "$PY" -B -c \
  'import sys; from pathlib import Path; from examples.hub_validation_pipeline import spend; spend.init(Path(sys.argv[1]), sys.argv[2])' \
  "$LEDGER" "$CAMPAIGN_BUDGET_USD"
PLAN_RECEIPT_SHA=$(shasum -a 256 "$RUN/prepared.json" | cut -d' ' -f1)
"$PY" -B qwen_pipeline/batch.py "$RUN" --prepared-sha256 "$PLAN_RECEIPT_SHA" \
  --ledger "$LEDGER" --budget-usd "$RUN_BUDGET_USD"
"$PY" -B qwen_pipeline/collect.py check "$RUN" --prepared-sha256 "$PLAN_RECEIPT_SHA"
```

Review `estimate/manifest.json` and its reservation. For a paid run, repeat the batch command with `--submit` and supply `HF_TOKEN`, `HF_SANDBOX_TOKEN` and `HF_INFERENCE_TOKEN` to the process. That command stages private worker inputs and starts HF Jobs. It uses the reviewed plan digest and a campaign reservation tied to the measurement key. An underfunded submission that failed before any reservation can be rerun at a corrected cap. Each invocation keeps its manifest. Retain submission receipts and reconcile any unknown allocation or charge from those receipts before making a new attempt.

After the known Job is terminal, collect its worker evidence. Supply the current immutable private results-dataset parent to the explicit publication command. The collector reads the committed bytes back before producing a sealed manifest.

```sh
STAGE="$CAMPAIGN/result-$TASK_ID"
"$PY" -B qwen_pipeline/collect.py collect "$RUN" "$STAGE" --prepared-sha256 "$PLAN_RECEIPT_SHA"
"$PY" -B qwen_pipeline/collect.py publish "$STAGE" --parent "$RESULTS_PARENT"
```

If the result already has a verified publication revision, use `collect.py seal STAGE NEW_CAPTURE --revision SHA` for read-only recovery. For several tasks, `collect.py merge OUTPUT_DIR SEALED_DIR...` merges their verified result files. Pass `OUTPUT_DIR/results.json` (or `$STAGE/sealed/results.json` for a single task) to the view builder.

```sh
python3 openenv_pipeline/run.py views --source-repo "$SOURCE_REPO" --results-repo "$RESULTS_REPO" \
  --accepted-capture "$CAMPAIGN/accepted.json" --results-manifest "$STAGE/sealed/results.json" \
  --sample-manifest "$CAMPAIGN/sample-capture/sample-manifest.json" --output "$CAMPAIGN/views"
```

The builder emits the full Scale800 view with per-task score status, the mixed-outcome view and the binding proof. Check `capture-proof.json` for rejected or unavailable evidence. Historical correction, claim and phase-catalog authorities can be replayed separately with `openenv_pipeline/run.py replay-views`. The local campaign commands operate on one measurement at a time. The historical hourly coordinator, legacy outstanding reservations and its paid retries are operational state.
