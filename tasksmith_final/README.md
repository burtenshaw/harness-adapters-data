# Validate and score Tasksmith bundles

This is the HF Sandbox route used for the 24 accepted Repo2RLEnv tasks. It adapts the original no-network Python bundles, checks a do-nothing agent and two oracle runs, and measures Qwen with Harbor Terminus-2. The [parent thread](t3-thread://v2/d013e134-6c2d-4190-af72-9a5cb82d2691/53f28326-f24a-4427-9026-e202acc7c1d1) and [execution thread](t3-thread://v2/d013e134-6c2d-4190-af72-9a5cb82d2691/thread:delegated-task:command%3Amcp%3A4f4bf50a-210f-4c33-9283-6ec2e2fcac21%3Adelegate-task%3A2546b0df-164e-4808-837f-ed4dd69787c2) record the original decisions.

## Rebuild the November 16 final views offline

From the project root, choose an unused private output directory. Python 3.11+ handles the replay with its standard library.

```sh
python3 tasksmith_final/pipeline.py replay \
  "$HOME/.local/share/openenv-tasksmith-final" runs/final-replay
```

The command reads the retained native reports, task bundles, image receipts and eight attempt records per task, checks the original input hashes and rebuilds both JSONL files. The expected final revision of the private `harness-hub/agentic-coding-envs` dataset is `5d320e93b7832c6c66e6a5acd8403fb1a3c50bc6`. Its source revision is `3e8cb13c7e734d0d4dc2b6e7b13f01f32f9cb5d6`. The replay checks both files byte for byte.

| Replayed view | Rows | SHA-256 |
|---|---:|---|
| `final_v1` | 871 | `13aafbf59d7ae530916cde1e37f1cc6ddc691c6b1e909cf0eb9cb3d8e150c292` |
| `final_best_v1` | 177 | `ea0fd9799e2265295466b91b77dbc2a76731fd4c281fd9aa35aac51834f5f172` |

The full view has 847 real tasks and 24 Tasksmith tasks. Of 192 attempt slots, 189 had a valid reward. Twenty-one tasks had eight valid attempts, three had seven. Six Tasksmith tasks met the best-view rule (0 < solved < valid attempts). The five added columns identify the origin and HF adaptations. Historical script hashes are in [historical_sources.json](historical_sources.json). The private task contents and credentials stay outside this checkout.

## Prepare an expansion

Use the [generation export](../generation/) containing `verified.jsonl`, `tasks/` and `provenance/`. A new campaign can retain a prior 62-column final view, consume a 57-column scale800 view, or start from an empty JSONL for a Tasksmith-only cohort. A best-view input would exclude the remaining baseline rows.

```sh
export SOURCE=runs/my-generation-export
export BASE=runs/final-replay/views/final_v1/train.jsonl
export RUN_DIR=runs/expansion-validation
python3 tasksmith_final/pipeline.py init "$RUN_DIR" \
  --sources "$SOURCE" --split "$SOURCE/verified.jsonl" --base "$BASE" --tag v2
```

Supply additional `--split` arguments in priority order, with the newest recovery last. Later verified copies win within the new candidate set. An existing Tasksmith ID with the same source PR and commit keeps its previous scored row. A conflicting identity stops preparation. The version tag controls new task and view paths. Records carry a digest of the local input selection unless you supply the source dataset commit with `--revision`.

## Recreate the live runtime

The historical workers used [OpenEnv PR 1632](https://github.com/openenv/OpenEnv/pull/1632) at `f802ee4d99136b30041e4dd0b09be3ce6e1062ae`, Harbor 0.25.0, huggingface_hub 1.33.0, LiteLLM 1.109.1 and OpenAI 3.51.0. Run the bootstrap from the project root with Git and uv installed.

```sh
bash tasksmith_final/bootstrap.sh
export PY="$PWD/.sources/tasksmith-final-venv/bin/python"
```

The bootstrap selects CPython 3.13.14, fetches the exact OpenEnv commit, installs Harbor’s HF Sandbox dependencies and checks all 142 recovered package versions and the validator source. An existing clean checkout and virtual environment are reused. To use a local Git source and cached wheels, run `UV_OFFLINE=1 bash tasksmith_final/bootstrap.sh .sources /path/to/original/OpenEnv`. The retained source on this machine is `~/.t3/worktrees/OpenEnv/t3-0ec43381-72c2b845b07133ab`.

[runtime-constraints.txt](runtime-constraints.txt) contains the installed mandatory dependency closure from the original macOS arm64 scoring environment. Linux also resolves the platform-specific keyring dependencies SecretStorage and jeepney. Archival versions for those two are unavailable. Export uses PyArrow 26.0.1 when writing rejected-task Parquet, installed separately from the historical scoring closure. The HF Jobs starter images themselves use pinned Linux/amd64 digests.

### Starter images

For previously built starters, supply their existing resolved receipts. The local adapter checks every starter file against its build receipt.

```sh
python3 tasksmith_final/pipeline.py prepare "$RUN_DIR" --images "$RECEIPTS_DIR"
```

For new starters, the following distinct operations write to the Hub. Set `HF_TOKEN` for the chosen Space namespace. Use the recovered `starter_images.py` from the [OpenEnv pipeline checkout](../openenv_pipeline/) at `bb027fa3f7b50718df4b8d8a2312d8bee1760c41`.

```sh
"$PY" tasksmith_final/pipeline.py publish-images "$RUN_DIR" --namespace "$SPACE_OWNER"
"$PY" tasksmith_final/pipeline.py resolve-images "$RUN_DIR" --starter-images "$STARTER_IMAGES_PY"
"$PY" tasksmith_final/pipeline.py prepare "$RUN_DIR"
```

Each starter is a Docker Space. Its context consists of the Space README, `environment/Dockerfile` and `environment/source/`. The builder audits private test and solution separation, creates the Space privately, reads back its committed files, then makes it public. When the build finishes, resolution pins the Linux/amd64 digest and pauses the Space. Repeat `resolve-images` while builds are pending. Public visibility is part of this historical route and requires source code approved for public distribution.

The adapted task runs with network access and as root, replacing the original learner/root user split. Harbor uploads the private tests to a separate verifier sandbox at grading time and copies submitted artifacts across. The original and modified bundles have separate paths. The transform checks the original Dockerfile, shell and TOML shapes before applying the changes. Other languages or verifier layouts require their own adapter.

### Validation and Qwen scoring

Both commands show an offline estimate by default. The historical ledger reserved $5 for the first validation task, $5 for the next 23 and $150 for Qwen’s 192 slots. The recorded settlements were $0.03, $0.57 and $22.10. The new estimate reserves $5 for the validation canary and $5 per subsequent group of up to 23. Scoring prorates the historical reservation at $6.25 per eligible task. The shared ledger enforces the authorized reservation. Provider billing can differ.

Use the restored OpenEnv spend tool (default `.local/openenv/examples/hub_validation_pipeline/spend.py`). Set `CAMPAIGN_LIMIT_USD`, `VALIDATION_CAP_USD` and `SCORING_CAP_USD` to the new campaign’s approved amounts. Initialize the ledger once, or point to the same initialized ledger as other stages of this campaign.

```sh
export LEDGER=runs/my-campaign-spend.json
python3 tasksmith_final/admission.py "$LEDGER" --limit-usd "$CAMPAIGN_LIMIT_USD"

# Review each estimate before submitting its exact plan hash.
python3 tasksmith_final/pipeline.py validate "$RUN_DIR" --namespace "$JOBS_OWNER" > "$RUN_DIR/validation-estimate.json"
cat "$RUN_DIR/validation-estimate.json"
VALIDATION_PLAN=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["plan_sha256"])' "$RUN_DIR/validation-estimate.json")
"$PY" tasksmith_final/pipeline.py validate "$RUN_DIR" --namespace "$JOBS_OWNER" \
  --submit --plan-sha256 "$VALIDATION_PLAN" --ledger "$LEDGER" --budget-usd "$VALIDATION_CAP_USD"

python3 tasksmith_final/pipeline.py score "$RUN_DIR" --namespace "$JOBS_OWNER" --concurrency 1 > "$RUN_DIR/scoring-estimate.json"
cat "$RUN_DIR/scoring-estimate.json"
SCORING_PLAN=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["plan_sha256"])' "$RUN_DIR/scoring-estimate.json")
"$PY" tasksmith_final/pipeline.py score "$RUN_DIR" --namespace "$JOBS_OWNER" --concurrency 1 \
  --submit --plan-sha256 "$SCORING_PLAN" --ledger "$LEDGER" --budget-usd "$SCORING_CAP_USD"
"$PY" tasksmith_final/pipeline.py stage "$RUN_DIR" runs/expansion-private-export
```

Supply `HF_TOKEN` for the sandbox and `OPENAI_API_KEY` for the HF router only for live work. Each submission records a stage-specific receipt under `RUN_DIR` and checks that the reservation remains active before starting each validation task or new scoring slot. A failed canary stops the validation wave. A validation log with no complete report needs Job reconciliation before retry. Scoring recovery uses the existing run ID to inspect and clean up owned Jobs, preserves recorded attempts and marks interrupted slots null. A completed CLI invocation leaves the hold reserved until the operator reconciles provider usage. With verified billing evidence, settle the receipt’s `id` on the same ledger.

```sh
python3 .local/openenv/examples/hub_validation_pipeline/spend.py --ledger "$LEDGER" settle \
  --id "$RESERVATION_ID" --usd "$VERIFIED_USD" --evidence "$BILLING_RECEIPT"
```

Validation uses the historical six checks, a do-nothing reward below one, an oracle and replay reward of one, and verified cleanup. A report can have an overall WARN and pass this gate. Only passing bundles go to scoring. Invalid or missing evidence cannot produce a passing task.

Each task gets eight slots at `qwen38-terminus2-hfsandbox-64k-2m-nothink-tasksmith-v1`. The local controller calls DeepInfra through the HF router; the agent workspace and separate grader run in HF Jobs. The model is Qwen/Qwen3.8-27B, temperature 0.7, reasoning effort none, 48 turns, 65,536 output tokens, 262,144 context, 2M total tokens and 1,800 seconds. The historical Terminus wrapper grades the workspace on budget stop or agent timeout. Infrastructure errors retain a null outcome. Restarting the same scoring directory preserves existing slots and marks interrupted work null. The separate scale800 tool-calling R3/A4 protocols use different attempt budgets and runtime assumptions.

Staging preserves the baseline rows and their task paths. It includes original generation bundles and provenance for new tasks, adapted bundles, inventories, validation evidence and all attempt records. Current Tasksmith rows keep the historical quarantine and training-admissibility fields. Rejected tasks go into a Parquet config when present. The two principal views use the campaign version tag.

### Append the private export

A private mirror can be the destination. Mirror the original dataset card, exact baseline JSONL, complete baseline task directories, inventories, adapter code, source provenance, image receipts, validation and scoring evidence at the same repository-relative paths. A copy of the view alone cannot resolve these rows. External image pins must remain pullable by the Jobs account. The publisher checks every final row’s nonempty `*_path` against the committed baseline and the new payload.

The publisher verifies the exact destination ID and private visibility, pins the parent commit, checks the baseline view hash and existing config names, and reads back the committed bytes. It takes the same filesystem lock used by other publishers to that dataset. Set `HF_TOKEN` for private dataset write access. Supply the actual baseline path in that dataset.

```sh
"$PY" tasksmith_final/publish.py "$RUN_DIR" \
  --repo "$PRIVATE_DATASET" --parent "$PARENT_SHA" \
  --base-view views/final_v1/train.jsonl --lock "$SHARED_DATASET_LOCK"
```

The first commit adds new task files and evidence. The second adds the new views and card entries. Previously published original source paths may be reused when their bytes match. An ambiguous commit leaves a local publication receipt marked pending for reconciliation. The standard library smoke test exercises the new-campaign path; `--mock-publish` also tests both commits and retry against an in-memory private Hub.

```sh
python3 tasksmith_final/smoke.py
"$PY" tasksmith_final/smoke.py --check-budget --mock-publish --base "$BASE"
```
