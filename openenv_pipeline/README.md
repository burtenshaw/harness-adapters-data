# Reproduce the OpenEnv Scale800 branch

The production corpus used two SWE-smith mutation sources and the TaskTrove distribution of SWE-Gym PR repairs. OpenEnv converted their original tests and references to Harbor tasks. Its HF Jobs gate ran NOP, reference, reference replay and declared wrong-answer controls in independent solver and verifier Jobs. It admitted 858 of 1,127 distinct task IDs. The 40-task repository cap left 847 accepted tasks, including 227 Go and 620 Python. Tasksmith supplied a separate expansion of the corpus. [OpenEnv production thread](t3-thread://v2/d013e134-6c2d-4190-af72-9a5cb82d2691/1f093fad-03de-4f23-a9e3-856e37c76ea7) · [Tasksmith expansion](../generation/README.md)

## Install and verify

Run from the project root. The checkout already installed on the original machine lives at `.local/openenv`. A fresh machine needs Git, uv, Python 3.13, the DuckDB CLI for Parquet and the GitHub CLI for authenticated public source reads. Bootstrap fetches an immutable public parent and restores the original working tree at `bb027fa3f7b50718df4b8d8a2312d8bee1760c41`. The included object pack carries the changes needed for that tree. The archive also supplies the historical uv lock, the observed Harbor overlay dependency versions and the SHA256-verified production operators originally kept under an ignored output directory. [Source and dataset pins](pins.json)

```sh
python3 openenv_pipeline/run.py verify
python3 openenv_pipeline/run.py bootstrap
uv sync --project .local/openenv --frozen --group dev --python 3.13
uv pip install --python .local/openenv/.venv/bin/python -r openenv_pipeline/runtime-overlay.requirements.txt
python3 openenv_pipeline/run.py smoke --output runs/openenv-smoke
```

Skip installation if this checkout already exists. Offline bootstrap accepts `--git-source /path/to/OpenEnv` with the pinned public parent present. Another checkout/interpreter can be selected using `--checkout` and `--python` **before** the subcommand. The smoke command builds and rereads a coding-audit bundle through the native cloud plan parser. The original acquisition and prepared-batch CLIs are available through `run.py native real_tasks --help` and `run.py native prepared_batch --help`. The production Scale800 adapters and admission gate have separate commands below.

## Capture a new batch from pinned train data

Choose named task IDs from the pinned Parquet. The three adapters use the original language-specific profile, source and redistribution evidence. They check native tests, immutable upstream identity and license records. The Go and Python SWE-smith readers reconstruct the broken, bug-stage and healthy trees. The TaskTrove reader verifies the native Harbor archive and its per-commit license. The original eligibility screen applies quarantined repositories, PRs, patch/instruction identities, evaluation-only markers and license decisions. For a new benchmark add its held-out identities to the campaign policy and current accepted identities to the existing roster. Keep the original exclusions. Only reviewed training sources belong here. [Eligibility policy and identity schema](operators/eligibility/) · [Benchmark selection](../benchmarks/README.md)

```sh
RUN="$PWD/runs/openenv-expansion"
mkdir -m 700 "$RUN"
FAMILY=swesmith-go
TASK='allegro__bigcache.5aa251c4.func_pm_flip_operators__mlplg9xo'
REPO='SWE-bench/SWE-smith-go'
REV='d2f6ecc2cf8ae1af00fc790801bbacfa2913e015'
PINNED='data/train-00000-of-00001.parquet'
POLICY="$PWD/openenv_pipeline/operators/eligibility/policy.json"
EXISTING="$PWD/openenv_pipeline/operators/eligibility/existing-identities.json"
.local/openenv/.venv/bin/hf download "$REPO" --repo-type dataset --revision "$REV" \
  --include "$PINNED" --local-dir "$RUN/parquet"
python3 openenv_pipeline/run.py capture "$FAMILY" --task "$TASK" \
  --shards "$RUN/parquet" --policy "$POLICY" --existing "$EXISTING" --output "$RUN/source"
```

Repeat `--task` for each instance. The example ID is a replay candidate. For new collection, use IDs absent from the existing roster. Input shards use the following repo-relative paths. All SHA256s are enforced before reading rows. With an archived `network.json` and its verified cached responses, pass one or more `--offline-cache DIR` options to replay without fetching source from GitHub.

| Family | Pinned dataset and revision | Source files and ID |
|---|---|---|
| `swesmith-go` | SWE-bench/SWE-smith-go, `d2f6ecc2cf8ae1af00fc790801bbacfa2913e015` | `data/train-00000-of-00001.parquet`, native `instance_id` |
| `swesmith-py` | SWE-bench/SWE-smith-py, `77cab9055d42ab4a5c25c89a8f937096db13558e` | All eleven `data/train-*.parquet` shards, native `instance_id` |
| `swegym` | open-thoughts/TaskTrove, `946884702046be1a7dcea2638186ad6b0d2ea103` | `laion__swegym-tasks-patched-validated-v5/tasks.parquet`, a `swegym-NNNN` ID |

Inspect `source/decisions.json` and `source/capture.json`. Eligible rows move to `candidates.jsonl`. To rescreen pre-existing candidate JSONL independently, run `run.py screen --candidates FILE --policy FILE --existing FILE --output FRESH.jsonl`. Score-null or rejected inputs remain in their original disposition.

## Convert captured sources into Harbor tasks

Use the reviewed manifest and candidate-index SHA256 from `source/capture.json`. The following commands use jq. Go checks the recorded source modes, selected grader and published profile. Keep the default single-package profile when the native test panel is in one Go package. Use `--go-profile all-packages` for the historical multi-package workflow when that matches the source. Supply `--runtime-lock FILE` for Go once a clean amd64 base and its attached registry receipts have been qualified.

```sh
MANIFEST=$(jq -r .manifest "$RUN/source/capture.json")
HASH=$(jq -r .manifest_sha256 "$RUN/source/capture.json")
INDEX=$(jq -r .index_sha256 "$RUN/source/capture.json")
python3 openenv_pipeline/run.py convert swesmith-go --source "$RUN/source" \
  --manifest "$RUN/source/$MANIFEST" --expected-sha256 "$HASH" \
  --index-sha256 "$INDEX" --output "$RUN/drafts"
```

For `swesmith-py` and `swegym`, use the same command with the matching family and omit `--index-sha256`. Conversion preserves private tests, reference payloads and manifest/mode inventories. Each adapter writes its own manifest and blocked reasons. On the original machine `runs/openenv-example/go-draft`, `draft-py` and `draft-gym` contain completed examples from all three source readers.

## Prepare, execute and register the semantic gate

Gate preparation needs the effective task content digest, a reviewed execution JSON and a verified linux/amd64 image receipt for the actual runtime. A Go starter carries the preinstalled dependency cache and excludes task source, Git history, gold and private tests. Python uses the frozen Git patch adapter with independent dependency installation on both sides. The production cohort reused a measured dependency lock per compatible runtime. A new Python runtime requires its own dependency evidence. The plan embeds the complete role list, exact modes, task digest, deadline, approved budget and code hashes.

```sh
python3 openenv_pipeline/run.py gate "$GATE_PROFILE" prepare \
  --task "$TASK_DIRECTORY" --task-sha256 "$TASK_DIGEST" \
  --execution "$EXECUTION_JSON" --image-receipt "$AMD64_RECEIPT" \
  --budget-usd "$TASK_BUDGET" --deadline-utc "$CAMPAIGN_DEADLINE" --output "$RUN/plan"
```

Select `go` or the historical `python-v1`, `python-v2`, `python-v3` profile appropriate to the adapter/execution contract. The worked examples under `runs/openenv-example/gate-input-go` and `gate-input-python` hold qualified task snapshots, verified image receipts and execution JSON. Their sibling `gate-go` and `gate-python` contain fresh, unexecuted plans. They were prepared from recorded qualified source cases (Workiva and Conan).

The paid command consumes a checked plan SHA and the campaign’s shared spend ledger. Existing execution claims prevent redispatch after uncertain completion. Keep the complete execution folder for rejected attempts. Semantic admission requires the manifest, startup, well-formed reward, deterministic replay, oracle maximum, floor gap and canary floor checks to pass. Python also binds dependency identity. [Original gate runner and reservation contract](operators/production/hf-check-gate-v1/RUNNER.md)

```sh
python3 openenv_pipeline/run.py gate "$GATE_PROFILE" execute \
  --plan "$RUN/plan/plan.json" --expected-plan-sha256 "$PLAN_SHA" \
  --spend-ledger "$CAMPAIGN_LEDGER" --reservation-id "$UNIQUE_RESERVATION" \
  --concurrency 2 --execute
python3 openenv_pipeline/run.py terminal-proof --plan "$RUN/plan/plan.json" \
  --plan-sha256 "$PLAN_SHA" --report-sha256 "$REPORT_SHA" \
  --output "$RUN/terminal.json"
```

Supply `HF_SANDBOX_TOKEN` to the runtime. The independent terminal check queries the recorded Job IDs and owned creation labels and checks the actual image, role and terminal state. It creates no Jobs. Register passing tasks with a JSON array of `task_id`, `upstream_repo`, `plan_path`, `plan_sha256`, `report_sha256`. Python also needs `terminal_proof_path` and `terminal_proof_sha256`. File paths may be relative to the roster. For an expansion, supply every existing accepted split index across Go and Python to enforce the historical 40-task cap before staging.

```sh
python3 openenv_pipeline/run.py stage "$LANGUAGE" --roster "$RUN/roster.json" \
  --campaign "$CAMPAIGN_ID" --batch "$BATCH_ID" --prior-index "$PRIOR_ACCEPTED_JSONL" \
  --output "$RUN/stage"
```

The stage contains `plan.json`, registered split JSONL, task directories, exact file/mode inventories, gate reports, execution descriptors, image receipts and Python dependency/terminal evidence. Follow the private source-registration instructions for immutable commit and readback. Qwen then consumes the registered source revision, accepted index and matching public starter image receipts. [Source registration](PUBLISH.md) · [Qwen acquisition and scoring](../qwen_pipeline/)

## Rebuild the derived views

Once the accepted splits have been registered, fetch their exact index bytes. `--snapshot` optionally reads a local Hub cache directory ending in `datasets--OWNER--NAME/snapshots/REVISION`. A new private source dataset can contain Go, Python or both. Fresh results may use a second private repository. Use the same source and results IDs used by collection.

```sh
python3 openenv_pipeline/run.py accepted --source-repo "$SOURCE_REPO" \
  --revision "$REGISTERED_REVISION" --output "$RUN/accepted.json"
python3 openenv_pipeline/run.py views --source-repo "$SOURCE_REPO" --results-repo "$RESULTS_REPO" \
  --accepted-capture "$RUN/accepted.json" --results-manifest "$SEALED_RESULTS_JSON" \
  --output "$RUN/views"
```

The results manifest identifies captured summary/config/worker and source-control evidence with immutable locators. Use an explicit `{"records": [], "claims": []}` manifest to derive a new unscored cohort. Optional `--sample-manifest` binds the selected sample and seed. Only completed four-of-four A4 or eight-of-eight R3 measurements produce numeric scores. The best view requires a mixed result. The gate-reuse profile records that generated alternatives and leak audits did not run.

For the November 14 historical view, use the correction-aware refresh. It verifies the private capture read set, collection corrections, phase catalog, sample authority and both expected output SHA256s. The original machine has the capture at the path below. On another machine copy that capture and the pinned sample/catalog objects into the same revision-relative layout. [Authority and output hashes](historical-view-inputs.json)

```sh
CAPTURE="$HOME/.local/share/openenv-derived-views/cycles/20261114T090819Z-9f97d6df82fe4097a07d78ae5369e0e5/capture"
SNAPSHOTS="$HOME/.cache/huggingface/hub/datasets--harness-hub--agentic-coding-envs/snapshots"
python3 openenv_pipeline/run.py replay-views --capture "$CAPTURE" --snapshots "$SNAPSHOTS" \
  --output runs/openenv-history
```

The reproduced historical view has 847 accepted rows, 442 scored, 82 incomplete, 67 scoring and 256 not started. Its best view has 171 rows. A later stage of the project joined the Tasksmith expansion and published a different final population. [Final corpus replay](../replay/)

## Append to the full final corpus

The 871-row `final_v1` release contains 847 Scale800 rows and 24 Tasksmith rows. To add a new Scale800 cohort, derive its views first, then run the CPU-only assembler. It copies existing final rows byte-for-byte, retains their historical Qwen protocol, measurements, sample flags and relative file paths, and appends newly accepted Scale800 IDs in the final 62-column schema. It rejects a reused task ID if any source field differs. It recomputes the mixed-success view across the combined population. [Final corpus baseline](../replay/)

```sh
python3 openenv_pipeline/extend_final.py --base runs/baseline/views/final_v1/train.jsonl \
  --derived "$RUN/views" --tag "$CAMPAIGN_ID" --output "$RUN/combined"
```

For a subsequent batch, pass the previous full final view and its reviewed `--base-sha256`. The original-machine example at `runs/openenv-example/combined/export/` reapplies the corrected 847-row cohort to the 871-row release. It recognized every overlap and reproduced both published final JSONL hashes, including all 177 mixed rows.

The assembler writes a campaign and a stage manifest accepted by the shared private publisher. Use the private source dataset that already contains the baseline view, its referenced artifacts and the newly registered sources at their relative paths. The current published source revision and the parent used below can differ after later result registration. Supply the destination’s current commit SHA as the parent. The publisher registers `final_TAG/train` and the nonempty `final_best_TAG/train` configs, verifies the referenced paths, and reads back the registered files. [Private final publication](../tasksmith_final/README.md)

```sh
.local/openenv/.venv/bin/python tasksmith_final/publish.py "$RUN/combined" \
  --repo "$SOURCE_REPO" --parent "$DEST_PARENT" --base-view views/final_v1/train.jsonl \
  --lock "$RUN/registry.lock"
```

For a new cohort's `in_stratified_sample` values, pass the `sample-manifest.json` produced by the immutable Qwen draw capture to `run.py views --sample-manifest`. A missing published roster leaves membership null. [Qwen population and draw](../qwen_pipeline/)

## Containerize Harbor tasks for HF Sandbox (no Spaces)

To turn any Harbor task directory (Scale800 Go/Python, SWE-Gym, Tasksmith, Flash-Next waves, Knowledge, or Cyber Defense) into HF-Sandbox-ready bundles with digest-pinned, publicly pullable `linux/amd64` `[environment].docker_image` entries in `task.toml`, use `containerize` (backed by [OpenEnv PR #1757](https://github.com/openenv/OpenEnv/pull/1757), `openenv harbor build-images`):

```sh
# 0. On a fresh machine or Slurm cluster node whose pinned OpenEnv predates PR #1757:
python3 openenv_pipeline/run.py containerize --bootstrap-openenv-images

# 1. Audit, classify (oci_append vs kaniko/docker build vs shared verify) and deduplicate:
python3 openenv_pipeline/run.py containerize "$TASKS_DIR" --plan --json

# 2. Build/append in parallel via Kaniko on HF Jobs -> one multi-tag GHCR repo (no Spaces or local Docker):
#    Note: ensure the target GHCR package is set to Public once on GitHub so HF Sandbox can pull anonymously.
export GHCR_TOKEN=... GHCR_USERNAME=burtenshaw HF_TOKEN=...
python3 openenv_pipeline/run.py containerize "$TASKS_DIR" \
  --source-manifest "$EXPORT/verified.jsonl" \
  --registry ghcr.io/harness-hub/tasksmith-flashnext \
  --builder kaniko --namespace harness-hub --flavor cpu-upgrade \
  --cache-repo ghcr.io/harness-hub/tasksmith-flashnext-cache \
  --concurrency 16 \
  --per-task-receipts-dir "$RUN/images" \
  --output-dir "$RUN/harbor-ready" \
  --receipts "$RUN/image-receipts.json"

# 3. Preflight-verify every task.toml points to a publicly pullable linux/amd64 digest:
python3 openenv_pipeline/run.py containerize "$RUN/harbor-ready" \
  --verify-only --require-digest-pin
```

Declarative `COPY`/`WORKDIR`/`ENV`-only Dockerfiles (such as Go SWE-smith tasks built on a per-repo base) use pure-Python OCI layer append with zero Docker daemon or HF Jobs overhead; `RUN` Dockerfiles fan out in parallel through Kaniko on HF Jobs (`--builder kaniko`) or local/VM BuildKit (`--builder docker`). Pass `--extra-dockerfile harness.Dockerfile` to layer target agent harnesses (`pi`, `opencode`, `hermes`) without maintaining separate build scripts.
