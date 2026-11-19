# Generate and collect native Tasksmith tasks

Repo2RLEnv 0.9.5 at `61903fe0ed805ea5418811b0fcf399e4144e95e4` turned merged public Python PRs into Harbor task directories. The expansion used the native `tasksmith batch` controller. Each candidate started from the PR head with its source patch reversed. Its private verifier and reference solution travelled with the operator bundle. [Pinned source intake](https://github.com/huggingface/Repo2RLEnv/blob/61903fe0ed805ea5418811b0fcf399e4144e95e4/src/repo2rlenv/tasksmith/source.py) · [Pinned batch controller](https://github.com/huggingface/Repo2RLEnv/blob/61903fe0ed805ea5418811b0fcf399e4144e95e4/src/repo2rlenv/tasksmith/batch.py)

## Install the runtime

Run these commands from the project root with Git, uv, Python 3.12 and Node ≥22.19 available. The bootstrap checks out the source, syncs its frozen Python lock, verifies the author runtime packages, and builds the worker wheel with the historical uv 0.13.7 generator. The checked wheel SHA256 is `49589871dc0acf0286bfa11a2c8a4a84eae2aedd775f13d05cc78ae23b6236c6`. The optional second argument to bootstrap accepts a local Git clone.

```sh
bash generation/bootstrap.sh runs/tasksmith-runtime
PY="$PWD/runs/tasksmith-runtime/Repo2RLEnv/.venv/bin/python"
CLI="$PWD/runs/tasksmith-runtime/Repo2RLEnv/.venv/bin/repo2rlenv"
WHEEL="$PWD/runs/tasksmith-runtime/dist/repo2rlenv-0.9.5-py3-none-any.whl"
```

## Prepare a new benchmark

Use the roster and benchmark screen to select independent PRs and prepare a native batch plan. The example produces `runs/sql-parser-gap/prepared/launch-plan.json`. The private plan contains source diffs. [Benchmark setup](../benchmarks/README.md)

The initial expansion profile in `options.json` is byte-identical to the original. It runs OpenCode 1.19.5 and Anthropic Sonnet 4.6 on two-CPU, 4096 MiB Modal workers. It allows two concurrent candidates, two author attempts per stage, two repairs, two grounded read rounds and four probes. The quality loop checks the baseline and reference, a known-wrong implementation, a valid alternative and a blind Terminus-2/Sonnet rollout. A legitimate blind failure can verify a sound task. The downstream Qwen difficulty score has its own protocol.

## Run a new campaign

The following commands initialize an internal budget ledger and start paid generation. Set `CREDENTIALS_FILE` to your private dotenv containing `ANTHROPIC_API_KEY` and the Modal profile/config path. The sample profile reserves an admission budget of USD 48 for its one source. Set your campaign budget in the benchmark profile before preparing a different panel. Native reservations control admission. Provider invoices and worker reconciliation are separate.

```sh
RUN="$PWD/runs/sql-parser-gap"
BUDGET=$("$PY" -c 'import json,sys; print(json.load(open(sys.argv[1]))["max_spend_usd"])' "$RUN/prepared/launch-plan.json")
"$CLI" campaign init "$RUN/campaign" --budget-usd "$BUDGET" --json
(
  umask 022
  env -i PATH="$PATH" HOME="$HOME" TMPDIR="${TMPDIR:-/tmp}" \
    "$CLI" tasksmith batch "$RUN/prepared/launch-plan.json" \
      --campaign "$RUN/campaign" --output "$RUN/batch" \
      --runtime-wheel "$WHEEL" --env-file "$CREDENTIALS_FILE" --json
)
```

The outer run directory is mode 0700. A 022 umask inside it preserves permissions the unprivileged verifier needs for staging and execution. Keep `batch/`, the internal ledger and all worker receipts. Upstream can resume undispatched sources with an identical plan, wheel, ledger and output path. A `drain-request.json` in the batch output stops new admissions while children finish. Independently confirm each owned worker reached a terminal state and reconcile retained reservations before progressing a live campaign. The report records rejected tasks and pending sources even when the panel is exhausted below its target.

After a terminal batch, copy the verified bundles into the input format used by the OpenEnv/Qwen stage.

```sh
"$PY" -IB generation/campaign.py collect "$RUN/prepared" "$RUN/batch" "$RUN/export"
```

`export/verified.jsonl` has the source PR, head commit, license, native bundle hash and relative task/provenance paths. The collector replays upstream `verified_result` over the original trials, binds the labeled copy to the frozen PR, checks the bundled license and verifies the copied tree’s bytes and modes. `export/generation-report.json` records the batch report digest and all reported candidate statuses. Retain the original batch alongside the export for raw author, solver, trial and repair evidence. The package includes private tests and solutions. The downstream adapter builds learner starter images from the environment subtree. [Validation and scoring](../tasksmith_final/README.md)

## Replay the original generation evidence

On the original machine the private archive is `$HOME/.t3/worktrees/OpenEnv/ben-benchmark-gap-envs/examples/tasksmith_campaign/outputs`. Its five native plans preserve the reviewed per-source profiles, prepared packages, probes, prior result paths and shared ledger lineage. The benchmark-gap thread separately produced hand-authored `synthetic_gap_*` examples and the pilot `tasksmith_gap_v1`. The final native cohort was selected from `tasksmith_gap_v2`, `v3` and `v4`. [Create Benchmark-Gap Environments](t3-thread://v2/d013e134-6c2d-4190-af72-9a5cb82d2691/115101eb-3acb-43b3-9a85-702efcf93a42) · [Validate and Score Tasksmith Tasks](t3-thread://v2/d013e134-6c2d-4190-af72-9a5cb82d2691/53f28326-f24a-4427-9026-e202acc7c1d1)

| Native plan below the archive | Selected PRs | What happened |
| --- | ---: | --- |
| `expansion-v2/launch-plan.json` | 24 | Fresh batch, target 12, shared USD 600 admission scope. |
| `expansion-v2/phase2/launch-plan.json` | 24 | Continued after correcting execution-directory permissions and supplying six source-bound profiles. Seven native passes. |
| `expansion-v3/recovery/launch-plan.json` | 14 | Eight prepared profiles and six previously constructed bundles yielded 14 more native passes. Three NetworkX sources stayed blocked. |
| `expansion-v4/native/launch-plan.json` | 3 | Multi-file sources with prepared profiles, Sonnet review and Opus escalation. Initial batch yielded zero new passes. |
| `expansion-v4/recovery/launch-plan.json` | 3 | Source-specific repairs and Opus review, with Sonnet blind solver, added the final three. |

Prepare and replay a historical phase in a **fresh** private output directory. This reads saved results without launching workers. On another machine, historical recovery plans require their referenced source artifacts and prior evidence. A fresh expansion builds its own paths from its new inputs.

```sh
ARCHIVE="$HOME/.t3/worktrees/OpenEnv/ben-benchmark-gap-envs/examples/tasksmith_campaign/outputs"
REPLAY="$PWD/runs/native-v3-replay"
"$PY" -IB generation/campaign.py prepare generation/expansion-v2.json "$REPLAY/prepared" \
  --frozen-records "$ARCHIVE/expansion-v2/candidates/frozen-sources.json" \
  --recorded-plan "$ARCHIVE/expansion-v3/recovery/launch-plan.json"
"$PY" -IB generation/campaign.py collect "$REPLAY/prepared" \
  "$ARCHIVE/expansion-v3/recovery/batch" "$REPLAY/export"
```

Use `generation/expansion-v2.json` for the first three plans, and `generation/multifile-v4.json` with `expansion-v4/candidates/frozen-sources.json` for the last two. Supply the matching phase’s `launch-plan.json` and `batch/`. All five plan digests are recorded in `generation/campaign.py`. Omitting `--recorded-plan` builds a new plan with the v2 initial quality profile. With the historical v2 intake this reproduces the original 305,598-byte launch plan at SHA256 `89c98532060cef20e9ed965c8d554e6cdb0b399f3db51a66c0a74c3e51065a38`.
