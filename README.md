# Harness adapters data pipeline

Reproduce the coding-task dataset and prepare new benchmark-specific runs. The original pipeline used two routes. Tasksmith generated new tasks from merged Python PRs. OpenEnv also converted existing SWE-smith and SWE-Gym tasks directly. They meet in the final dataset after separate validation and Qwen scoring.

| Route | Inputs and execution | Reproduced result |
| --- | --- | --- |
| Tasksmith / Repo2RLEnv | Reviewed merged PRs → pinned authoring wheel on Modal → reference, known-wrong, alternative and blind-solver controls → Harbor tasks → OpenEnv HF Sandbox validation → eight Terminus-2 Qwen slots per task | 7 + 14 + 3 verified bundles. All 24 passed the HF gate. 21 received eight valid outcomes, three received seven. |
| OpenEnv / Scale800 | Pinned SWE-smith Go, SWE-smith Python and TaskTrove SWE-Gym sources → Harbor drafts → source, image and verifier checks on HF Jobs → repository-stratified Qwen measurement | 227 Go + 490 Python + 130 SWE-Gym = 847 accepted tasks. 131 completed the eight-attempt R3 protocol and 311 completed the four-attempt A4 protocol. |

The final JSONL has **871 tasks**, **463 complete Qwen scores** and **177 rows with both a successful and an unsuccessful attempt**. Of those 177, 171 come from Scale800 and six from Tasksmith. All 871 retain `training_admissible=false`. The historical hand-authored gap tasks and the first Tasksmith pilot were separate experiments. [Immutable dataset release](https://huggingface.co/datasets/harness-hub/harness-adapters/tree/5d320e93b7832c6c66e6a5acd8403fb1a3c50bc6)

## Reproduce the baseline

Run commands from the project root. Choose fresh output directories. The first command downloads two public JSONL files at the release commit, checks their SHA-256s and recomputes the shortlist. The second independently builds both files from the original validation and scoring evidence on the machine that produced it. Python 3.11+ is sufficient for these commands.

```sh
python3 replay/baseline.py runs/public-replay
python3 tasksmith_final/pipeline.py replay \
  "$HOME/.local/share/openenv-tasksmith-final" runs/evidence-replay
```

On the setup machine, the workspace contains a [baseline summary](runs/baseline/summary.json), a [raw-evidence replay](runs/final-replay/publish-summary.json) and the prepared [Squirrel example](runs/baseline/squirrel-task/). The [five native generation replays](runs/tasksmith-replay/) retain the 24 verified task IDs, source PRs and commits that appear in the final release. The two independent routes matched the SHA-256s `13aafbf59d7ae530916cde1e37f1cc6ddc691c6b1e909cf0eb9cb3d8e150c292` (full) and `ea0fd9799e2265295466b91b77dbc2a76731fd4c281fd9aa35aac51834f5f172` (mixed). The original one-task public consumer is in [replay/prepare_squirrel.py](replay/prepare_squirrel.py). Run it from an empty directory with huggingface_hub 1.33.0 installed.

## SEC-bench Pro

The SEC-bench Pro expansion keeps all 344 benchmark cases held out. Tasksmith draws from three Python PRs outside the benchmark that improve compiler coverage diagnostics, source positions and traceback formatting. The prepared plan targets one verified task. The OpenEnv validation and Qwen scoring stages follow generation. [Reproduce the SEC-bench Pro plan](benchmarks/README.md#sec-bench-pro)

## Expand for a different benchmark

1. Copy the benchmark profile and provide its benchmark revision, target capabilities, evaluation exclusions and a reviewed panel of independent merged PRs. Freeze the PR heads, license evidence and source diffs. The screen compares these with existing tasks and the historical quarantine. [Benchmark intake and runnable example](benchmarks/README.md)
2. Prepare a native Tasksmith plan. The worked SQL-parser example is ready locally. It selected `andialbrecht/sqlparse#867` and excluded `#868`, which already occurred in the source history. Its plan digest is `73e2f714dc045668d443a11f461b11f49e022cd506c76058de208e3c426328b2`. The planned candidate has no generated task or score yet. [Intake decisions](runs/sql-parser-gap/intake-report.json) · [Prepared plan and input hashes](runs/sql-parser-gap/prepared/binding.json)
3. On an authorized campaign budget, run the frozen Repo2RLEnv batch, then collect verified bundles. Use the existing full final JSONL as the base, validate and score the additions, and stage the expanded dataset. The guide includes the five historical plans and their recovery inputs. [Tasksmith generation](generation/README.md) · [OpenEnv validation, Terminus-2 scoring and private publication](tasksmith_final/README.md)
4. For existing benchmark task bundles, use the matching OpenEnv converter. Capture the upstream task and source revision, build the Harbor draft, run its controls, then register the accepted split. Freeze a population and collect Qwen outcomes under the corresponding attempt protocol. The final assembler appends new Scale800 IDs to the 871-row baseline and retains earlier Tasksmith rows and scores. A different source representation needs its own converter and gate evidence. [OpenEnv conversion and gates](openenv_pipeline/README.md) · [Private registration](openenv_pipeline/PUBLISH.md) · [Qwen measurement and dataset views](qwen_pipeline/README.md)

The original benchmark targets were Terminal-Bench 2.1, SWE-bench Pro v2.0 Hard and DeepSWE 1.1. These supplied gap and holdout criteria. Measuring model performance on those benchmark evaluations is a separate experiment. The [SWE-bench Verified example](benchmarks/swe-bench-verified.json) exercises a fourth benchmark with all 500 test IDs and their 12 source repositories excluded. Both example profiles select the same independent SQL-parser PR, so one generation run covers that source. The new profile has its own [intake report](runs/swe-verified-sql-gap/intake-report.json) and [native launch plan](runs/swe-verified-sql-gap/prepared/launch-plan.json).

## Runtime and destinations

| Runtime | Source pin | Installed in this workspace |
| --- | --- | --- |
| Repo2RLEnv 0.9.5 / Tasksmith | `61903fe0ed805ea5418811b0fcf399e4144e95e4` | `runs/tasksmith-runtime/`, including the verified worker wheel |
| OpenEnv Scale800 / Qwen | `bb027fa3f7b50718df4b8d8a2312d8bee1760c41` plus the locked historical operators | `.local/openenv/` and `.sources/qwen/` |
| OpenEnv separate-verifier Sandbox | `f802ee4d99136b30041e4dd0b09be3ce6e1062ae`, Harbor 0.25.0, huggingface_hub 1.33.0 and LiteLLM 1.109.1 | `.sources/openenv-tasksmith/` and `.sources/tasksmith-final-venv/` |

For a clean checkout, install Git, uv, Node ≥22.19, DuckDB CLI and GitHub CLI, then run `bash bootstrap.sh` from the project root. It installs the three toolchains, restores the Qwen sources and runs offline checks. Each stage guide also includes its own installation commands. To check all three installed runtimes, the worker wheel, the benchmark screen, a real OpenEnv plan and a simulated append with the baseline, run the following command.

```sh
bash verify.sh --base runs/baseline/views/final_v1/train.jsonl
```

Omitting `--base` exercises a fresh empty dataset. The original private source name, `harness-hub/agentic-coding-envs`, now resolves to the public `harness-hub/harness-adapters` dataset. Use an explicitly named private dataset for fresh task evidence, workers and scores. To retain the existing 871 tasks in a private publication, the private destination needs the baseline and its referenced files at their original paths. The final publisher checks them before appending. Public starter images follow their separate source-only publication procedure.

All worked examples here used local replay, read-only downloads or plan preparation. Run state, datasets and credentials belong outside Git. Billable Modal generation, HF Jobs, inference, and Hub publication have explicit entry points in the stage guides.

## Original threads

| Thread | What was recovered |
| --- | --- |
| [Synthetic RL Task Pipeline](t3-thread://v2/d013e134-6c2d-4190-af72-9a5cb82d2691/8d873981-d2d9-4aa9-8536-ed4bbfb1c5fd) | Source-to-task synthesis, data release and the public one-task recipe |
| [Validate and Score Tasksmith Tasks](t3-thread://v2/d013e134-6c2d-4190-af72-9a5cb82d2691/53f28326-f24a-4427-9026-e202acc7c1d1) | HF Sandbox adaptation, control evidence, eight-attempt scoring and final views |
| [Create Benchmark-Gap Environments](t3-thread://v2/d013e134-6c2d-4190-af72-9a5cb82d2691/115101eb-3acb-43b3-9a85-702efcf93a42) | Benchmark screening, Tasksmith source selection, recovery phases and private exports |
| [Build an OpenEnv RL Pipeline](t3-thread://v2/d013e134-6c2d-4190-af72-9a5cb82d2691/1f093fad-03de-4f23-a9e3-856e37c76ea7) | Real-task acquisition, Harbor adapters, HF control gates and prepared Jobs |
| [Reproduce and Expand Data Pipeline](t3-thread://v2/d013e134-6c2d-4190-af72-9a5cb82d2691/2fbc866a-32fc-478e-a133-01b4240b28fc) | Byte-for-byte dataset replay, independent PR intake for new benchmark targets, and the later APEX expansion |
