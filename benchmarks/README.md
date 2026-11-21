# Prepare an expansion for another benchmark

A benchmark profile describes the target capabilities, pinned benchmark repositories, known holdout PRs, repository lineages and task IDs. A panel lists merged public Python PRs with evidence that they exercise those capabilities. Benchmark evaluation instances stay in the exclusion list. The source-specific quality and base-model measurements happen after intake. [Generation](../generation/README.md)

The example uses the original three benchmark revisions and two SQL parsing PRs. The sample selects `andialbrecht/sqlparse#867`, a historical alternate that had been deferred to keep the original panel diverse. It removes `#868` because that source is already represented. The dependency on each benchmark’s capability is an operator judgment. Matching identifiers and hashes provides a narrower check than semantic non-overlap.

## Prepare a private run

Run from the project root with the Tasksmith environment installed. Use fresh output directories. The project on the original machine already has the worked example at `runs/sql-parser-gap/`. Choose another path to replay it.

```sh
PY="$PWD/runs/tasksmith-runtime/Repo2RLEnv/.venv/bin/python"
RUN="$PWD/runs/sql-example-replay"
python3 replay/baseline.py runs/baseline
"$PY" -IB generation/campaign.py freeze benchmarks/example-panel.json runs/sql-example-intake
python3 benchmarks/prepare.py benchmarks/original-benchmarks.json \
  runs/sql-example-intake/panel.json "$RUN"
"$PY" -IB generation/campaign.py prepare "$RUN/generation-spec.json" "$RUN/prepared" \
  --frozen-records runs/sql-example-intake/frozen-records.json
```

Skip the baseline command if `runs/baseline/views/final_v1/train.jsonl` already exists. The screen checks those bytes against the published 871-row baseline digest. `freeze` resolves PRs and license blobs using read-only GitHub calls. On the original machine, append the option below to the freeze command for an entirely offline replay of the example.

```sh
--source-evidence "$HOME/.t3/worktrees/OpenEnv/ben-benchmark-gap-envs/examples/tasksmith_campaign/outputs/expansion-v2/candidates/all-candidates.json"
```

For another benchmark, copy `original-benchmarks.json`, replace its benchmark names, repository pins and capability tags, and fill its known `holdout_repos`, `holdout_prs` and `holdout_task_ids`. Set the campaign name, verified target and admission budget. In the panel, supply each PR’s URL, capability tags and reviewed source license (`spdx` and repository-relative `path`). The optional `expected` and `license.sha256` fields shown in `example-panel.json` are populated by `freeze` for new PRs and checked when already present. Include `repository_lineage` for known upstream/fork aliases, and supply known `source_task_ids` and evaluation-only flags.

The screen uses the archived 105 quarantined repositories, 253 benchmark task IDs, seen Tasksmith identities and diff hashes, plus the final baseline and new profile exclusions. Pass `--accepted <jsonl>` once per additional accepted roster to suppress repeats from subsequent campaigns. The intake report records every selection and rejection, input checksums and benchmark revisions. If the panel has fewer eligible PRs than the requested target, the command writes its report and exits 2. Add reviewed candidates or adjust the target before preparing another directory. A fresh candidate advances to generation with training admission still unset.

```sh
python3 -B -m unittest benchmarks.test_prepare
```

## SWE-bench Verified

The second profile pins the official benchmark code and the single `test` Parquet shard from `princeton-nlp/SWE-bench_Verified`. Its SHA-256 is `a45b1fe4e2f0c8390b2b2938ac83e92ed5979000856808f3679c07812e9e6dcd`. Projecting only `repo` and `instance_id` yielded 500 distinct instances across 12 repositories. The official collector constructs each ID from the repository name and the pull-request number. All 500 corresponding URLs were independently resolved as merged pull requests through GitHub. The profile carries these task IDs, repositories and PRs as exclusions. [Profile](swe-bench-verified.json) · [Benchmark collector at the pinned commit](https://github.com/SWE-bench/SWE-bench/blob/02e7a74ffd0b707aab73d203fe87bdc7c76afc8e/swebench/collect/build_dataset.py#L35-L40) · [Pinned dataset](https://huggingface.co/datasets/princeton-nlp/SWE-bench_Verified/tree/c104f840cc67f8b6eec6f759ebc8b2693d585d4a)

The worked run preserves the 500 GitHub GraphQL results in `runs/swe-verified-sql-gap/pull-request-readback.json`, SHA-256 `900cfff169a57c2e4bf9c9275af289d28f26387a486c8811ae0108120a74cd28`. Each record contains the instance ID, GitHub node ID, PR number, canonical URL and merged flag. To corroborate a refreshed profile, query `repository(owner:OWNER,name:REPO){pullRequest(number:N){id number url merged}}` for each instance, using the suffix for `N`. Verify the returned number, canonical URL and `merged == true`. The receipt sorts by instance ID and uses compact key-sorted JSON followed by one newline.

The worked plan uses the independent SQL panel as a Python maintenance example. It selected `andialbrecht/sqlparse#867` and excluded the previously seen `#868`. Only `#867` and its native source record enter task authoring. The profile makes no measurement of benchmark performance. Reuse the frozen SQL intake from the first example, or set `INTAKE` to the panel directory produced by the `freeze` command above. [Original upstream PR](https://github.com/andialbrecht/sqlparse/pull/867)

```sh
PY="$PWD/runs/tasksmith-runtime/Repo2RLEnv/.venv/bin/python"
INTAKE="$PWD/runs/sql-parser-gap/intake"
RUN="$PWD/runs/swe-verified-sql-replay"
python3 benchmarks/prepare.py benchmarks/swe-bench-verified.json "$INTAKE/panel.json" "$RUN"
"$PY" -IB generation/campaign.py prepare "$RUN/generation-spec.json" "$RUN/prepared" \
  --frozen-records "$INTAKE/frozen-records.json"
```

The worked output is `runs/swe-verified-sql-gap/prepared/launch-plan.json`, SHA-256 `d58d12d28fbf2d520855a43b8c6a9f03e29ce2db138104674cb52fb46c4fa101`.

## SEC-bench Pro

Use the profile to prepare diagnostic-maintenance tasks from repositories outside SEC-bench Pro. The official benchmark evaluates vulnerability discovery and proof-of-concept generation. This project uses its case identifiers and repository lineages as exclusions. Qwen scores collected downstream describe the generated maintenance tasks. [Official benchmark overview](https://sec-bench.github.io/) · [Pinned profile](sec-bench-pro.json)

The pinned GitHub tree contains **344 cases** across V8 (103), SpiderMonkey (104) and Linux (137). The intake excludes each case in both native and project-qualified form. A separate read of the `project` and `instance_id` columns in the pinned Hugging Face test split found **183 distinct IDs**. All 183 matched GitHub exactly. GitHub also contains 24 additional SpiderMonkey and 137 Linux cases. The profile records both revisions and the SHA-256 of each sorted ID list. [GitHub revision](https://github.com/SEC-bench/SEC-bench-Pro/tree/da80928ee20dc417ca6a068a1213e1d9d279df20) · [Hugging Face revision](https://huggingface.co/datasets/SEC-bench/SEC-bench-Pro/tree/226b7a006e1b0e3c24d20a17fff9934609901fc1)

| Merged source PR | Behavior the upstream tests exercise |
| --- | --- |
| [gcovr #1075](https://github.com/gcovr/gcovr/pull/1075) | Attach the filename and source line to coverage-counter diagnostics. |
| [asttokens #174](https://github.com/gristlabs/asttokens/pull/174) | Map tokens back to source positions across mixed line endings. |
| [stack_data #20](https://github.com/alexmojaki/stack_data/pull/20) | Align traceback markers with the highlighted multiline expression. |

The panel pins each PR's base, head, diff digest and license bytes. All three cleared the historical quarantine, the 871-row baseline and this workspace's 15-row APEX Tasksmith roster. The default pilot targets one verified task with a USD 48 generation admission budget. These are preparation settings. Generation, validation, scoring and publication have separate execution steps. [Frozen panel](sec-bench-pro-panel.json)

Run from the project root after installing the runtimes and materializing `runs/baseline` as described above. Choose a fresh `RUN` directory. The first command compares the profile against upstream Git tree metadata. For offline verification, omit `--github`. The freeze step reads the three independent PRs from GitHub.

```sh
PY="$PWD/runs/tasksmith-runtime/Repo2RLEnv/.venv/bin/python"
RUN="$PWD/runs/sec-bench-pro-replay"
python3 -B benchmarks/sec_bench_pro_inventory.py --github
"$PY" -IB generation/campaign.py freeze benchmarks/sec-bench-pro-panel.json "$RUN/intake"
python3 -B benchmarks/prepare.py benchmarks/sec-bench-pro.json \
  "$RUN/intake/panel.json" "$RUN/screen"
"$PY" -IB generation/campaign.py prepare "$RUN/screen/generation-spec.json" \
  "$RUN/prepared" --frozen-records "$RUN/intake/frozen-records.json"
```

For an offline replay on the setup machine, reuse `runs/sec-bench-pro/intake` in the last two commands. To repeat the APEX overlap check, also pass `--accepted runs/apex-agents-gap/downstream/export/verified.jsonl` to `benchmarks/prepare.py`. The worked plan is `runs/sec-bench-pro/prepared/launch-plan.json`, SHA-256 `d1c2339ec5c5edcaecb1bbc8bbc30d6bbca09e6aaae23aab17bbda3a0ff2067f`.

For a live expansion, use the prepared run directory in the native batch and collect commands. Once collection produces a verified export, use its `verified.jsonl` as the OpenEnv input, the full `final_v1` view as the base and `sec_bench_pro_v1` as the new dataset tag. Each accepted addition goes through the do-nothing and two reference controls before the eight-slot Qwen protocol. [Tasksmith batch and collection](../generation/README.md#run-a-new-campaign) · [OpenEnv validation and Qwen scoring](../tasksmith_final/README.md#prepare-an-expansion)
