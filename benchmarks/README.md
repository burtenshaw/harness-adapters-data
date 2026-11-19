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
