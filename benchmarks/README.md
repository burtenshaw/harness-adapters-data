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
