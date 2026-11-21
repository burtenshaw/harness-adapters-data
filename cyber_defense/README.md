# Defensive authorization audits

This experiment measures a model's ability to read an access policy and determine who can access a resource. Each episode starts with the case text and ends with a single JSON submission. The 1,000-case cohort uses an OpenEnv source converter. Tasksmith's PR-generation pilot and the SEC-bench Pro evaluation set have separate results.

| Task family | Count | What the model returns |
| --- | ---: | --- |
| Cedar | 610 | Decisions, determining policy IDs and evaluation errors for 3–4 requests |
| OpenFGA Check | 140 | A decision for every access check in a panel |
| OpenFGA ListObjects | 250 | The exact sorted set of accessible object IDs |

Fourteen Cedar panels use a native upstream fixture. The other 596 compose two upstream policies and include derived requests. The 610 panels cover 143 constituent fixtures. OpenFGA cases use upstream Check and ListObjects assertions from 147 model-and-relationship groups. Source commits, fixture hashes, derivation details and validation methods accompany each answer. The holdout check compares source repositories and native identities against the pinned 344-case SEC-bench Pro inventory.

## Use the dataset

`prompts.jsonl` contains the learner-facing task IDs and instructions. `tasks.jsonl` contains the same cases with answers and provenance for the evaluator. Supply only the prompt to a model. Join scores to tasks on both `task_id` and `task_sha256`.

`rollouts/scores.jsonl` contains the solve count, pass rate, difficulty and 95% Wilson intervals for each fully measured task. Difficulty equals one minus the fraction solved. An entire answer must match, including Cedar diagnostics and the requested ordering. The provider receives one system message and the public case text, with temperature 0.7, reasoning effort `none` and a 1,536-token output allowance. Eight independent completions per task make this a coarse difficulty estimate. The historical Terminus-2 runs used a multi-turn coding agent and a different action space.

The data contains repeated policy components. A random task-level split can put the same constituents on both sides. The Cedar `source_group` field identifies all constituents, and OpenFGA `group_id` identifies the underlying model and relationship snapshot. Keep related cases together when designing a split. Public upstream conformance cases can also occur in model pretraining.

### Current experiment status

Qwen scoring stopped after 971 finalized responses when the user clarified the intended benchmark outcome. The saved scores cover 113 complete groups and 13 partial groups, all from Cedar. The 45 mixed groups measure variation in authorization-audit rewards. They supply no SEC-bench Pro transfer measurement. The native HF Sandbox CLI result covers one versioned control. [Benchmark relevance and the five source threads](../benchmarks/sec-bench-pro-training-readiness.md)

## Reproduce locally

From the project root, use the OpenEnv environment installed by the project bootstrap, a Python with the scoring dependencies, and Node.js for the official Cedar engine. The build downloads pinned Apache-2.0 fixtures, verifies their hashes and reuses the verified source cache on subsequent runs.

```sh
.local/openenv/.venv/bin/python -m cyber_defense.build --out runs/cyber-defense-1000
.local/openenv/.venv/bin/python -m cyber_defense.validate runs/cyber-defense-1000/tasks.jsonl
```

The historical invocation below made live paid requests on the authenticated Hugging Face account. It is recorded for provenance. The current unattended work uses saved responses.

```sh
.sources/tasksmith-final-venv/bin/python -m cyber_defense.score run \
  runs/cyber-defense-1000/tasks.jsonl runs/cyber-defense-1000/rollouts --slots 8 --workers 40
```

To audit completed results offline, replay the original HTTP responses, then replay the corresponding submissions through the OpenEnv environment.

```sh
.sources/tasksmith-final-venv/bin/python -m cyber_defense.score summarize runs/cyber-defense-1000/rollouts
.local/openenv/.venv/bin/python -m cyber_defense.results runs/cyber-defense-1000
```

The scorer retains model and provider identity, completion IDs, exact request and response digests, and terminal grades. Model formatting errors or output-limit failures receive zero. Infrastructure failures leave a measurement incomplete. The cloud validation job replays the oracle, a differently formatted oracle, a plausible wrong answer, an empty object, malformed text, and the single-action limit against the pinned Linux OpenEnv runtime.
