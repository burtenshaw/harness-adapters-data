# HF Jobs semantic trial runner

`run.py` freezes and executes one task under the separate `harbor-semantic-jobs-v1` operator profile. It makes **zero model calls**. Admission comes only from `gate.assess`, which calls the merged pure semantic graders after exact reward and replay checks. It does not run native `openenv validate`, compare with native reports, establish full RFC qualification, or mark training admission.

Each role uses a fresh solver Job and a different fresh private-verifier Job through the merged `HFTaskBackend`. A task with three declared canaries therefore has six roles and twelve Jobs. Roles can run concurrently; the solver and verifier for one role run sequentially. Runtime image, namespace, returned Job IDs and terminal cleanup are checked by the backend. The supplied image receipt must resolve to a linux/amd64 OCI digest. Image metadata does not claim physical-host architecture or served-model attestation.

The root operator must supply an approved, empty shared runtime and a task containing `environment/source/`. The complete public source tree is seeded into both fresh environments. The transfer allowlist must cover every initial public source file. New paths and executable-mode changes remain unsupported; approved initial644/755 modes are preserved by the source-seeded backend. Private tests, solutions and canaries stay in the private task snapshot and reach only private Jobs/RPC calls. Script bodies never enter CLI arguments or Job creation metadata.

## Prepare without spending

Use the existing project environment with `huggingface_hub==1.33.0` and Harbor0.25.0. Run from this checkout; worker processes receive the same project import paths. The underlying backend requires a Unix main thread, so every role executes in its own Python process.

```sh
RUNNER=outputs/full-hub-run-20261110/scale800-pilot-v1/production/hf-check-gate-v1/run.py
PYTHONPATH=.:src:envs .venv/bin/python -B "$RUNNER" prepare \
  --task "$MATERIALIZED_TASK" \
  --task-sha256 "$ACQUIRED_TASK_CONTENT_DIGEST" \
  --execution "$REVIEWED_EXECUTION_JSON" \
  --image-receipt "$VERIFIED_AMD64_REGISTRY_RECEIPT" \
  --output "$FRESH_PREPARATION_DIRECTORY" \
  --budget-usd 6 \
  --deadline-utc 2026-11-13T11:39:00Z
```

The amount6USD is an example of an explicit operator-approved pilot reservation, not a cost estimate for every task. Preparation rejects mutable/mismatched images, malformed source contracts, missing references/canaries, unsupported execution fields, and transfer surfaces that omit initial public files. This profile currently uses `cpu-basic`, an explicit execution namespace, and the captured `['/bin/bash','/tests/test.sh']` verifier. Credentials belong only in the runtime environment.

The resulting private directory contains `task/`, the exact original `image-receipt.json` bytes, and `plan.json`. Preparation captures task bytes/modes before parsing, checks the supplied acquired source digest, freezes every script hash, and binds the runner/backend/gate/validation source files. The printed `plan_sha256` is the hash of the exact bytes to review and later consume. Edits to any frozen task, mode, receipt, code or role mapping invalidate execution. Reprepare into a fresh directory after an intentional change; do not edit a reviewed plan in place.

## Execute one reviewed plan

The parent privately loads only `HF_SANDBOX_TOKEN` into the controller environment. Do not put tokens in execution JSON or shell arguments. Worker processes do not receive the persistence or inference keys.

```sh
PYTHONPATH=.:src:envs .venv/bin/python -B "$RUNNER" execute \
  --plan "$FRESH_PREPARATION_DIRECTORY/plan.json" \
  --expected-plan-sha256 "$REVIEWED_PLAN_SHA256" \
  --spend-ledger "$SHARED_SPEND_LEDGER" \
  --reservation-id "$FRESH_RESERVATION_ID" \
  --concurrency 6 \
  --execute
```

Before spawning any role, the parent reserves the explicit amount with `plan_costs={consumed_plan_sha256: exact_amount}` using the reviewed shared ledger. Each worker independently verifies the still-active matching reservation before constructing a backend. The shared spending ceiling remains authoritative; this runner never changes it, releases historical holds, settles estimated charges as actual, or automatically retries an ambiguous effect.

`execution-run/claim.json` makes the invocation one-shot. Each role also claims its own numbered directory once. Existing claims are never silently deleted or reused after restart. Lifecycle journals retain unique creation labels **before** SDK creation, returned IDs, source-seeding identity and cleanup outcomes, allowing the owner to reconcile a cancelled or unknown attempt without redispatching it.

Every role saves private `trial.json`, exact `reward.raw`, sanitized `records.json`, and bounded original submission bytes. The collector reads actual agent exit status and verifier trace status; it does not assume either is zero, replace a nonzero reference exit with a generic grading success, or round raw rewards through a float. Both actual image references, both Job IDs, both cleanup outcomes, task content digest and the backend's actual captured task-mode inventory digest enter the gate evidence.

On uncertain cleanup or a supervised timeout, queued roles stop. Already-running workers drain; a timeout sends SIGINT, allows120seconds for cleanup, then SIGKILL if necessary. Cleanup signals still execute if writing the marker fails. The parent claim prevents automatic restart even when a disk failure prevented the marker from becoming durable. The owner must inspect exact lifecycle labels/IDs and reconcile resources before creating a new attempt.

The final `execution-run/report.json` is the semantic admission result. `controller-receipt.json` records the consumed plan and process outcomes, and `SHA256SUMS` binds the evidence files. `admitted:true` requires every prerequisite and merged semantic check PASS. Incomplete/malformed evidence remains unadmitted. No native-report fallback exists. Qwen difficulty measurement remains with the existing separately owned evaluator.

## Offline verification

```sh
PYTHONPATH=.:src:envs .venv/bin/python -B -m pytest \
  outputs/full-hub-run-20261110/scale800-pilot-v1/production/hf-check-gate-v1/test_run.py \
  -q -p no:cacheprovider
```

These tests exercise the actual preparation, ledger, worker, collector and merged semantic-gate call paths with a fake remote backend. They cover source changed-and-restored capture, task/mode/receipt/plan drift, a substituted canary, omitted plan hash, insufficient or mismatched funding, preserved nonzero oracle exit, actual inventory mismatch, credential-field rejection, one-shot execution, cleanup uncertainty and marker-write failure. They launch no Jobs and use no real credentials.
