# Freeze a private Scale800 sampling population

Run from the project root after registering the accepted splits on the new private dataset. Use the project’s pinned OpenEnv Python environment. Set `SOURCE_REPO` to the exact private dataset ID, `SOURCE_REVISION` to the full 40-hex commit returned by registration, and `RUN` to a private campaign directory. Each output path must be fresh.

```sh
.local/openenv/.venv/bin/python qwen_pipeline/population.py "$RUN/population.json" \
  --source-repo "$SOURCE_REPO" --revision "$SOURCE_REVISION"
python3 qwen_pipeline/draw.py "$RUN/population.json" "$RUN/draw"
```

The first command reads the registered `accepted` split paths from the immutable dataset card for `scale800_gate_v1` (Go) and `scale800_py_gate_v1` (Python). A fresh dataset may register either or both. For each row, it reads the full path, size, SHA-256 and octal mode inventory and the starter image receipt at that same commit. The evidence records each split’s hash, exact line number and raw line hash. GitHub repository metadata supplies the public canonical name and numeric repository ID. The existing authenticated `gh` CLI is used when available. Anonymous GitHub reads are subject to the host’s rate limit. A missing repository, mismatched name, malformed inventory or unavailable private artifact stops assembly.

A unit’s identity includes its upstream dataset, canonical repository, native task and full inventory digests, and immutable starter image identity with explicit omitted fields. Matching registrations share one unit and retain their row memberships. The original accepted source row travels with the evidence. Selection uses only the repository and the unit identity digest.

The second command chooses a fresh public 32-byte seed and records it in `draw/seed.json`. For each repository, it selects the first six units (or all available) ordered by `SHA256(b"openenv-qwen-srs6-v1\0" + seed_bytes + unit_identity_digest_bytes)`, with the identity digest breaking ties. The command prints the SHA-256 of `draw/draw-manifest.json`. Keep the receipt and supply `--draw "$RUN/draw"` when preparing routed Qwen tasks. Draw the entire new population before collecting outcomes. The later 22-task outside-sample authority in the archived campaign applied to that campaign’s original base draw.

## Register a sample for corrected dataset views

Set `DRAW_SHA` to the printed draw digest. Set `PARENT_REVISION` to the current, reviewed private source dataset head. The source revision recorded in the draw stays fixed. This explicit publication adds the six frozen draw files beneath a new content-addressed prefix in the same private dataset.

```sh
.local/openenv/.venv/bin/python qwen_pipeline/draw.py publish \
  "$RUN/draw" "$RUN/sample-capture" --source-repo "$SOURCE_REPO" \
  --draw-sha256 "$DRAW_SHA" --parent "$PARENT_REVISION"
```

The publisher verifies privacy, source revision, current parent and prefix availability, then makes one expected-parent commit. It reads back every byte at the returned commit before emitting `sample-capture/sample-manifest.json`. An attempt marker in the draw directory prevents automatic resubmission. If an upload loses its response, identify the actual immutable commit containing the expected prefix in the dataset history. A later read-only capture may use that commit.

```sh
.local/openenv/.venv/bin/python qwen_pipeline/draw.py capture \
  "$RUN/draw" "$RUN/sample-recovery" --source-repo "$SOURCE_REPO" \
  --draw-sha256 "$DRAW_SHA" --revision "$PUBLISHED_REVISION"
```

Pass the captured manifest to the corrected views builder. Its original verifier checks the seed receipt, rank, row, inventory file count, full digest and published locators for each sampled task.

```sh
python3 openenv_pipeline/run.py views --source-repo "$SOURCE_REPO" \
  --results-repo "$RESULTS_REPO" --accepted-capture "$RUN/accepted.json" \
  --results-manifest "$RUN/results-manifest.json" \
  --sample-manifest "$RUN/sample-capture/sample-manifest.json" --output "$RUN/views"
```

## Reproduce the original draw offline

Point `ARCHIVE` at the original private `incoming/srs6-repo-3afa3ffb-v1` evidence directory. The replay binds the archived repository proofs, registered split rows, card, and inventory/image files through their historical hashes. It does not require a Hub or GitHub connection.

```sh
.local/openenv/.venv/bin/python qwen_pipeline/population.py "$RUN/population.json" \
  --source-repo harness-hub/agentic-coding-envs \
  --revision 3afa3ffb350eae408cdc4962952452726a680559 --historical-archive "$ARCHIVE"
python3 qwen_pipeline/draw.py "$RUN/population.json" "$RUN/draw" \
  --seed 3340a71c3d236dd72732f5d05ff6144ead6ff6064d77004f29384dea010a1112
```

At that revision, the reconstructed 825 units across 27 repositories match the original 158 sampled and 667 outside-sample unit records, including ranks, source rows, modes and image evidence. A replay records new timestamps and has its own draw manifest digest.
