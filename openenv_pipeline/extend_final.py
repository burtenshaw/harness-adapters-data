"""Append new Scale800 rows to the final corpus while retaining previous rows verbatim."""

import argparse
import hashlib
import json
import re
import sys
import tempfile
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from replay.baseline import DIGESTS
from tasksmith_final.rows import MOD_COLUMNS, ORIGIN

MAIN = "views/scale800_v1/train.jsonl"
SHORT = "views/scale800_best_v1/train.jsonl"
DEFAULT_BASE_SHA = DIGESTS["views/final_v1/train.jsonl"]
MEASUREMENT = {"in_stratified_sample"}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def write(path, document):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True, allow_nan=False) + "\n"
    )


def mixed(row):
    return (
        row["qwen_status"] == "scored"
        and row["qwen_valid_attempts"]
        and 0 < row["qwen_solved"] < row["qwen_valid_attempts"]
    )


def register(inputs, rows, schema, raw_lines):
    new_ids = set()
    duplicates = 0
    for candidate in inputs:
        task_id = candidate["task_id"]
        need(
            task_id not in new_ids, f"Duplicate task ID in the incoming view: {task_id}"
        )
        new_ids.add(task_id)
        need(
            candidate["source_dataset"] in ORIGIN
            and candidate["gate_passed"] is True
            and candidate["training_admissible"] is False,
            f"Unsupported Scale800 input: {task_id}",
        )
        for key in ("task_source_sha256", "task_inventory_sha256"):
            need(
                re.fullmatch(r"[0-9a-f]{64}", candidate[key]),
                f"Missing native digest: {task_id}",
            )
        need(
            not (set(candidate) - set(schema))
            and not ({"task_origin", *MOD_COLUMNS} & candidate.keys()),
            "Incoming view schema differs from the original Scale800 representation",
        )
        row = dict.fromkeys(schema)
        row.update(candidate, task_origin=ORIGIN[candidate["source_dataset"]])
        prior = rows.get(task_id)
        if prior:
            # Measurements and sample membership can differ across collections.
            # All source fields, including relative artifact paths, must agree.
            keys = [
                k for k in schema if not k.startswith("qwen_") and k not in MEASUREMENT
            ]
            need(
                all(prior[k] == row[k] for k in keys),
                f"Conflicting source identity for {task_id}",
            )
            duplicates += 1
            continue
        rows[task_id] = row
        raw_lines[task_id] = (json.dumps(row, allow_nan=False) + "\n").encode()
    return duplicates


def assemble(base, base_sha, derived, output, tag):
    need(re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,60}", tag), "Use a lowercase view tag")
    need(
        not output.exists() and not output.is_symlink(), "Use a fresh output directory"
    )
    base_raw = base.read_bytes()
    need(sha(base_raw) == base_sha, "Final baseline SHA256 mismatch")
    need(base_raw.endswith(b"\n"), "Expected a complete final JSONL file")
    rows, lines = {}, {}
    schema = None
    for line in base_raw.splitlines(keepends=True):
        row = json.loads(line)
        if schema is None:
            schema = list(row)
            need(
                len(schema) == 62 and {"task_origin", *MOD_COLUMNS} <= set(schema),
                "Expected final 62-column schema",
            )
        need(
            row["task_id"] not in rows and set(row) == set(schema),
            "Duplicate ID or schema drift in baseline",
        )
        rows[row["task_id"]] = row
        lines[row["task_id"]] = line

    before = len(rows)
    proof_raw = (derived / "capture-proof.json").read_bytes()
    proof = json.loads(proof_raw)
    files = {p: (derived / p).read_bytes() for p in (MAIN, SHORT)}
    if "files" in proof:
        hashes, repo = proof["files"], proof["source_repository"]
    else:
        plan = json.loads((derived / "plan.json").read_bytes())
        hashes, repo = plan["files"], plan["repo_id"]
        # The historical replay branch has one fixed pair of published file hashes.
        pins = json.loads(
            Path(__file__).with_name("historical-view-inputs.json").read_bytes()
        )
        need(
            hashes == pins["expected_view_sha256"]
            and plan["source_revision"] == proof["accepted_revision"],
            "Unknown historical view authority",
        )
    need(
        hashes == {p: sha(raw) for p, raw in files.items()},
        "Scale800 views differ from the derivation receipt",
    )
    need(
        re.fullmatch(r"[\w.-]+/[\w.-]+", repo)
        and re.fullmatch(r"[0-9a-f]{40}", proof["accepted_revision"]),
        "Expected immutable source revision and repository",
    )
    inputs = [json.loads(line) for line in files[MAIN].splitlines()]
    need(
        [r for r in inputs if mixed(r)]
        == [json.loads(line) for line in files[SHORT].splitlines()],
        "Scale800 shortlist differs from full rows",
    )
    same = register(inputs, rows, schema, lines)
    added = len(rows) - before
    summary = {
        "base_rows": before,
        "new_scale800_rows": added,
        "existing_scale800_rows": same,
        "tasks": len(rows),
        "mixed": sum(bool(mixed(row)) for row in rows.values()),
        "origins": dict(Counter(row["task_origin"] for row in rows.values())),
        "base_sha256": base_sha,
        "scale800_source_repo": repo,
        "scale800_revision": proof["accepted_revision"],
        "scale800_views": hashes,
        "scale800_capture_proof_sha256": sha(proof_raw),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=output.parent) as temp:
        run = Path(temp) / "run"
        pub = run / "export"
        packet = pub / "scale800-derived" / tag
        packet.mkdir(parents=True)
        (packet / "capture-proof.json").write_bytes(proof_raw)
        write(packet / "assembly.json", summary)
        for name, chosen in [
            (f"final_{tag}", rows.values()),
            (f"final_best_{tag}", filter(mixed, rows.values())),
        ]:
            path = pub / f"views/{name}/train.jsonl"
            path.parent.mkdir(parents=True)
            with path.open("wb") as stream:
                for row in chosen:
                    stream.write(lines[row["task_id"]])
        write(
            run / "campaign.json",
            {
                "tag": tag,
                "selected": {},
                "source_repo": repo,
                "base": str(base.resolve()),
                "base_sha256": base_sha,
            },
        )
        write(
            run / "stage-manifest.json",
            {
                "out": str(output.resolve() / "export"),
                "files": {
                    path.relative_to(pub).as_posix(): sha(path.read_bytes())
                    for path in sorted(pub.rglob("*"))
                    if path.is_file()
                },
            },
        )
        run.rename(output)
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument(
        "--base-sha256",
        default=DEFAULT_BASE_SHA,
        help="Defaults to the published 871-row final corpus",
    )
    parser.add_argument(
        "--derived",
        type=Path,
        required=True,
        help="Output directory of views or replay-views",
    )
    parser.add_argument(
        "--tag", required=True, help="New final_TAG and final_best_TAG config suffix"
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(
        json.dumps(
            assemble(args.base, args.base_sha256, args.derived, args.output, args.tag),
            indent=2,
        )
    )
