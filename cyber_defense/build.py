"""Build the version-one, 1,000-task defensive authorization cohort."""

import argparse
from collections import Counter
import hashlib
from itertools import islice
import json
from pathlib import Path

from . import access_review, authz
from .grading import canonical, payload_sha256
from .validate import replay


def seal_row(row):
    row = dict(row)
    if row["family"] == "cedar_authorization":
        row["source_repo"] = row["source_id"]
        row["source_id"] = row["native_case_id"]
        row["group_id"] = row["structural_key"]
    else:
        row["derivation"] = "native"
    source = [row["source_repo"], row["source_revision"], row["source_id"], row["family"]]
    row["task_id"] = row["family"] + "-" + hashlib.sha256(canonical(source)).hexdigest()[:20]
    row["task_sha256"] = payload_sha256(row)
    return row


def select_cedar(rows, needed):
    native = [r for r in rows if r["derivation"] == "native"]
    composed = [r for r in rows if r["derivation"] == "composed_source_policies"]
    if not len(native) <= needed <= len(native) + len(composed):
        raise ValueError("Unexpected number of Cedar cases")
    result = native.copy()
    uses = Counter(p for task in native for p in task["source_group"])
    while len(result) < needed:
        def priority(row):
            reuse = [uses[p] for p in row["source_group"]]
            return (max(reuse), sum(reuse), row["structural_key"])
        chosen = min(composed, key=priority)
        composed.remove(chosen)
        uses.update(chosen["source_group"])
        result.append(chosen)
    return result


def immutable(path, data):
    if path.exists():
        if path.read_bytes() != data:
            raise ValueError(f"Existing sealed file differs: {path}")
    else:
        temp = path.with_suffix(path.suffix + ".tmp")
        temp.write_bytes(data)
        temp.replace(path)


def json_lines(rows):
    return b"".join(canonical(row) + b"\n" for row in rows)


def check_holdout(rows):
    from benchmarks.sec_bench_pro_inventory import verify

    path = Path(__file__).resolve().parents[1] / "benchmarks" / "sec-bench-pro.json"
    profile = json.loads(path.read_bytes())
    counts = verify(profile)
    excluded_repos = {r.casefold() for r in profile["holdout_repos"]}
    excluded_ids = set(profile["holdout_task_ids"])
    observed = set()
    for row in rows:
        observed.add(row["source_repo"].casefold())
        native = {row["task_id"], row["source_id"], row["native_case_id"], *row.get("source_group", [])}
        if excluded_ids.intersection(native):
            raise ValueError("SEC-bench Pro source case appeared in the training candidate cohort")
    if observed.intersection(excluded_repos):
        raise ValueError("SEC-bench Pro source repository appeared in the cohort")
    return {"held_out_native_cases": sum(counts.values()), "profile_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "checked_sources": sorted(observed), "checked_tasks": len(rows),
            "matching_source_ids": 0, "matching_source_repositories": 0}


def build(cache, out):
    out.mkdir(parents=True, exist_ok=True)
    fga = list(access_review.build(cache))
    cedar = list(islice(authz.build(cache), 806))
    if len(fga) != 390 or len(cedar) != 806:
        raise ValueError(f"Unexpected source-pool size: OpenFGA {len(fga)}, Cedar {len(cedar)}")
    selected = select_cedar(cedar, 1000 - len(fga))
    rows = sorted(map(seal_row, fga + selected), key=lambda r: r["task_id"])
    claims = {(row["source_repo"], row["source_revision"], row["source_id"], row["family"])
              for row in rows}
    if len(claims) != len(rows) or len({r["structural_key"] for r in selected}) != len(selected):
        raise ValueError("Duplicate source claim or Cedar policy structure")
    cohort = out / "tasks.jsonl"
    immutable(out / "holdout-check.json", canonical(check_holdout(rows)) + b"\n")
    immutable(cohort, json_lines(rows))
    immutable(out / "prompts.jsonl", json_lines(
        {"task_id": r["task_id"], "prompt": r["prompt"]} for r in rows))
    evidence = replay(cohort, out / "validation.jsonl")
    constituent_counts = Counter(p for row in selected for p in row["source_group"])
    report = dict(evidence, family_counts=Counter(r["family"] for r in rows),
                  derivation_counts=Counter(r["derivation"] for r in rows),
                  openfga_model_tuple_groups=len({r["group_id"] for r in fga}),
                  cedar_distinct_structures=len(selected),
                  cedar_constituent_fixtures=len(constituent_counts),
                  max_cedar_fixture_uses=max(constituent_counts.values()),
                  sources={r["source_repo"]: r["source_revision"] for r in rows})
    immutable(out / "validation-summary.json", json.dumps(report, indent=2, sort_keys=True).encode() + b"\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("runs/cyber-defense-1000"))
    args = parser.parse_args()
    print(json.dumps(build(args.out / "source-cache", args.out), indent=2))
