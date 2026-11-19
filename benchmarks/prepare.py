"""Screen a reviewed benchmark panel and write the inputs for a new Tasksmith campaign."""

import argparse
from decimal import Decimal
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit

# Direct script execution starts with benchmarks/ as the import root.
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from generation.campaign import formatted, new_output, read, sha  # noqa: E402
from openenv_pipeline.operators.eligibility.eligibility import pr_name, repo_name  # noqa: E402
from replay.baseline import DIGESTS, REVISION  # noqa: E402

GATE = ROOT / "openenv_pipeline/operators/eligibility"
BASELINE_VIEW = "views/final_v1/train.jsonl"


def strings(record, key):
    values = record[key]
    if not isinstance(values, list) or any(
        not isinstance(v, str) or not v.strip() for v in values
    ):
        raise ValueError(f"{key} must be an array of nonempty strings")
    return set(values)


def setup(profile_path, panel_path, output, baseline, extra_accepted=()):
    profile, panel = read(profile_path), read(panel_path)
    policy, existing = (
        read(GATE / "policy.json"),
        read(GATE / "existing-identities.json"),
    )
    targets = profile["benchmarks"]
    scopes = strings(profile, "capability_tags")
    budget = Decimal(profile["max_spend_usd"])
    if (
        not scopes
        or not isinstance(targets, list)
        or not targets
        or not isinstance(panel, list)
        or not re.fullmatch("[a-z][a-z0-9-]{0,30}", profile["name"])
        or not budget.is_finite()
        or budget <= 0
        or type(profile["target_verified"]) is not int
        or profile["target_verified"] < 1
    ):
        raise ValueError(
            "Invalid campaign name, targets, capabilities, count, or admission budget"
        )
    repos = set(policy["quarantined_repositories"])
    repos.update(repo_name(x) for x in strings(profile, "holdout_repos"))
    for target in targets:
        if not target["name"].strip() or not re.fullmatch(
            "[0-9a-f]{40}", target["revision"]
        ):
            raise ValueError(
                "Each benchmark needs a name and an immutable Git revision"
            )
        repos.add(repo_name(target["repository"]))
    held_ids = set(policy["benchmark_task_ids"]) | strings(profile, "holdout_task_ids")
    held_prs = {pr_name(p) for p in strings(profile, "holdout_prs")}
    known_prs = {pr_name(p) for p in existing["source_pr_urls"]}
    known_ids = set(existing["task_ids"] + existing["seen_source_ids"])
    known_heads = {(r["repo"], r["head"]) for r in existing["source_records"]}
    known_diffs = set(existing["patch_sha256s"])
    accepted_digests = []
    for i, file in enumerate([baseline, *extra_accepted]):
        data = file.read_bytes()
        digest = sha(data)
        if i == 0 and digest != DIGESTS[BASELINE_VIEW]:
            raise ValueError(
                f"Baseline differs from {REVISION}. Use --accepted for subsequent releases"
            )
        accepted_digests.append({"path": str(file.resolve()), "sha256": digest})
        for line in data.splitlines():
            row = json.loads(line)
            known_ids.add(row["task_id"])
            if row.get("source_pr_url"):
                canonical = pr_name(row["source_pr_url"])
                known_prs.add(canonical)
                head = row.get("source_head_commit") or row.get("source_commit")
                if head:
                    known_heads.add(
                        (
                            repo_name(
                                "/".join(urlsplit(canonical).path.split("/")[1:3])
                            ),
                            head,
                        )
                    )

    accepted, decisions = [], []
    seen_ids, seen_prs, seen_heads, seen_diffs = set(), set(), set(), set()
    for candidate in panel:
        canonical = pr_name(candidate["url"])
        repo = "/".join(urlsplit(canonical).path.strip("/").split("/")[:2])
        lineage = (
            {repo, *(repo_name(r) for r in strings(candidate, "repository_lineage"))}
            if "repository_lineage" in candidate
            else {repo}
        )
        pins, lic = candidate["expected"], candidate["license"]
        patterns = {
            "id": "[0-9a-f]{12}",
            "head": "[0-9a-f]{40}",
            "base": "[0-9a-f]{40}",
            "full_diff_sha256": "[0-9a-f]{64}",
        }
        if any(
            not re.fullmatch(pattern, pins[key]) for key, pattern in patterns.items()
        ):
            raise ValueError(f"Invalid source fingerprint for {canonical}")
        path = Path(lic["path"])
        if (
            not path.name
            or path.is_absolute()
            or ".." in path.parts
            or not re.fullmatch("[0-9a-f]{64}", lic["sha256"])
        ):
            raise ValueError(f"Invalid license fingerprint for {canonical}")
        tags = strings(candidate, "capability_tags")
        ids = {pins["id"], "tasksmith-" + pins["id"]}
        ids.update(
            candidate[field]
            for field in ("task_id", "source_task_id", "candidate_id")
            if isinstance(candidate.get(field), str)
        )
        ids.update(
            strings(candidate, "source_task_ids")
            if "source_task_ids" in candidate
            else set()
        )
        heads = {(r, pins["head"]) for r in lineage}
        reasons = []
        if not tags.intersection(scopes):
            reasons.append("no requested capability")
        if lic["spdx"] not in policy["pilot_license_allowlist"]:
            reasons.append("source license outside the recorded pilot allowlist")
        if lineage & repos:
            reasons.append("benchmark repository overlap")
        if (
            ids & held_ids
            or canonical in held_prs
            or candidate.get("evaluation_only")
            or candidate.get("benchmark_task_id")
        ):
            reasons.append("benchmark identity or evaluation-only source")
        if (
            canonical in known_prs
            or ids & known_ids
            or heads & known_heads
            or pins["full_diff_sha256"] in known_diffs
        ):
            reasons.append("previously seen source")
        if (
            canonical in seen_prs
            or ids & seen_ids
            or heads & seen_heads
            or pins["full_diff_sha256"] in seen_diffs
        ):
            reasons.append("duplicate within panel")
        seen_prs.add(canonical)
        seen_ids.update(ids)
        seen_heads.update(heads)
        seen_diffs.add(pins["full_diff_sha256"])
        decisions.append(
            {"url": candidate["url"], "selected": not reasons, "reasons": reasons}
        )
        if not reasons:
            accepted.append(candidate)

    ready = len(accepted) >= profile["target_verified"]
    with new_output(output) as out:
        report = {
            "benchmark_revisions": targets,
            "decisions": decisions,
            "eligible_candidates": len(accepted),
            "profile_sha256": sha(profile_path.read_bytes()),
            "panel_sha256": sha(panel_path.read_bytes()),
            "historical_policy_sha256": sha((GATE / "policy.json").read_bytes()),
            "historical_identities_sha256": sha(
                (GATE / "existing-identities.json").read_bytes()
            ),
            "baseline_revision": REVISION,
            "accepted_inputs": accepted_digests,
            "generation_spec_written": ready,
            "semantic_nonoverlap_established": False,
            "training_admissible": False,
        }
        (out / "intake-report.json").write_bytes(formatted(report))
        (out / "benchmark-profile.json").write_bytes(formatted(profile))
        if ready:
            (out / "generation-spec.json").write_bytes(
                formatted(
                    {
                        "name": profile["name"],
                        "benchmarks": [target["name"] for target in targets],
                        "candidates": accepted,
                        "excluded_prs": sorted(held_prs | known_prs),
                        "target_verified": profile["target_verified"],
                        "max_spend_usd": str(budget),
                    }
                )
            )
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", type=Path)
    parser.add_argument("panel", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument(
        "--baseline", type=Path, default=ROOT / "runs/baseline" / BASELINE_VIEW
    )
    parser.add_argument(
        "--accepted",
        action="append",
        type=Path,
        default=[],
        help="Additional accepted JSONL roster",
    )
    args = parser.parse_args()
    result = setup(args.profile, args.panel, args.output, args.baseline, args.accepted)
    print(
        f"Selected {result['eligible_candidates']}/{len(result['decisions'])} PRs. See {args.output}/intake-report.json"
    )
    return 0 if result["generation_spec_written"] else 2


if __name__ == "__main__":
    sys.exit(main())
