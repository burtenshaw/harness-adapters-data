"""Frozen metadata intake screening; eligibility is not training approval."""

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from urllib.parse import unquote, urlsplit

HERE = Path(__file__).resolve().parent
SHA1 = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
PART = re.compile(r"[A-Za-z0-9_.-]+\Z")


def repo_name(value):
    """Normalize explicit GitHub identities without guessing fork ancestry."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("missing repository")
    value = value.strip()
    if value.startswith("git@github.com:"):
        value = value.removeprefix("git@github.com:")
    elif "://" in value:
        parsed = urlsplit(value)
        if (
            parsed.scheme not in {"https", "http", "ssh"}
            or parsed.hostname not in {"github.com", "www.github.com"}
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.username not in {None, "git"}
        ):
            raise ValueError("unsupported repository locator")
        value = unquote(parsed.path).strip("/")
    parts = value.rstrip("/").split("/")
    if len(parts) != 2:
        raise ValueError("repository must contain owner/name")
    parts[-1] = parts[-1].casefold().removesuffix(".git")
    if any(not PART.fullmatch(part) or part in {".", ".."} for part in parts):
        raise ValueError("invalid repository")
    return "/".join(parts).casefold()


def pr_name(value):
    if not isinstance(value, str):
        raise ValueError("invalid PR locator")
    parsed = urlsplit(value)
    parts = parsed.path.strip("/").split("/")
    if (
        parsed.scheme != "https"
        or parsed.hostname not in {"github.com", "www.github.com"}
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or len(parts) != 4
        or parts[2] != "pull"
        or not parts[3].isdigit()
        or int(parts[3]) < 1
    ):
        raise ValueError("invalid PR locator")
    return f"https://github.com/{repo_name('/'.join(parts[:2]))}/pull/{int(parts[3])}"


def assess(candidate, policy, existing):
    """Return eligible_for_controls, quarantine, or unknown with explicit reasons.

    Reviewed evidence fields are operator inputs, not assertions inferred from
    a public card. This function checks their shape/binding; it does not fetch
    licenses or prove semantic independence, verifier validity or permission.
    """
    blocked, missing, warnings = [], [], []
    if not isinstance(candidate, dict):
        return {
            "status": "unknown",
            "reasons": ["candidate must be an object"],
            "warnings": [],
            "semantic_nonoverlap_established": False,
            "training_admissible": False,
        }
    for flag in ("is_fork", "evaluation_only", "anti_training_canary"):
        if flag in candidate and type(candidate[flag]) is not bool:
            missing.append("invalid " + flag)
    repos = set()
    for field in ("source_repo", "upstream_repo"):
        value = candidate.get(field)
        if field == "source_repo" or value is not None:
            try:
                repos.add(repo_name(value))
            except (TypeError, ValueError):
                missing.append(f"invalid or missing {field}")
    lineage = candidate.get("repository_lineage", [])
    if not isinstance(lineage, list):
        missing.append("repository_lineage must be a list")
    else:
        for value in lineage:
            try:
                repos.add(repo_name(value))
            except (TypeError, ValueError):
                missing.append("invalid repository_lineage member")
    if candidate.get("upstream_identity_reviewed") is not True:
        missing.append("upstream/fork identity not reviewed")
    if candidate.get("is_fork") is True and not candidate.get("upstream_repo"):
        missing.append("fork has no explicit upstream identity")
    overlap = sorted(repos.intersection(policy["quarantined_repositories"]))
    if overlap:
        blocked.append("benchmark repository overlap: " + ", ".join(overlap))
    identifiers = {
        candidate[key]
        for key in ("candidate_id", "task_id", "source_task_id")
        if isinstance(candidate.get(key), str)
    }
    if identifiers.intersection(existing["task_ids"] + existing["seen_source_ids"]):
        blocked.append("previously seen task/source identity")
    if identifiers.intersection(policy["benchmark_task_ids"]):
        blocked.append("benchmark task identity overlap")
    if (
        not isinstance(candidate.get("candidate_id"), str)
        or not candidate["candidate_id"].strip()
    ):
        missing.append("candidate_id missing")
    if candidate.get("benchmark_task_id") or candidate.get("evaluation_only") is True:
        blocked.append("benchmark/evaluation-only source")
    if candidate.get("anti_training_canary") is True:
        blocked.append("anti-training canary")
    if candidate.get("anti_training_reviewed") is not True:
        missing.append("anti-training/canary review incomplete")
    if candidate.get("source_split") != "train":
        if candidate.get("source_split"):
            blocked.append("source partition is not train")
        else:
            missing.append("source training partition missing")
    dataset = candidate.get("source_dataset", "")
    if not isinstance(dataset, str) or not re.fullmatch(r"[\w.-]+/[\w.-]+", dataset):
        missing.append("invalid or missing source_dataset")
    elif dataset.casefold() in policy["evaluation_dataset_ids"]:
        blocked.append("evaluation dataset identity")
    commit = candidate.get("source_commit", "")
    if not isinstance(commit, str) or not SHA1.fullmatch(commit) or commit == "0" * 40:
        missing.append("full immutable source_commit missing")
    if "source_head_commit" in candidate and (
        not isinstance(candidate["source_head_commit"], str)
        or not SHA1.fullmatch(candidate["source_head_commit"])
    ):
        missing.append("invalid source_head_commit")
    for field in ("patch_sha256", "task_sha256"):
        value = candidate.get(field, "")
        if not isinstance(value, str) or not SHA256.fullmatch(value):
            missing.append(f"{field} missing or invalid")
        elif value in existing[field + "s"]:
            blocked.append("previously seen " + field)
    instruction = candidate.get("instruction_sha256")
    if instruction is not None:
        if not isinstance(instruction, str) or not SHA256.fullmatch(instruction):
            missing.append("invalid instruction_sha256")
        elif instruction in policy["benchmark_instruction_sha256"]:
            blocked.append("benchmark instruction digest overlap")
    pr = candidate.get("source_pr_url")
    if pr:
        try:
            normalized = pr_name(pr)
            if normalized in existing["source_pr_urls"]:
                blocked.append("previously seen source PR")
            if (
                repo_name("/".join(urlsplit(normalized).path.strip("/").split("/")[:2]))
                not in repos
            ):
                missing.append("PR repository differs from declared lineage")
        except (TypeError, ValueError):
            missing.append("source_pr_url is invalid")
    elif candidate.get("source_kind") == "pr":
        missing.append("PR source has no source_pr_url")
    for row in existing["source_records"]:
        if row["repo"] in repos and candidate.get("source_head_commit") == row["head"]:
            blocked.append("previously seen repository/head commit")
        if row["repo"] in repos and commit == row["base"]:
            warnings.append(
                "shared existing repository/base; distinct patch is not semantic independence"
            )
    revision = candidate.get("source_revision", "")
    if not isinstance(revision, str) or not (
        SHA1.fullmatch(revision) or re.fullmatch(r"sha256:[0-9a-f]{64}", revision)
    ):
        missing.append("immutable dataset/package source_revision missing")
    licenses = candidate.get("license_evidence", {})
    for scope, pin in (("source_code", commit), ("task_bundle", revision)):
        record = licenses.get(scope, {}) if isinstance(licenses, dict) else {}
        if not isinstance(record, dict):
            record = {}
        if record.get("training_allowed") is False:
            blocked.append(scope + " permission denied")
        if (
            record.get("reviewed") is not True
            or record.get("training_allowed") is not True
            or record.get("spdx") not in policy["pilot_license_allowlist"]
            or not isinstance(record.get("sha256"), str)
            or not SHA256.fullmatch(record["sha256"])
            or not isinstance(record.get("url"), str)
            or not isinstance(pin, str)
            or not pin
            or pin not in record.get("url", "")
        ):
            missing.append(scope + " reviewed pinned license evidence missing")
    return {
        "status": "quarantine"
        if blocked
        else "unknown"
        if missing
        else "eligible_for_controls",
        "reasons": sorted(set(blocked + missing)),
        "warnings": sorted(set(warnings)),
        "semantic_nonoverlap_established": False,
        "training_admissible": False,
    }


def assess_many(candidates, policy, existing):
    """Also retain and quarantine aliases repeated within this intake batch."""
    seen = set()
    for index, candidate in enumerate(candidates):
        result = assess(candidate, policy, existing)
        keys = set()
        if isinstance(candidate, dict):
            identity = candidate.get("candidate_id")
            if isinstance(identity, str) and identity:
                keys.add(("candidate_id", identity))
            for field in ("patch_sha256", "task_sha256"):
                value = candidate.get(field)
                if isinstance(value, str) and SHA256.fullmatch(value):
                    keys.add((field, value))
            try:
                keys.add(("source_pr_url", pr_name(candidate.get("source_pr_url"))))
            except (TypeError, ValueError):
                pass
        duplicates = sorted(key for key, value in keys if (key, value) in seen)
        if duplicates:
            result["status"] = "quarantine"
            result["reasons"] = sorted(
                set(
                    result["reasons"]
                    + ["earlier intake row repeats " + key for key in duplicates]
                )
            )
        seen.update(keys)
        yield {
            "row": index,
            "candidate_id": candidate.get("candidate_id")
            if isinstance(candidate, dict)
            else None,
            **result,
        }


def build(evidence_root, hub_path):
    """Extract only identifiers/hashes from the local frozen evidence."""
    consumed = {}

    def captured(path, expected=None):
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if expected is not None and digest != expected:
            raise ValueError(f"Frozen evidence digest mismatch: {path.name}")
        consumed[str(path.absolute())] = digest
        return data

    def read(path, expected=None):
        return json.loads(captured(path, expected))

    coverage = evidence_root / "coverage-overview-20261112"
    summary = read(coverage / "benchmark-evidence.json")
    intake = read(
        evidence_root
        / "expansion-v4/intake-export/tasksmith_gap_v4/20261111/intake/file-sha256.json",
        "67e17820dc2d56b75f84280b71442a4fe2656d2189c717a5e5627ef3d041737d",
    )
    research = []
    for name in ("tasksmith-next.json", "repo-next.json", "terminal-next.json"):
        research.append(
            read(
                evidence_root / "expansion-v4/research" / name,
                intake["tasksmith_gap_v4/20261111/intake/research/" + name],
            )
        )
    refs, repo_next, terminal = research
    hub = read(hub_path)
    benchmark_ids = {row["benchmark_task_id"] for row in terminal["task_assessments"]}
    for record in repo_next["benchmark_metadata_census"].values():
        benchmark_ids.update(record["task_ids"])
    exclusions = refs["benchmark_repository_exclusion"]
    benchmark_repos = set(exclusions["deepswe"]["repos"]) | set(
        exclusions["swepro_v2"]["repos"]
    )
    official = {
        "harbor-framework/terminal-bench-2-1",
        "scaleapi/swe-bench_pro-os",
        "datacurve-ai/deep-swe",
    }
    selected = []
    cache = (
        hub_path.parent
        / "cache/hub"
        / ("datasets--" + hub["repo"].replace("/", "--"))
        / "snapshots"
        / hub["revision"]
    )
    for split in hub["splits"]:
        if not (
            split["config"].startswith(("synthetic_gap_", "tasksmith_gap_"))
            or split["split"].startswith("synthetic_gap_")
        ):
            continue
        rows = []
        for name, digest in split["index_sha256"].items():
            rows.extend(
                json.loads(line)
                for line in captured(cache / name, digest).decode().splitlines()
            )
        if len(rows) != split["rows"]:
            raise ValueError("Frozen source index row count differs")
        selected.extend(rows)
    source_records = {}
    for relative in (
        "frozen-sources.json",
        "expansion-v2/candidates/frozen-sources.json",
        "expansion-v4/candidates/frozen-sources.json",
    ):
        for record in read(evidence_root / relative):
            url = pr_name(record["url"])
            source_records[url] = {
                "repo": repo_name(record["repo"]),
                "url": url,
                "source_id": record["id"],
                "base": record["base"],
                "head": record["head"],
                "patch_sha256s": sorted(
                    {
                        hashlib.sha256(record[key].encode()).hexdigest()
                        for key in ("source_diff", "full_diff")
                        if record.get(key)
                    }
                ),
            }
    source_prs = [row["source_pr_url"] for row in selected if row.get("source_pr_url")]
    existing = {
        "schema": "scale800-existing-identities-v1",
        "dataset_revision": hub["revision"],
        "task_ids": sorted({row["task_id"] for row in selected}),
        "source_ids": sorted(
            {row["source_id"] for row in selected if row.get("source_id")}
        ),
        "seen_source_ids": sorted(row["source_id"] for row in source_records.values()),
        "source_pr_urls": sorted(source_records),
        "patch_sha256s": sorted(
            {v for row in source_records.values() for v in row["patch_sha256s"]}
        ),
        "task_sha256s": sorted(
            {
                row[key]
                for row in selected
                for key in ("task_sha256", "task_source_sha256")
                if row.get(key)
            }
        ),
        "source_records": sorted(source_records.values(), key=lambda row: row["url"]),
        "stored_source_rows": len(selected),
        "constructed_source_pr_urls": sorted({pr_name(url) for url in source_prs}),
        "repeated_source_pr_rows": {
            url: count
            for url, count in sorted(Counter(map(pr_name, source_prs)).items())
            if count > 1
        },
        "patch_digest_scope": "Exact recorded UTF-8 source_diff/full_diff bytes only; no normalized or semantic patch matching.",
    }
    policy = {
        "schema": "scale800-intake-policy-v1",
        "policy_stage": "metadata_screening_before_controls",
        "snapshot_date": "2026-11-12",
        "source_files_sha256": consumed,
        "benchmark_targets": summary["benchmark_targets"],
        "quarantined_repositories": sorted(benchmark_repos | official),
        "benchmark_source_repositories_count": len(benchmark_repos),
        "official_benchmark_repositories": sorted(official),
        "benchmark_task_ids": sorted(benchmark_ids),
        "benchmark_instruction_sha256": sorted(
            row["instruction_sha256"] for row in terminal["task_assessments"]
        ),
        "evaluation_dataset_ids": [
            "scaleai/swe-bench_pro",
            "swe-bench/swe-bench",
            "swe-bench/swe-bench_verified",
            "swe-bench/swe-bench_lite",
            "swe-bench/swe-bench_multilingual",
        ],
        "pilot_license_allowlist": [
            "MIT",
            "BSD-2-Clause",
            "BSD-3-Clause",
            "Apache-2.0",
            "ISC",
            "0BSD",
        ],
        "confirmed_cattrs_repository_overlap": summary[
            "confirmed_source_repository_overlap"
        ],
        "limits": [
            "Frozen local metadata only; no live or complete semantic holdout audit.",
            "Repository quarantine is deliberately conservative; it does not establish contamination.",
            "Absence from these identifier/repository sets is not semantic novelty or training permission.",
            "Fork ancestry must be explicitly reviewed; repository basenames are never guessed.",
            "Benchmark aliases, unseen forks and anti-training text require separate content review.",
            "Shared source base commits do not collapse different mutations into one task.",
            "The existing 50 constructed IDs include two unverified packaging pilots; main pool remains48.",
            "All statuses leave training_admissible and semantic_nonoverlap_established false.",
        ],
        "counts": {
            "benchmark_task_ids": len(benchmark_ids),
            "benchmark_source_repos": len(benchmark_repos),
            "all_quarantined_repos": len(benchmark_repos | official),
            "existing_constructed_task_ids": len(existing["task_ids"]),
            "existing_constructed_unique_prs": len(set(source_prs)),
            "prior_source_records_including_blocked": len(source_records),
            "stored_source_rows": len(selected),
            "source_pr_recovery_duplicate_rows": len(source_prs) - len(set(source_prs)),
        },
    }
    for name, data in (("policy.json", policy), ("existing-identities.json", existing)):
        (HERE / name).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    return policy["counts"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    make = commands.add_parser("build")
    make.add_argument("--evidence-root", required=True, type=Path)
    make.add_argument("--hub-inventory", required=True, type=Path)
    check = commands.add_parser("check")
    check.add_argument("candidates", type=Path)
    args = parser.parse_args()
    if args.command == "build":
        print(json.dumps(build(args.evidence_root, args.hub_inventory), sort_keys=True))
    else:
        policy = json.loads((HERE / "policy.json").read_text())
        existing = json.loads((HERE / "existing-identities.json").read_text())
        with args.candidates.open() as stream:
            for result in assess_many(
                (json.loads(line) for line in stream), policy, existing
            ):
                print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
