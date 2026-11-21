"""Verify the SEC-bench Pro holdout IDs offline or against the pinned GitHub tree."""

import argparse
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import re
from urllib.request import urlopen


PROFILE = Path(__file__).with_name("sec-bench-pro.json")
QUALIFIED_ID = re.compile(r"(?:(?:sm|v8)__[0-9]+|linux__CVE-[0-9]{4}-[0-9]{4,})")


def github_inventory(target):
    root = "https://api.github.com/repos/SEC-bench/SEC-bench-Pro/git/"
    revision = target["revision"]
    if target["repository"] != "SEC-bench/SEC-bench-Pro" or not re.fullmatch(
        r"[0-9a-f]{40}", revision
    ):
        raise ValueError("Expected an immutable SEC-bench Pro revision")
    with urlopen(root + "commits/" + revision, timeout=30) as response:
        commit = json.load(response)
    tree_sha = target["inventory"]["tree_sha"]
    if commit["sha"] != revision or commit["tree"]["sha"] != tree_sha:
        raise ValueError("Root tree differs from the pinned commit")
    with urlopen(root + f"trees/{tree_sha}?recursive=1", timeout=30) as response:
        tree = json.load(response)
    if tree["sha"] != tree_sha or tree["truncated"] is not False:
        raise ValueError("Incomplete or unexpected GitHub tree")

    ids = []
    for entry in tree["tree"]:
        path = entry["path"].split("/")
        if path[0] == "projects" and path[-1] == "meta.json":
            if len(path) != 4 or (entry["type"], entry["mode"]) != ("blob", "100644"):
                raise ValueError(f"Unexpected case metadata path: {entry['path']}")
            ids.append(f"{path[1]}__{path[2]}")
    return sorted(ids)


def verify(profile, github=False):
    (target,) = profile["benchmarks"]
    inventory = target["inventory"]
    held = profile["holdout_task_ids"]
    ids = sorted(value for value in held if QUALIFIED_ID.fullmatch(value))
    aliases = {value.split("__")[1] for value in ids}
    if held != sorted(set(ids) | aliases):
        raise ValueError(
            "Holdouts must include every qualified ID and its native alias"
        )
    counts = Counter(value.split("__")[0] for value in ids)
    if counts != inventory["case_counts"] or len(ids) != inventory["cases"]:
        raise ValueError("Counts differ from the recorded inventory")
    digest = sha256(("\n".join(ids) + "\n").encode("ascii")).hexdigest()
    if digest != inventory["qualified_ids_sha256"]:
        raise ValueError("Qualified IDs differ from the recorded inventory digest")
    if github and ids != github_inventory(target):
        raise ValueError("Qualified IDs differ from the pinned GitHub case paths")
    return counts


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--github",
        action="store_true",
        help="Also compare against upstream tree metadata",
    )
    args = parser.parse_args()
    counts = verify(json.loads(PROFILE.read_text(encoding="utf-8")), github=args.github)
    detail = ", ".join(
        f"{project}={count}" for project, count in sorted(counts.items())
    )
    source = " and upstream tree" if args.github else ""
    print(
        f"Verified {sum(counts.values())} cases ({detail}) against profile digest{source}"
    )
