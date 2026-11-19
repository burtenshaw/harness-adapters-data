"""Bind independently reviewed captures to the original scale800 converters."""

import argparse
import json
import re
from pathlib import Path

from run import PINS, checked, load, sha


def add_arguments(parser):
    parser.add_argument("family", choices=["swesmith-go", "swesmith-py", "swegym"])
    parser.add_argument(
        "--source",
        required=True,
        type=Path,
        help="Directory containing captured source artifacts",
    )
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument(
        "--expected-sha256", required=True, help="Reviewed hash of the manifest"
    )
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--task",
        action="append",
        default=[],
        help="Select an exact source task ID; repeatable",
    )
    parser.add_argument("--index-sha256", help="Reviewed Go candidates.jsonl hash")
    parser.add_argument(
        "--runtime-lock",
        type=Path,
        help="Go runtime-lock mapping and adjacent signed-off image receipts",
    )
    parser.add_argument(
        "--go-profile",
        choices=["single-package", "all-packages"],
        default="single-package",
    )


def below(root, name):
    part = Path(name)
    if (
        part.is_absolute()
        or ".." in part.parts
        or not part.parts
        or (root / part).resolve() != root / part
    ):
        raise ValueError(f"Unsafe captured source path: {name}")
    return root / part


def read_rows(raw, requested):
    rows = [json.loads(line) for line in raw.splitlines()]
    ids = [r["task_id"] for r in rows]
    if not ids or len(ids) != len(set(ids)):
        raise ValueError("Source index needs distinct, nonempty task identities")
    if len(requested) != len(set(requested)) or set(requested) - set(ids):
        raise ValueError("Repeated or missing --task ID")
    return [r for r in rows if not requested or r["task_id"] in requested]


def go(args, raw):
    if args.manifest != args.source / "SHA256SUMS" or not args.index_sha256:
        raise ValueError("Go inputs require SOURCE/SHA256SUMS and --index-sha256")
    name = (
        "go-batch-v1"
        if args.go_profile == "single-package"
        else "go-jobs-wave-all-packages-v3"
    )
    factory = load(args.operators / name / "factory.py")
    factory.MANIFEST_SHA = sha(raw)
    factory.INDEX_SHA = args.index_sha256
    # The archive reader verifies the membership, modes and bytes against the
    # pinned manifest. Bind the two Python source inputs consumed by construct.
    files, hashes = factory.capture(args.source)
    for member, pin in (
        ("materialize.py", "go_materialize_sha256"),
        ("inputs/upstream/swesmith/profiles/golang.py", "go_profile_sha256"),
    ):
        if sha(files[member]) != PINS[pin]:
            raise ValueError(f"Different Go producer source: {member}")
    if (
        not args.task
        and args.index_sha256
        == "1dee9663bf086755aa6cff97e178337bc78d0be0f77e6273b9ab5cc213aa84f6"
    ):
        rows = factory.candidates(files)
    else:
        rows = read_rows(files["candidates.jsonl"], args.task)
    total = len(files["candidates.jsonl"].splitlines())
    factory.capture = lambda: (files, hashes)
    factory.candidates = lambda captured: rows
    # Both original factories share the same grader bytes.
    factory.HERE = args.operators / "go-batch-v1"
    result = factory.prepare(args.output, args.runtime_lock)
    result.pop("excluded_existing_squirrel_families", None)
    result.update(selected_rows=len(rows), unselected_rows=total - len(rows))
    factory.atomic(args.output / "manifest.json", result)
    return {
        "source_rows": total,
        "selected": len(rows),
        "materialized": sum("task_path" in r for r in result["items"]),
    }


def python_smith(args, raw):
    module = load(args.operators / "python-smith-wave-v3/prepare.py")
    module.SOURCE = args.source
    module.configure_inputs(args.manifest, sha(raw))
    rows = read_rows(checked(module.SOURCE_INDEX, module.INDEX_SHA), args.task)
    for row in rows:
        below(args.source, row["provenance_path"])
    module.rows = lambda: rows
    result = module.prepare(args.output)
    return {
        "selected": len(rows),
        "materialized": result["prepared"],
        "blocked": len(result["blocked"]),
    }


def swegym(args, raw):
    if args.manifest != args.source / "candidates.jsonl":
        raise ValueError("SWE-Gym requires SOURCE/candidates.jsonl")
    rows = read_rows(raw, [])
    selected = read_rows(raw, args.task)
    for row in rows:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", row["task_id"]):
            raise ValueError("Unsafe native task ID")
        below(args.source, row["inventory_path"])
        below(args.source, row["task_path"])
    module = load(args.operators / "python-jobs-wave-v1/bulk_adapter.py")
    module.SOURCE = args.source
    module.INDEX_SHA = sha(raw)
    module.PILOT_IDS = {row["task_id"] for row in selected}
    result = module.prepare(args.output)
    return {
        "selected": len(selected),
        "materialized": len(result["tasks"]),
        "screened": result["source_rows"],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--operators", type=Path, required=True)
    add_arguments(parser)
    args = parser.parse_args()
    args.source = args.source.resolve(strict=True)
    args.manifest = args.manifest.resolve(strict=True)
    if (
        args.output.exists()
        or args.output.is_symlink()
        or args.output.resolve().is_relative_to(args.source)
    ):
        parser.error("Use a fresh output directory outside the captured source")
    if args.family != "swesmith-go" and (
        args.index_sha256 or args.runtime_lock or args.go_profile != "single-package"
    ):
        parser.error("Go options require --family swesmith-go")
    transform = {"swesmith-go": go, "swesmith-py": python_smith, "swegym": swegym}
    result = transform[args.family](args, checked(args.manifest, args.expected_sha256))
    print(json.dumps(result, sort_keys=True))
