"""Acquire one registered Scale800 row and recheck its original source gate and image."""

import argparse
import json
import os
import re
from pathlib import Path

import run


def acquire(args):
    if (
        not re.fullmatch("[0-9a-f]{40}", args.revision)
        or not run.SAFE_ID.fullmatch(args.task)
        or not run.REPO_ID.fullmatch(args.source_repo)
    ):
        raise ValueError(
            "Supply a source dataset, immutable revision and native task ID"
        )
    root = args.output.resolve()
    run.install(args.cache, root, relocate=True)
    run.runtime_paths(root)
    import core
    import scale800_intake as go
    import python_source_intake_r3_v2 as py_v2
    import python_source_intake_r3_v3 as py_v3
    from huggingface_hub import HfApi

    data = args.index.read_bytes()
    if args.index.suffix == ".json":
        captured = core.loads(data)
        if (captured["repo_id"], captured["revision"]) != (
            args.source_repo,
            args.revision,
        ):
            raise ValueError("Accepted index belongs to another source or revision")
        rows = captured["rows"]
    else:
        rows = [core.loads(line) for line in data.splitlines() if line.strip()]
    matches = [r for r in rows if r["task_id"] == args.task]
    if not matches or any(row != matches[0] for row in matches):
        raise ValueError("Expected a unique native row in the registered source split")
    row = matches[0]
    if row["language"] == "go":
        go.GATE = (
            run.HERE.parent
            / "openenv_pipeline/operators/production/hf-check-gate-v1/gate.py"
        )
        if not args.image_receipts:
            raise ValueError(
                "Go intake needs --image-receipts with the starter publication receipts"
            )
        go.RUNTIME_IMAGES = args.image_receipts.resolve()
        module = go
    elif row["language"] == "python":
        module = py_v2 if row.get("adapter_plan_schema", "").endswith("-v1") else py_v3
    else:
        raise ValueError(
            "Scale800 source intake supports SWE-smith Go, SWE-smith Python, and SWE-Gym"
        )
    workspace = root / "incoming" / args.task
    workspace.parent.mkdir(parents=True, exist_ok=True)
    # Use credentials supplied to this process. The historical Hub constructor loaded its worktree .env.
    hub = core.Hub.__new__(core.Hub)
    hub.repo = args.source_repo
    hub.api = HfApi()
    info = hub.api.repo_info(hub.repo, repo_type="dataset", revision=args.revision)
    if info.id != hub.repo or info.private is not True or info.sha != args.revision:
        raise ValueError(
            "Source must resolve to the named private dataset and exact revision"
        )
    result = module.acquire_one(hub, args.revision, row, workspace)
    if module is go and result["status"] == "acquired":
        path = core.safe_path(row["gate_report_path"])
        report = (workspace / "hub" / path).read_bytes()
        result.update(
            task_directory=str(workspace),
            candidate_optional_gate_identity=dict(
                repo_id=hub.repo,
                revision=args.revision,
                report_path=path,
                report_sha256=run.sha(report),
            ),
        )
        core.atomic(workspace / "acquisition.json", result)
    print(
        json.dumps(
            {
                "acquisition": str(workspace),
                "task_id": args.task,
                "status": result["status"],
                "reason": result.get("reason"),
            }
        )
    )
    return result["status"] == "acquired"


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "index",
        type=Path,
        help="Registered split JSONL or accepted command's indexed JSON",
    )
    p.add_argument("task")
    p.add_argument("output", type=Path)
    p.add_argument("--revision", required=True)
    p.add_argument("--source-repo", required=True)
    p.add_argument("--cache", type=Path, default=run.DEFAULT_CACHE)
    p.add_argument(
        "--image-receipts",
        type=Path,
        help="Go runtime-images-v1 tree used to build the pinned images",
    )
    os.umask(0o077)
    raise SystemExit(0 if acquire(p.parse_args()) else 2)
