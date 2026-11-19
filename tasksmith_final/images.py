"""Historical starter Space build and digest verification."""

import hashlib
import importlib.util
import json
import time

import httpx
from huggingface_hub import CommitOperationAdd

from audit import audit, context
from common import scan_credentials


def load_registry(path):
    if (
        hashlib.sha256(path.read_bytes()).hexdigest()
        != "2c18a634e28c18c03c0b14add408ed74965fd9e48ba04603a99605b3f1d00129"
    ):
        raise ValueError("unexpected OpenEnv starter_images.py version")
    spec = importlib.util.spec_from_file_location("starter_images", path)
    starter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(starter)
    return starter.Registry


def sha(data):
    return hashlib.sha256(data).hexdigest()


def publish(api, task_dir, receipts, namespace):
    task_id = task_dir.name
    receipt_path = receipts / f"{task_id}.json"
    if receipt_path.exists():
        return json.loads(receipt_path.read_text())
    files = context(task_dir)
    audit(task_dir)
    for data in files.values():
        scan_credentials(data)
    repo = f"{namespace}/{task_id}-env"
    api.create_repo(
        repo, repo_type="space", space_sdk="docker", private=True, exist_ok=False
    )
    commit = api.create_commit(
        repo,
        repo_type="space",
        operations=[
            CommitOperationAdd(path_in_repo=n, path_or_fileobj=d)
            for n, d in sorted(files.items())
        ],
        commit_message="Starter image context (environment/ only)",
    )
    tree = {
        f.path: f
        for f in api.list_repo_tree(
            repo, repo_type="space", revision=commit.oid, recursive=True
        )
        if hasattr(f, "blob_id") and f.path != ".gitattributes"
    }
    if set(tree) != set(files):
        raise ValueError(f"{task_id}: uploaded inventory differs")
    for name, data in files.items():
        entry = tree[name]
        if entry.lfs is not None:
            ok = entry.lfs.sha256 == sha(data)
        else:
            ok = (
                entry.blob_id
                == hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()
            )
        if not ok:
            raise ValueError(f"{task_id}: uploaded bytes differ")
    api.update_repo_settings(repo, repo_type="space", private=False)
    receipt = {
        "task_id": task_id,
        "space_id": repo,
        "space_commit": commit.oid,
        "context_files": {n: sha(d) for n, d in sorted(files.items())},
        "contents": "environment/Dockerfile and environment/source only; no tests, solution or instruction",
        "status": "building",
    }
    receipt_path.write_text(json.dumps(receipt, indent=1))
    return receipt


def resolve(api, receipts, task_id, username, token, registry_class):
    receipt_path = receipts / f"{task_id}.json"
    receipt = json.loads(receipt_path.read_text())
    if receipt.get("status") == "resolved":
        return receipt
    runtime = api.get_space_runtime(receipt["space_id"])
    if (
        runtime.stage in ("BUILDING", "NO_APP_FILE", "CONFIG_ERROR")
        or runtime.stage == "BUILD_ERROR"
    ):
        receipt["stage"] = runtime.stage
        receipt_path.write_text(json.dumps(receipt, indent=1))
        return receipt
    info = api.space_info(receipt["space_id"])
    if info.sha != receipt["space_commit"] or info.private:
        raise ValueError(f"{task_id}: Space commit or visibility drift")
    with httpx.Client() as http:
        registry = registry_class(http, info.subdomain, username, token)
        pinned = registry.resolve()
        if api.pause_space(receipt["space_id"]).stage != "PAUSED":
            raise ValueError(f"{task_id}: pause not confirmed")
        again = registry.resolve(pinned["registry_digest"])
    if again["image"] != pinned["image"]:
        raise ValueError(f"{task_id}: digest drift after pause")
    receipt.update(
        pinned, stage=runtime.stage, status="resolved", resolved_at=time.time()
    )
    receipt_path.write_text(json.dumps(receipt, indent=1))
    return receipt
