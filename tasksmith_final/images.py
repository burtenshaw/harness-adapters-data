"""OCI container builds (Kaniko on HF Jobs / Docker Buildx / OCI append) for Tasksmith tasks.

Replaces the historical Docker Space build route with direct OCI registry pushes
(e.g. ``ghcr.io/<org>/<repo>``) pinned by immutable ``linux/amd64`` ``@sha256:`` digests,
delegating to OpenEnv's ``openenv.harbor.images`` module with true parallel fan-out
and incremental per-task receipt writes.
"""

from collections import defaultdict
import hashlib
import importlib.util
import json
import sys
import time
from pathlib import Path

from audit import audit, context
from common import scan_credentials

ROOT = Path(__file__).resolve().parents[1]


def _load_openenv_images(openenv_src=None):
    pipeline_dir = str(ROOT / "openenv_pipeline")
    if pipeline_dir not in sys.path:
        sys.path.insert(0, pipeline_dir)
    from containerize import load_openenv_images

    return load_openenv_images(openenv_src)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def env_context_hashes(task_dir):
    """SHA-256 hashes of the audited ``environment/`` files (no Space README.md)."""
    return {
        k: sha(v)
        for k, v in context(task_dir).items()
        if k != "README.md"
    }


def build_oci(
    task_dirs,
    receipts,
    *,
    registry,
    builder="kaniko",
    namespace=None,
    flavor="cpu-basic",
    timeout="30m",
    cache_repo=None,
    concurrency=4,
    no_push=False,
    verify_public=True,
    tag_prefix="",
    extra_dockerfile=None,
    openenv_src=None,
):
    """Audit and build/push Tasksmith starter images in parallel to an OCI registry (no Spaces)."""
    images = _load_openenv_images(openenv_src)
    receipts = Path(receipts)
    receipts.mkdir(parents=True, exist_ok=True)
    extra_text = (
        Path(extra_dockerfile).read_text(encoding="utf-8")
        if isinstance(extra_dockerfile, (str, Path)) and Path(extra_dockerfile).is_file()
        else extra_dockerfile
    )
    extra_sha = sha(extra_text.encode("utf-8")) if extra_text else None

    expected_by_id = {}
    groups = defaultdict(list)
    results = {}
    for task_dir in sorted((Path(p).resolve() for p in task_dirs), key=lambda p: p.name):
        task_id = task_dir.name
        audit(task_dir)
        files = {k: v for k, v in context(task_dir).items() if k != "README.md"}
        for data in files.values():
            scan_credentials(data)
        expected_hashes = {k: sha(v) for k, v in sorted(files.items())}
        expected_by_id[task_id] = expected_hashes
        receipt_path = receipts / f"{task_id}.json"
        if receipt_path.is_file() and not no_push:
            existing = json.loads(receipt_path.read_text(encoding="utf-8"))
            if (
                existing.get("status") == "resolved"
                and existing.get("task_id") == task_id
                and existing.get("context_files") == expected_hashes
                and existing.get("extra_dockerfile_sha256") == extra_sha
            ):
                results[task_id] = existing
                continue
        groups[task_dir.parent].append(task_id)

    for parent_dir, batch_ids in sorted(groups.items()):
        summary = images.build_harbor_images(
            parent_dir,
            registry=registry,
            builder=builder,
            per_task_receipts_dir=receipts,
            task_ids=batch_ids,
            tag_prefix=tag_prefix,
            extra_dockerfile=extra_text,
            skip_pinned=False,
            verify_public=verify_public,
            no_push=no_push,
            concurrency=concurrency,
            namespace=namespace,
            flavor=flavor,
            timeout=timeout,
            cache_repo=cache_repo,
            progress=lambda msg: print(msg, file=sys.stderr, flush=True),
        )
        failures = [
            f"{tid}: {summary['tasks'][tid].get('error')}"
            for tid in batch_ids
            if summary["tasks"][tid]["status"] == "failed"
        ]
        if failures:
            raise RuntimeError("OCI image build failed:\n  " + "\n  ".join(failures))
        now = time.time()
        for tid in batch_ids:
            rec = summary["tasks"][tid]
            receipt = {
                "task_id": tid,
                "status": rec["status"],
                "builder": rec["builder"],
                "image": rec["image"],
                "registry_digest": rec["registry_digest"],
                "tag": rec["tag"],
                "config": rec["config"],
                "public_pull_verified": rec["public_pull_verified"],
                "env_hash": rec["env_hash"],
                "job_id": rec["job_id"],
                "context_files": expected_by_id[tid],
                "contents": "environment/Dockerfile and environment/source only; no tests, solution or instruction",
                "resolved_at": now,
                **(
                    {"extra_dockerfile_sha256": extra_sha}
                    if extra_sha is not None
                    else {}
                ),
            }
            dest = receipts / f"{tid}.json"
            tmp = dest.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(receipt, indent=1, sort_keys=True) + "\n", encoding="utf-8")
            tmp.replace(dest)
            results[tid] = receipt

    return results


# Legacy Space helper retained strictly for inspecting historical receipts.
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
