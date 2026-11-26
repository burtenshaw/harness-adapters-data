"""Build, OCI-append, push, and verify Harbor task containers via OpenEnv (no Spaces).

Delegates to OpenEnv's ``openenv.harbor.images`` feature (PR #1757) so every Harbor
export in this repository (Scale800 Go/Python, SWE-Gym, Tasksmith, Flash-Next waves,
Knowledge, Cyber Defense) produces digest-pinned, publicly pullable ``linux/amd64``
OCI images in ``task.toml`` without creating Docker Spaces.

Works on laptops and on Slurm cluster nodes (no local Docker daemon required when
using ``--builder kaniko`` on HF Jobs or pure-Python OCI append for COPY-only tasks):

    # One-time on a machine whose pinned OpenEnv predates PR #1757:
    python3 openenv_pipeline/run.py containerize --bootstrap-openenv-images

    # Plan / audit / classify any Harbor task directory or Tasksmith export:
    python3 openenv_pipeline/run.py containerize "$EXPORT/tasks" \\
        --source-manifest "$EXPORT/verified.jsonl" --plan --json

    # Build/append in parallel via Kaniko on HF Jobs -> single GHCR repo:
    export GHCR_TOKEN=... GHCR_USERNAME=burtenshaw HF_TOKEN=...
    python3 openenv_pipeline/run.py containerize "$EXPORT/tasks" \\
        --source-manifest "$EXPORT/verified.jsonl" \\
        --registry ghcr.io/harness-hub/tasksmith-flashnext \\
        --builder kaniko --namespace harness-hub --flavor cpu-upgrade \\
        --cache-repo ghcr.io/harness-hub/tasksmith-flashnext-cache \\
        --concurrency 16 \\
        --per-task-receipts-dir "$RUN/images" \\
        --output-dir "$RUN/harbor-ready" \\
        --receipts "$RUN/image-receipts.json"

    # Preflight-verify every task.toml points to a publicly pullable linux/amd64 digest:
    python3 openenv_pipeline/run.py containerize "$RUN/harbor-ready" \\
        --verify-only --require-digest-pin
"""

from __future__ import annotations

import argparse
import importlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OPENENV_IMAGES_GIT_URL = "https://github.com/openenv/OpenEnv.git"
OPENENV_IMAGES_BRANCH = "feat/harbor-build-images"
OPENENV_IMAGES_COMMIT = "ff1b9c1de719022164749deceac940c71e1da57a"
OPENENV_IMAGES_PR = "https://github.com/openenv/OpenEnv/pull/1757"
DEFAULT_LOCAL_OPENENV_IMAGES = ROOT / ".local" / "openenv-images"


def _candidate_openenv_srcs(openenv_src: Path | None = None) -> list[Path]:
    candidates: list[Path] = []
    if openenv_src is not None:
        candidates.append(openenv_src)
    env_src = os.environ.get("OPENENV_IMAGES_SRC")
    if env_src:
        candidates.append(Path(env_src))
    candidates.extend(
        [
            DEFAULT_LOCAL_OPENENV_IMAGES / "src",
            Path.home()
            / ".t3"
            / "worktrees"
            / "OpenEnv"
            / "feat-harbor-build-images"
            / "src",
            Path.home() / "code" / "OpenEnv" / "src",
        ]
    )
    return candidates


def bootstrap_openenv_images(
    dest: Path = DEFAULT_LOCAL_OPENENV_IMAGES,
    *,
    git_url: str = OPENENV_IMAGES_GIT_URL,
    commit: str = OPENENV_IMAGES_COMMIT,
) -> Path:
    """Shallow-checkout OpenEnv PR #1757 into ``.local/openenv-images`` (leaves pinned checkouts untouched)."""
    dest = dest.resolve()
    src = dest / "src"
    if (src / "openenv" / "harbor" / "images.py").is_file():
        head = subprocess.run(
            ["git", "-C", str(dest), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
        ).stdout.strip()
        if head == commit:
            return src
        subprocess.run(
            ["git", "-C", str(dest), "fetch", "--depth=1", git_url, commit],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(dest), "checkout", "--detach", commit],
            check=True,
        )
        return src

    dest.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="openenv-images-", dir=dest.parent) as tmp:
        repo = Path(tmp) / "repo"
        repo.mkdir()
        subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
        subprocess.run(
            ["git", "-C", str(repo), "fetch", "-q", "--depth=1", git_url, commit],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(repo), "checkout", "-q", "--detach", commit],
            check=True,
        )
        if not (repo / "src" / "openenv" / "harbor" / "images.py").is_file():
            raise RuntimeError(
                f"Checked-out OpenEnv commit {commit} does not contain src/openenv/harbor/images.py"
            )
        if dest.exists():
            raise FileExistsError(
                f"Destination exists without valid OpenEnv images module: {dest}"
            )
        repo.rename(dest)
    return src


def load_openenv_images(openenv_src: Path | None = None):
    """Import ``openenv.harbor.images`` from the active env or an OpenEnv source tree."""
    try:
        return importlib.import_module("openenv.harbor.images")
    except ModuleNotFoundError:
        pass

    for src in _candidate_openenv_srcs(openenv_src):
        resolved = src.expanduser().resolve()
        if (resolved / "openenv" / "harbor" / "images.py").is_file():
            if str(resolved) not in sys.path:
                sys.path.insert(0, str(resolved))
            if "openenv" in sys.modules:
                existing = getattr(sys.modules["openenv"], "__file__", "") or ""
                if str(resolved) not in existing:
                    for name in list(sys.modules):
                        if name == "openenv" or name.startswith("openenv."):
                            del sys.modules[name]
            return importlib.import_module("openenv.harbor.images")

    raise ModuleNotFoundError(
        "openenv.harbor.images is not installed in this Python environment.\n"
        f"Run `python3 openenv_pipeline/run.py containerize --bootstrap-openenv-images` "
        f"(fetches {OPENENV_IMAGES_PR} @ {OPENENV_IMAGES_COMMIT[:12]} into {DEFAULT_LOCAL_OPENENV_IMAGES}),\n"
        f"or install directly: `uv pip install 'git+{OPENENV_IMAGES_GIT_URL}@{OPENENV_IMAGES_BRANCH}'`,\n"
        "or pass --openenv-src PATH / set OPENENV_IMAGES_SRC."
    )


def task_ids_from_manifest(manifest_path: Path) -> list[str]:
    """Extract verified task IDs from a Tasksmith/pipeline JSONL manifest."""
    ids: list[str] = []
    seen: set[str] = set()
    for line in manifest_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if row.get("tasksmith_verified") is False:
            continue
        tid = row.get("task_id")
        if not tid and row.get("task_path"):
            tid = Path(row["task_path"]).name
        if not tid:
            raise ValueError(
                f"Manifest row missing task_id and task_path: {manifest_path}"
            )
        if tid not in seen:
            seen.add(tid)
            ids.append(tid)
    if not ids:
        raise ValueError(f"No verified tasks found in manifest: {manifest_path}")
    return ids


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "path",
        nargs="?",
        type=Path,
        help="Harbor task directory (with task.toml) or dataset directory containing tasks",
    )
    parser.add_argument(
        "--bootstrap-openenv-images",
        action="store_true",
        help=f"Shallow-clone OpenEnv PR #1757 ({OPENENV_IMAGES_COMMIT[:12]}) into .local/openenv-images and exit",
    )
    parser.add_argument(
        "--source-manifest",
        type=Path,
        help="Optional JSONL manifest (e.g. Tasksmith verified.jsonl) selecting task IDs under `path`",
    )
    parser.add_argument(
        "--task",
        action="append",
        default=[],
        help="Select specific task ID(s) under `path` (repeatable)",
    )
    parser.add_argument(
        "--registry",
        help="Target OCI repository (e.g. ghcr.io/harness-hub/scale800)",
    )
    parser.add_argument(
        "--builder",
        choices=("auto", "kaniko", "docker", "oci-append"),
        default="auto",
        help="Builder for RUN Dockerfiles (COPY-only always uses fast OCI layer append)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Write updated Harbor task copies with pinned task.toml here",
    )
    parser.add_argument(
        "--in-place",
        action="store_true",
        help="Rewrite [environment].docker_image directly in each task.toml",
    )
    parser.add_argument(
        "--receipts",
        type=Path,
        help="JSON receipt manifest (also enables resume across interrupted batches)",
    )
    parser.add_argument(
        "--per-task-receipts-dir",
        type=Path,
        help="Directory for incremental `<task_id>.json` receipts (directly consumable by tasksmith_final/pipeline.py prepare --images)",
    )
    parser.add_argument(
        "--extra-dockerfile",
        type=Path,
        help="Optional Dockerfile fragment appended to each task Dockerfile (e.g. preinstalling pi/opencode/hermes)",
    )
    parser.add_argument("--tag-prefix", default="")
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument(
        "--namespace",
        help="HF namespace for Kaniko Jobs and temporary build-context bucket",
    )
    parser.add_argument("--flavor", default="cpu-basic")
    parser.add_argument("--timeout", default="30m")
    parser.add_argument(
        "--kaniko-image", default="ghcr.io/osscontainertools/kaniko:debug"
    )
    parser.add_argument("--bucket", default="openenv-kaniko-builds")
    parser.add_argument(
        "--cache-repo",
        help="Optional OCI repository for Kaniko / BuildKit layer cache",
    )
    parser.add_argument("--no-oci-append", action="store_true")
    parser.add_argument("--rebuild-pinned", action="store_true")
    parser.add_argument("--strip-dockerfile", action="store_true")
    parser.add_argument(
        "--no-verify-public",
        action="store_true",
        help="Skip anonymous public pull verification (for private or localhost registries)",
    )
    parser.add_argument(
        "--plan",
        action="store_true",
        help="Audit, classify, and deduplicate without building or pushing",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Preflight-check every task.toml image is pullable as linux/amd64",
    )
    parser.add_argument(
        "--require-digest-pin",
        action="store_true",
        help="With --verify-only, reject mutable image tags without @sha256:...",
    )
    parser.add_argument(
        "--no-push",
        action="store_true",
        help="Build without pushing to a registry (useful for Kaniko/Docker smoke tests)",
    )
    parser.add_argument("--registry-user")
    parser.add_argument("--registry-password")
    parser.add_argument(
        "--openenv-src",
        type=Path,
        help="Path to an OpenEnv `src/` tree containing `openenv/harbor/images.py`",
    )
    parser.add_argument("--json", dest="json_output", action="store_true")


def execute(args: argparse.Namespace) -> dict:
    if getattr(args, "bootstrap_openenv_images", False):
        src = bootstrap_openenv_images()
        info = {
            "openenv_src": str(src),
            "commit": OPENENV_IMAGES_COMMIT,
            "pr": OPENENV_IMAGES_PR,
        }
        print(json.dumps(info, indent=2, sort_keys=True))
        return info

    if args.path is None:
        raise ValueError(
            "Supply a Harbor task or dataset directory `path` (or --bootstrap-openenv-images)"
        )

    images = load_openenv_images(getattr(args, "openenv_src", None))
    extra_text = (
        args.extra_dockerfile.read_text(encoding="utf-8")
        if args.extra_dockerfile
        else None
    )

    selected_ids: list[str] | None = None
    manifest_ids = (
        task_ids_from_manifest(args.source_manifest)
        if getattr(args, "source_manifest", None)
        else []
    )
    cli_ids = list(getattr(args, "task", None) or [])
    if manifest_ids or cli_ids:
        selected_ids = list(dict.fromkeys([*manifest_ids, *cli_ids]))

    if args.plan and args.verify_only:
        raise ValueError("Pass either --plan or --verify-only, not both")

    if args.verify_only:
        result = images.verify_harbor_images(
            args.path,
            anonymous=not args.no_verify_public,
            require_digest_pin=args.require_digest_pin,
            concurrency=args.concurrency,
            task_ids=selected_ids,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        if result["failed"]:
            raise SystemExit(1)
        return result

    if args.plan:
        plans = images.plan_harbor_images(
            args.path,
            registry=args.registry,
            tag_prefix=args.tag_prefix,
            extra_dockerfile=extra_text,
            skip_pinned=not args.rebuild_pinned,
            allow_oci_append=not args.no_oci_append,
            task_ids=selected_ids,
        )
        payload = {
            "total_tasks": len(plans),
            "unique_environments": len({(p.action, p.env_hash) for p in plans}),
            "actions": {
                a: sum(p.action == a for p in plans)
                for a in ("keep_pinned", "verify_shared", "oci_append", "build")
            },
            "tasks": [
                {
                    "task_id": p.task_id,
                    "action": p.action,
                    "env_hash": p.env_hash,
                    "base_image": p.base_image,
                    "target_tag": p.target_tag,
                    "reason": p.reason,
                }
                for p in plans
            ],
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
        return payload

    summary = images.build_harbor_images(
        args.path,
        registry=args.registry,
        builder=args.builder,
        output_dir=args.output_dir,
        in_place=args.in_place,
        receipts_path=args.receipts,
        per_task_receipts_dir=getattr(args, "per_task_receipts_dir", None),
        task_ids=selected_ids,
        tag_prefix=args.tag_prefix,
        extra_dockerfile=extra_text,
        skip_pinned=not args.rebuild_pinned,
        allow_oci_append=not args.no_oci_append,
        strip_dockerfile_for_shared=args.strip_dockerfile,
        verify_public=not args.no_verify_public,
        no_push=args.no_push,
        concurrency=args.concurrency,
        namespace=args.namespace,
        flavor=args.flavor,
        timeout=args.timeout,
        kaniko_image=args.kaniko_image,
        bucket_name=args.bucket,
        cache_repo=args.cache_repo,
        registry_username=args.registry_user,
        registry_password=args.registry_password,
        progress=None
        if args.json_output
        else (lambda msg: print(msg, file=sys.stderr, flush=True)),
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    if summary["failed"]:
        raise SystemExit(1)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    add_arguments(parser)
    execute(parser.parse_args())


if __name__ == "__main__":
    main()
