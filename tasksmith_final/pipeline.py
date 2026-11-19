"""Reproduce the Tasksmith HF Sandbox branch of the OpenEnv dataset pipeline."""

import argparse
import asyncio
import fcntl
import hashlib
import importlib.metadata
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

from admission import DEFAULT_SPEND, stage_plan, reserve
from adapt import modify
from audit import audit, context
from common import candidates, inside, jsonl, read, require, sha, source_digest, write
from evidence import gate
from stage import stage

HISTORICAL_REV = "3e8cb13c7e734d0d4dc2b6e7b13f01f32f9cb5d6"
HERE = Path(__file__).resolve().parent


def init(args):
    root = args.sources.resolve(strict=True)
    run = args.run.resolve()
    require(
        not run.is_relative_to(root) and not run.exists(),
        "supply a new run outside the source export",
    )
    require(
        re.fullmatch(r"[a-z][a-z0-9_]{0,47}", args.tag),
        "use a dataset-safe version, such as v2",
    )
    if args.revision:
        require(
            re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", args.revision),
            "expected immutable source revision",
        )
    rows = candidates(args.split)
    require(rows, "no verified Tasksmith rows found")
    base = jsonl(args.base)
    by_id = {r["task_id"]: r for r in base}
    require(len(by_id) == len(base), "duplicate task IDs in base view")
    skipped, digests, provenance_digests = [], {}, {}
    for tid, (_, row) in list(rows.items()):
        previous = by_id.get(tid)
        if previous:
            require(
                previous.get("task_origin") == "tasksmith"
                and previous["source_commit"] == row["source_head_commit"]
                and previous["source_repo"] == row["source_repo"]
                and previous.get("source_pr_url") == row["source_pr_url"],
                f"conflicting task ID in base: {tid}",
            )
            del rows[tid]
            skipped.append(tid)
            continue
        task = inside(root, row["task_path"])
        audit(task)
        meta = tomllib.loads((task / "task.toml").read_text())["metadata"]["repo2env"]
        require(
            meta["bundle_hash"] == row["tasksmith_bundle_hash"],
            f"bundle identity differs for {tid}",
        )
        digests[tid] = source_digest(task)
        provenance = inside(root, row["provenance_path"])
        require(provenance.is_dir(), f"missing provenance for {tid}")
        provenance_digests[tid] = source_digest(provenance)
    require(rows, "all selected tasks already occur in the base view")
    source_hash = hashlib.sha256(
        json.dumps([rows, digests, provenance_digests], sort_keys=True).encode()
    ).hexdigest()
    cfg = {
        "revision": args.revision or source_hash,
        "sources": str(root),
        "selected": rows,
        "digests": digests,
        "provenance_digests": provenance_digests,
        "already_present": skipped,
        "tag": args.tag,
        "prefix": f"tasksmith_hfsandbox_{args.tag}",
        "base": str(args.base.resolve()),
        "base_sha256": sha(args.base),
    }
    run.mkdir(parents=True, mode=0o700)
    write(run / "campaign.json", cfg)
    return {
        "tasks": len(rows),
        "already_present": len(skipped),
        "source_revision": cfg["revision"],
    }


def original(cfg, tid):
    task = inside(Path(cfg["sources"]), cfg["selected"][tid][1]["task_path"])
    require(
        source_digest(task) == cfg["digests"][tid], f"source tree changed for {tid}"
    )
    return task


def prepare(run, cfg, receipt_dir):
    receipt_dir = (receipt_dir or run / "images").resolve()
    target = run / "modified"
    require(not target.exists(), f"modified output already exists: {target}")
    with tempfile.TemporaryDirectory(dir=run) as tmp:
        dest = Path(tmp) / "modified"
        manifest = {}
        for tid, (_, row) in sorted(cfg["selected"].items()):
            task = original(cfg, tid)
            audit(task)
            from_receipt = receipt_dir / f"{tid}.json"
            receipt = read(from_receipt)
            hashes = {
                k: hashlib.sha256(v).hexdigest() for k, v in context(task).items()
            }
            require(
                receipt["task_id"] == tid and receipt["context_files"] == hashes,
                f"receipt does not match starter bytes for {tid}",
            )
            require(
                receipt["status"] == "resolved"
                and receipt["image"].endswith("@" + receipt["registry_digest"])
                and receipt["config"]["os"] == "linux"
                and receipt["config"]["architecture"] == "amd64",
                f"unresolved starter for {tid}",
            )
            rel = f"{cfg['prefix']}/tasks/{tid}"
            prov = modify(task, receipt, dest / rel, row["task_path"], cfg["revision"])
            manifest[tid] = {
                "path": rel,
                "image": receipt["image"],
                "effective_digest": source_digest(dest / rel),
                **prov,
            }
            local = run / "images" / f"{tid}.json"
            if from_receipt != local:
                local.parent.mkdir(exist_ok=True)
                if local.exists():
                    require(
                        sha(local) == sha(from_receipt),
                        f"conflicting local receipt for {tid}",
                    )
                else:
                    shutil.copyfile(from_receipt, local)
        write(dest / "modifications.json", manifest)
        dest.rename(target)
    return {"prepared": len(manifest)}


def live_environment():
    from openenv.validation import harbor, runner

    require(sys.version_info[:2] == (3, 13), "the scoring runtime uses Python 3.13")
    for line in (HERE / "runtime-constraints.txt").read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        package, version = line.split("==")
        require(
            importlib.metadata.version(package) == version,
            f"this protocol requires {package}=={version}",
        )
    for module, digest in (
        (harbor, "234835a1788537938ba8178721777c2b5248c48ec2c7db6b92eeef0f90c3ca73"),
        (runner, "0067e86e50086b473c65dbd6a178264b63402c33b24e7f65227a5ddfc563974a"),
    ):
        require(
            sha(Path(module.__file__)) == digest,
            "use the pinned OpenEnv separate-verifier checkout",
        )


def live(args, run, cfg):
    cmd = args.command
    if cmd in ("publish-images", "resolve-images"):
        from huggingface_hub import HfApi
        from images import load_registry, publish, resolve

        api = HfApi(endpoint="https://huggingface.co", token=os.environ["HF_TOKEN"])
        receipts = run / "images"
        receipts.mkdir(exist_ok=True)
        registry = (
            load_registry(args.starter_images) if cmd == "resolve-images" else None
        )
        for tid in cfg["selected"]:
            if cmd == "publish-images":
                publish(api, original(cfg, tid), receipts, args.namespace)
            else:
                receipt = resolve(
                    api,
                    receipts,
                    tid,
                    api.whoami()["name"],
                    os.environ["HF_TOKEN"],
                    registry,
                )
                require(
                    receipt["status"] == "resolved",
                    f"{tid} image pending: {receipt.get('stage')}",
                )
        return {"images": len(cfg["selected"])}
    mods = read(run / "modified/modifications.json")
    require(
        mods.keys() == cfg["selected"].keys(),
        "campaign inputs differ from prepared tasks",
    )
    for tid, mod in mods.items():
        task = inside(run / "modified", mod["path"])
        require(
            mod["path"] == f"{cfg['prefix']}/tasks/{tid}"
            and source_digest(task) == mod["effective_digest"],
            f"prepared bytes differ for {tid}",
        )
    ids = (
        sorted(mods)
        if cmd == "validate"
        else sorted(tid for tid, mod in mods.items() if not gate(run, tid, mod)[2])
    )
    if not ids:
        return {"stage": cmd, "eligible": 0, "reserved_usd": "0"}
    if cmd == "score":
        require(args.concurrency >= 1, "positive --concurrency required")
    require(
        re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,95}", args.namespace),
        "invalid HF Jobs namespace",
    )
    plan = stage_plan(run, args, mods, ids)
    if not args.submit:
        return plan
    live_environment()
    require(
        os.environ.get("HF_TOKEN"), "HF_TOKEN for the selected Jobs owner is required"
    )
    if cmd == "score":
        require(
            os.environ.get("OPENAI_API_KEY"),
            "OPENAI_API_KEY for the HF inference route is required",
        )
    check = reserve(run, args, plan)
    if cmd == "validate":
        dest = run / "validation/final"
        dest.mkdir(parents=True, exist_ok=True)
        for index, tid in enumerate(ids):
            mod = mods[tid]
            report = dest / f"{tid}.json"
            log = dest / f"{tid}.log"
            if report.exists():
                _, _, reasons = gate(run, tid, mod)
                require(
                    index or not reasons,
                    "validation canary failed; review its evidence",
                )
                continue
            task = inside(run / "modified", mod["path"])
            check()
            print(
                f"Validating {index + 1}/{len(ids)} {tid}", file=sys.stderr, flush=True
            )
            with log.open("x") as stream:
                binary = Path(sys.executable).parent / "openenv"
                result = subprocess.run(
                    [
                        binary,
                        "validate",
                        task,
                        "--sandbox",
                        "hf-sandbox",
                        "--namespace",
                        args.namespace,
                        "--level",
                        "semantic",
                        "--output",
                        report,
                    ],
                    stdout=stream,
                    stderr=subprocess.STDOUT,
                    pass_fds=(args.lock_fd,),
                )
            require(
                report.exists(),
                f"{tid}: validator exited {result.returncode}; inspect {log}",
            )
            _, _, reasons = gate(run, tid, mod)
            require(
                index or not reasons, "validation canary failed; review its evidence"
            )
        return {
            "validated": len(mods),
            "reservation_usd": plan["reservation_usd"],
            "actual_cost_usd": None,
        }
    from score_trials import score

    asyncio.run(
        score(
            run / "modified" / cfg["prefix"] / "tasks",
            run / "qwen/runs",
            args.concurrency,
            ids,
            args.namespace,
            check,
        )
    )
    return {
        "eligible": len(ids),
        "attempt_slots": len(ids) * 8,
        "reservation_usd": plan["reservation_usd"],
        "actual_cost_usd": None,
    }


def replay(cache, out):
    cache = cache.resolve(strict=True)
    out = out.resolve()
    require(
        not out.is_relative_to(cache),
        "historical cache is read-only; choose a different output root",
    )
    base = cache / "ds/views/scale800_v1/train.jsonl"
    cfg = {
        "selected": candidates(
            [cache / f"ds/splits/tasksmith_gap_v{v}.jsonl" for v in (2, 3, 4)]
        ),
        "revision": HISTORICAL_REV,
        "prefix": "tasksmith_hfsandbox_v1",
        "tag": "v1",
        "base": str(base),
        "base_sha256": sha(base),
    }
    pins = read(HERE / "historical_data.json")
    for rel, expected in pins.items():
        require(sha(cache / rel) == expected, f"historical input differs at {rel}")
    summary = stage(cache, out, cfg, historical=True)
    require(
        read(cache / "publish-summary.json") == summary,
        "replay counts differ from historical counts",
    )
    for view in ("final_v1", "final_best_v1"):
        rel = Path(f"views/{view}/train.jsonl")
        require(
            sha(out / rel) == sha(cache / "publish" / rel), f"replay differs for {view}"
        )
    return {**summary, "both_views_byte_identical": True}


def main():
    require(
        __debug__,
        "use Python without -O so the original transform checks remain active",
    )
    os.umask(0o077)
    cli = argparse.ArgumentParser(description=__doc__)
    subs = cli.add_subparsers(dest="command", required=True)
    parser = subs.add_parser(
        "replay", help="rebuild and compare the two historical views offline"
    )
    parser.add_argument("cache", type=Path)
    parser.add_argument("out", type=Path)
    for name in (
        "init",
        "prepare",
        "publish-images",
        "resolve-images",
        "validate",
        "score",
        "stage",
    ):
        parser = subs.add_parser(name)
        parser.add_argument("run", type=Path)
        if name == "init":
            parser.add_argument("--sources", required=True, type=Path)
            parser.add_argument(
                "--split",
                required=True,
                type=Path,
                action="append",
                help="ordered verified JSONL manifest; later copies of the same ID win",
            )
            parser.add_argument(
                "--base",
                required=True,
                type=Path,
                help="scale800 or previous final view train.jsonl",
            )
            parser.add_argument(
                "--tag", required=True, help="new dataset version, e.g. v2"
            )
            parser.add_argument(
                "--revision",
                help="immutable revision of the source export; defaults to local manifest hash",
            )
        elif name == "prepare":
            parser.add_argument(
                "--images", type=Path, help="directory of resolved starter receipts"
            )
        elif name == "resolve-images":
            parser.add_argument(
                "--starter-images",
                type=Path,
                required=True,
                help="pinned OpenEnv starter_images.py",
            )
        elif name in ("publish-images", "validate", "score"):
            parser.add_argument(
                "--namespace",
                required=True,
                help="HF Space owner or Jobs billing namespace",
            )
            if name in ("score", "validate"):
                parser.add_argument(
                    "--submit",
                    action="store_true",
                    help="reserve funds and start paid work",
                )
                parser.add_argument(
                    "--plan-sha256", help="hash returned by the estimate"
                )
                parser.add_argument(
                    "--ledger", type=Path, help="initialized shared OpenEnv ledger"
                )
                parser.add_argument(
                    "--budget-usd", help="maximum modeled reservation for this stage"
                )
                parser.add_argument("--spend-tool", type=Path, default=DEFAULT_SPEND)
            if name == "score":
                parser.add_argument("--concurrency", type=int, default=1)
        elif name == "stage":
            parser.add_argument(
                "out", type=Path, help="new private local export directory"
            )
    args = cli.parse_args()
    if args.command == "replay":
        result = replay(args.cache, args.out)
    elif args.command == "init":
        result = init(args)
    else:
        run = args.run.resolve(strict=True)
        cfg = read(run / "campaign.json")
        with (run / ".lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if args.command == "prepare":
                result = prepare(run, cfg, args.images)
            elif args.command == "stage":
                from publish import file_manifest

                out = args.out.resolve()
                result = stage(run, out, cfg)
                write(
                    run / "stage-manifest.json",
                    {"out": str(out), "files": file_manifest(out)},
                )
            else:
                args.lock_fd = lock.fileno()
                result = live(args, run, cfg)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
