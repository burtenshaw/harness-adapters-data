"""Materialize six source-bound canonical Harbor archives without executing them."""

import argparse
import base64
import gzip
import hashlib
import io
import json
import subprocess
import tarfile
import tomllib
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent
CANON = ROOT / "canonical"
SOURCE_SHA = "b0905406ee4d0a97154949a991a00bf91cb7e6a0a1224eb304c04689ff8f6aa0"
MAX_EXPANDED = 8 * 1024 * 1024
MAX_FILES = 128


def unpack(data):
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as compressed:
        expanded = compressed.read(MAX_EXPANDED + 1)
    if len(expanded) > MAX_EXPANDED:
        raise ValueError("expanded byte cap")
    files = {}
    seen = set()
    total = 0
    with tarfile.open(fileobj=io.BytesIO(expanded), mode="r:") as archive:
        for member in archive:
            p = PurePosixPath(member.name)
            if (
                p.is_absolute()
                or ".." in p.parts
                or "\\" in member.name
                or not p.parts
                or str(p) != member.name
            ):
                raise ValueError("unsafe path")
            key = str(p).casefold()
            if key in seen or len(seen) >= MAX_FILES:
                raise ValueError("duplicate/member cap")
            seen.add(key)
            if member.isdir():
                continue
            if (
                not member.isfile()
                or member.issparse()
                or member.size > 2 * 1024 * 1024
            ):
                raise ValueError("nonregular/large file")
            total += member.size
            if total > MAX_EXPANDED:
                raise ValueError("payload cap")
            value = archive.extractfile(member).read()
            if len(value) != member.size:
                raise ValueError("short file")
            files[str(p)] = (value, member.mode & 0o777)
    if "task.toml" not in files:
        raise ValueError("missing root manifest")
    return files


def self_check():
    for name, kind in [("../escape", tarfile.REGTYPE), ("link", tarfile.SYMTYPE)]:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as t:
            m = tarfile.TarInfo(name)
            m.type = kind
            m.size = 1 if kind == tarfile.REGTYPE else 0
            t.addfile(m, io.BytesIO(b"x") if m.size else None)
        try:
            unpack(buffer.getvalue())
        except ValueError:
            continue
        raise AssertionError("unsafe archive accepted")


def main():
    source = CANON / "swegym-v5.tasks.parquet"
    if hashlib.sha256(source.read_bytes()).hexdigest() != SOURCE_SHA:
        raise ValueError("unverified source")
    literal = "'" + str(source).replace("'", "''") + "'"
    sql = f"SELECT path,to_base64(task_binary) AS archive_base64 FROM read_parquet({literal}) ORDER BY octet_length(task_binary),path LIMIT 25"
    result = subprocess.run(
        ["duckdb", ":memory:", "-json", "-c", sql], capture_output=True, check=True
    )
    rows = json.loads(result.stdout)
    if len(rows) != 25 or len({r["path"] for r in rows}) != 25:
        raise ValueError("unexpected selected set")
    (CANON / "selected25.raw.json").write_bytes(result.stdout)
    (CANON / "tasks").mkdir(exist_ok=True)
    selected = []
    materialized = []
    repos = set()
    for row in rows:
        data = base64.b64decode(row["archive_base64"], validate=True)
        files = unpack(data)
        metadata = json.loads(files["metadata.json"][0])
        task = tomllib.loads(files["task.toml"][0].decode())
        flags = [
            name
            for name, (payload, _) in files.items()
            if b"terminal-bench-canary" in payload.lower()
            or b"benchmark data should never" in payload.lower()
        ]
        inventory = {
            name: {
                "sha256": hashlib.sha256(payload).hexdigest(),
                "bytes": len(payload),
                "mode": mode,
            }
            for name, (payload, mode) in files.items()
        }
        record = {
            "task_id": row["path"],
            "source_repo": "open-thoughts/TaskTrove",
            "source_revision": "946884702046be1a7dcea2638186ad6b0d2ea103",
            "source_path": "laion__swegym-tasks-patched-validated-v5/tasks.parquet",
            "source_parquet_sha256": SOURCE_SHA,
            "archive_sha256": hashlib.sha256(data).hexdigest(),
            "archive_bytes": len(data),
            "metadata": metadata,
            "task_config": task,
            "files": inventory,
            "anti_training_canary_files": flags,
            "source_train_split_declared": metadata.get("split") == "train",
            "native_runtime_qualified": False,
            "benchmark_holdout_review": "pending_parent_policy",
            "task_specific_negative_controls": "not_generated_or_run",
            "leakage_qualified": False,
            "model_calibrated": False,
        }
        selected.append(record)
        if metadata["repo"] not in repos and not flags:
            target = CANON / "tasks" / row["path"]
            target.mkdir(exist_ok=False)
            for name, (payload, mode) in files.items():
                p = target / name
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(payload)
                p.chmod(mode)
            record["materialized_path"] = str(target)
            materialized.append(row["path"])
            repos.add(metadata["repo"])
    # One extra small mypy task gives six total, preserving the ten-package bound
    # with the four separately retained old Harbor samples.
    for record, row in zip(selected, rows):
        if len(materialized) >= 6:
            break
        if record["task_id"] in materialized or record["anti_training_canary_files"]:
            continue
        target = CANON / "tasks" / record["task_id"]
        target.mkdir(exist_ok=False)
        for name, (payload, mode) in unpack(
            base64.b64decode(row["archive_base64"])
        ).items():
            p = target / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(payload)
            p.chmod(mode)
        record["materialized_path"] = str(target)
        materialized.append(record["task_id"])
    if len(materialized) > 6:
        raise ValueError("package acquisition cap")
    (CANON / "selected25.json").write_text(
        json.dumps(
            {
                "schema": "scale800-canonical-swegym-intake-v1",
                "source_sha256": SOURCE_SHA,
                "selected_count": len(selected),
                "distinct_repos": len({r["metadata"]["repo"] for r in selected}),
                "materialized": materialized,
                "tasks": selected,
            },
            indent=2,
        )
        + "\n"
    )
    print(
        json.dumps(
            {
                "selected": len(selected),
                "materialized": materialized,
                "repos": sorted(repos),
            }
        )
    )


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--self-check", action="store_true")
    a = p.parse_args()
    self_check()
    if a.self_check:
        print("self-check passed")
    else:
        main()
