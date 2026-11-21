"""Materialize sealed static audit records as native-format Harbor task directories."""

import argparse
from collections import Counter
import gzip
import hashlib
from importlib.metadata import version
import io
import json
from pathlib import Path
import re
import tarfile

from . import grading

IMAGE = "docker.io/library/python@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b"
SUBMISSION = "/tmp/answer.json"
COHORT_SHA = "1f1e183c76f81d72442ffcbaed0d8c17bf1a49c832b4981a2879c319101e56eb"
ORACLE = f"#!/bin/sh\nset -eu\ncp /solution/reference.json {SUBMISSION}\n"
VERIFY = """#!/bin/sh
set -eu
exec /usr/local/bin/python -I -B -S /tests/verify.py
"""
RUN_GRADER = f"""from pathlib import Path
from runpy import run_path

contract = run_path('/tests/grading.py')
expected = contract['parse_answer'](Path('/tests/expected.json').read_text())
answer = Path('{SUBMISSION}')
try:
    submitted = None if answer.is_symlink() else contract['parse_answer'](answer.read_text())
except (OSError, ValueError, RecursionError):
    submitted = None
value = contract['reward'](expected, submitted)
log = Path('/logs/verifier')
log.mkdir(parents=True, exist_ok=True)
(log / 'reward.txt').write_text(str(value) + '\\n')
"""
INSTRUCTION = f"Save your final JSON response to {SUBMISSION}. Harbor grades the contents of this file."


def sha(data):
    return hashlib.sha256(data).hexdigest()


def bundle_files(row, contract):
    """Only the base Dockerfile is visible in the agent's build context."""
    tid = row["task_id"]
    config = f"""schema_version = "1.3"
artifacts = ["{SUBMISSION}"]

[task]
name = "cyber-defense/{tid}"

[metadata.cyber_defense]
family = "{row['family']}"
sealed_task_sha256 = "{row['task_sha256']}"

[environment]
docker_image = "{IMAGE}"
workdir = "/tmp"
cpus = 1
memory_mb = 512
storage_mb = 2048
network_mode = "no-network"

[agent]
timeout_sec = 120
network_mode = "no-network"

[verifier]
timeout_sec = 60
environment_mode = "separate"
network_mode = "no-network"
"""
    openenv = {
        "profile": "harbor-semantic-v1", "reward_key": "reward",
        "reward": {"range": [0, 1], "oracle_tolerance": 0, "floor_margin": 0.1},
        "resources": {"cpu": 1, "memory_mb": 512, "disk_mb": 2048, "episode_timeout_s": 180},
        "types": {"tags": ["authorization"]}, "requires_credentials": False,
    }
    answer = grading.canonical(row["answer"]) + b"\n"
    return {
        "instruction.md": (row["prompt"].rstrip() + "\n\n" + INSTRUCTION + "\n").encode(),
        "task.toml": config.encode(),
        "environment/Dockerfile": f"FROM {IMAGE}\n".encode(),
        "solution/solve.sh": ORACLE.encode(),
        "solution/reference.json": answer,
        "tests/test.sh": VERIFY.encode(),
        "tests/expected.json": answer,
        "tests/grading.py": contract,
        "tests/verify.py": RUN_GRADER.encode(),
        "validation/openenv.json": grading.canonical(openenv) + b"\n",
    }


def write_equal(path, data):
    if path.exists():
        if path.is_symlink() or path.read_bytes() != data:
            raise ValueError(f"Existing artifact differs from the sealed export: {path}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as fd:
        fd.write(data)
    path.chmod(0o755 if path.suffix == ".sh" else 0o644)


def build(cohort, out):
    from harbor.models.task.task import Task
    from harbor.models.task.verifier_mode import resolve_verifier_environment_definition

    data = cohort.read_bytes()
    if sha(data) != COHORT_SHA:
        raise ValueError("Input does not match the frozen cohort")
    root = out / "harbor-bundles"
    archive = out / "harbor-bundles.tar.gz"
    rows = [json.loads(line) for line in data.splitlines()]
    package = Path(__file__).parent
    contract = (package / "grading.py").read_bytes()
    index = []
    file_names = set()
    families = Counter()
    for row in rows:
        tid = row["task_id"]
        if not re.fullmatch(r"[a-z0-9_-]+", tid) or grading.payload_sha256(row) != row["task_sha256"]:
            raise ValueError(f"Invalid task identity or digest: {tid!r}")
        folder = root / "tasks" / tid
        files = bundle_files(row, contract)
        for name, contents in files.items():
            path = folder / name
            write_equal(path, contents)
            file_names.add(path.relative_to(root).as_posix())
        task = Task(folder)
        verifier = resolve_verifier_environment_definition(task.config, task.paths)
        if (not Task.is_valid_dir(folder) or task.instruction != files["instruction.md"].decode()
                or task.config.environment.docker_image != IMAGE or verifier.config.docker_image != IMAGE
                or verifier.bundled_tests or verifier.directory != task.paths.environment_dir
                or task.config.agent.network_mode.value != "no-network"
                or task.config.verifier.network_mode.value != "no-network"
                or task.config.environment.network_mode.value != "no-network"):
            raise ValueError(f"Harbor failed to resolve the sealed contract: {tid}")
        index.append({"task_id":tid, "family":row["family"], "sealed_task_sha256":row["task_sha256"],
                      "files":{name:sha(contents) for name,contents in files.items()}})
        families[row["family"]] += 1
    index_data = b"".join(grading.canonical(row) + b"\n" for row in index)
    write_equal(root / "index.jsonl", index_data)
    license_files = [package / "access-review-LICENSE.txt", *sorted((package / "vendor").glob("cedar-*"))]
    for path in license_files:
        dest = root / "licenses" / path.name
        write_equal(dest, path.read_bytes())
        file_names.add(dest.relative_to(root).as_posix())
    file_names.add("index.jsonl")
    if {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()} != file_names:
        raise ValueError("Unexpected files in Harbor bundle directory")
    tmp = archive.with_suffix(".partial")
    with tmp.open("wb") as dest, gzip.GzipFile(filename="", fileobj=dest, mode="wb", mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w|") as tar:
            for name in sorted(file_names):
                contents = (root / name).read_bytes()
                info = tarfile.TarInfo(name)
                info.size = len(contents)
                info.mode = 0o755 if name.endswith(".sh") else 0o644
                tar.addfile(info, io.BytesIO(contents))
    if archive.exists() and archive.read_bytes() != tmp.read_bytes():
        tmp.unlink()
        raise ValueError("Existing task archive differs from the sealed export")
    tmp.replace(archive)
    report = dict(cohort_sha256=sha(data), archive_sha256=sha(archive.read_bytes()),
                  index_sha256=sha(index_data), grader_sha256=sha(contract), families=dict(families),
                  parser_validated=len(rows), harbor_version=version("harbor"), image=IMAGE,
                  adapter="sealed-static-authorization-to-harbor-v1", archive_members=len(file_names))
    write_equal(out / "harbor-materialization.json", json.dumps(report, indent=2).encode() + b"\n")
    return report


def stage_hf_control(run, task_id):
    """Create a separately versioned HF-compatible copy of one sealed local bundle."""
    from openenv.validation.runner import source_digest

    base = run / "harbor-bundles"
    index = [json.loads(line) for line in (base / "index.jsonl").read_bytes().splitlines()]
    row, = [r for r in index if r["task_id"] == task_id]
    source = base / "tasks" / task_id
    destination = run / "harbor-hf-control" / "v2" / "task"
    original = source_digest(source)
    files = {name:(source / name).read_bytes() for name in row["files"]}
    if {name:sha(data) for name,data in files.items()} != row["files"]:
        raise ValueError("The original bundle has changed")
    cfg = files["task.toml"]
    if cfg.count(b'network_mode = "no-network"') != 3:
        raise ValueError("Original task phase network settings have changed")
    files["task.toml"] = cfg.replace(b'network_mode = "no-network"', b'network_mode = "public"')
    meta = json.loads(files["validation/openenv.json"])
    meta["original_source_digest"] = original
    files["validation/openenv.json"] = grading.canonical(meta) + b"\n"
    for name,data in files.items():
        write_equal(destination / name, data)
    effective = source_digest(destination)
    receipt = dict(adapter="sealed-static-authorization-hf-sandbox-v2",
                   task_id=task_id, sealed_task_sha256=row["sealed_task_sha256"],
                   original_source_digest=original, effective_digest=effective,
                   changed=["task.toml", "validation/openenv.json"], image=IMAGE,
                   network_mode="public", verifier_mode="separate", directory=str(destination))
    write_equal(destination.parent / "staging.json", json.dumps(receipt, indent=2).encode()+b"\n")
    return receipt


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--run", type=Path, default=Path("runs/cyber-defense-1000"))
    p.add_argument("--hf-task", help="Stage one previously materialized task for HF Sandbox")
    args = p.parse_args()
    result = stage_hf_control(args.run,args.hf_task) if args.hf_task else build(args.run / "tasks.jsonl", args.run)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
