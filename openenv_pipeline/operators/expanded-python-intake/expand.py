"""Materialize source-screened TaskTrove PR tasks; never run repository code."""

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import threading
import time
import tomllib
import types
from collections import Counter, defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import requests

HERE = Path(__file__).resolve().parent
PILOT = HERE.parent
REVISION = "946884702046be1a7dcea2638186ad6b0d2ea103"
SHARD = "harbor/canonical/swegym-v5.tasks.parquet"
INPUTS = {
    SHARD: "b0905406ee4d0a97154949a991a00bf91cb7e6a0a1224eb304c04689ff8f6aa0",
    "expanded-python-intake/metadata-index.jsonl": "09abef60360e5cf61bdbc8366f79834936e8fae49fc9cc0d044d6b923e0689d4",
    "pilot50/harbor/screen.py": "50fef07f979f66953555143546ef9f4c98bdcffb2f51546f16e19f25f315a02a",
    "harbor/materialize_canonical.py": "76d1052db63460e3513d55f45584b84a8a1e20b12807bf9c02e6b577e3c9f3ba",
    "harbor/intake-manifest.json": "a8445d66949383c75807c2ce26d06f917db1941a7889a0fca212307531af0e5b",
    "harbor/TaskTrove.README.md": "a906abccd50817f3dd2ea2485b43f5411aec676441025422c15c8a031ac55828",
    "harbor/canonical/licenses-by-commit.json": "3c9644993bf9d98da2af38ffe417c6f3ab80e514f678db427aef33778b6a768a",
    "eligibility/policy.json": "4d9da53bf49d807086bf98c10c4761e33a295e0cc1fb4e5a53bd29ad30c71645",
    "eligibility/existing-identities.json": "4cf47bfcf624ef7e02250049f3ac71a946a6e9492590b07d2ebbc73c621f91ce",
    "eligibility/eligibility.py": "ed3b044361e5e5fdee2595f1d72372c3f877d4f278a21f8d7ff798e338f47f30",
}
SHA1 = re.compile(r"[a-f0-9]{40}\Z")
REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
LIMIT = 128 * 1024 * 1024
FILE_LIMIT = 4 * 1024 * 1024
LICENSE_NAMES = {
    "conan-io/conan": ["LICENSE.md", "LICENSE"],
    "bokeh/bokeh": ["LICENSE.txt", "LICENSE"],
    "dask/dask": ["LICENSE.txt", "LICENSE"],
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def atomic(path, data):
    if not isinstance(data, bytes):
        data = encoded(data)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def capture(root=PILOT, expected=INPUTS, read=None):
    read = read or (lambda path: path.read_bytes())
    captured = {}
    for name, expected_sha in expected.items():
        path = root / name
        if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
            raise ValueError("Pinned input must be a regular real file")
        raw = read(path)
        if sha(raw) != expected_sha:
            raise ValueError("Pinned captured input changed: " + name)
        captured[name] = raw
    return captured


def module(name, raw, filename):
    result = types.ModuleType(name)
    result.__file__ = str(filename)
    exec(compile(raw, str(filename), "exec"), result.__dict__)
    return result


def tools(captured):
    screen = module(
        "frozen_screen",
        captured["pilot50/harbor/screen.py"],
        PILOT / "pilot50/harbor/screen.py",
    )
    extractor = module(
        "frozen_unpack",
        captured["harbor/materialize_canonical.py"],
        PILOT / "harbor/materialize_canonical.py",
    )
    assessor = module(
        "frozen_assessor",
        captured["eligibility/eligibility.py"],
        PILOT / "eligibility/eligibility.py",
    )
    return screen, extractor, assessor


def classify_license(raw):
    text = raw.decode("utf-8").casefold()
    if "permission is hereby granted" in text and "without restriction" in text:
        return "MIT"
    if (
        "apache license" in text
        and "version 2.0" in text
        and "terms and conditions" in text
    ):
        return "Apache-2.0"
    if (
        "redistribution and use in source and binary forms" in text
        and "this software is provided" in text
    ):
        if "neither the name" in text:
            return "BSD-3-Clause"
        if (
            "redistributions of source code" in text
            and "redistributions in binary form" in text
        ):
            return "BSD-2-Clause"
    raise ValueError("Captured source license needs a separate review")


def archive_record(row, metadata_index, screen, extractor):
    task_id = row["path"]
    if not re.fullmatch(r"swegym-[0-9]{4}", task_id):
        raise ValueError("Unexpected source task identity")
    raw = base64.b64decode(row["archive_base64"], validate=True)
    if sha(raw) != metadata_index[task_id]["archive_sha256"]:
        raise ValueError("Native archive differs from pinned independent inventory")
    files = extractor.unpack(raw)
    inventory = {
        name: {"sha256": sha(data), "bytes": len(data), "mode": mode}
        for name, (data, mode) in sorted(files.items())
    }
    files, inventory = screen.unpack(
        raw, {"archive_sha256": sha(raw), "files": inventory}, extractor.unpack
    )
    metadata = json.loads(files["metadata.json"][0])
    repo, commit = metadata["repo"], metadata["base_commit"]
    if (
        not REPO.fullmatch(repo)
        or not SHA1.fullmatch(commit)
        or metadata["split"] != "train"
    ):
        raise ValueError("Source repository, full commit or train split invalid")
    observed = metadata_index[task_id]
    if (
        any(
            observed[key] != value
            for key, value in (
                ("source_repo", repo),
                ("source_commit", commit),
                ("source_split", metadata["split"]),
            )
        )
        or observed["native_task_files"] != len(files)
        or observed["native_task_bytes"] != sum(len(data) for data, _ in files.values())
    ):
        raise ValueError("Native metadata differs from captured census")
    prefix = repo.replace("/", "__") + "-"
    instance = metadata["instance_id"]
    if not instance.startswith(prefix) or not instance[len(prefix) :].isdigit():
        raise ValueError("Native source PR identity ambiguous")
    if (
        repo.encode() not in files["instruction.md"][0]
        or commit.encode() not in files["instruction.md"][0]
        or f"https://github.com/{repo}.git".encode()
        not in files["solution/solve.sh"][0]
    ):
        raise ValueError("Instruction/oracle source identity differs")
    if not metadata["fail_to_pass"] or not metadata["pass_to_pass"]:
        raise ValueError("No frozen F2P/P2P panel")
    for key in ("fail_to_pass", "pass_to_pass"):
        if not isinstance(metadata[key], list) or any(
            not isinstance(value, str) or not value for value in metadata[key]
        ):
            raise ValueError("Native test identities malformed")
    canaries = [
        name
        for name, (data, _) in files.items()
        if any(marker in data.lower() for marker in screen.ANTI_TRAINING)
    ]
    if canaries:
        raise ValueError("Anti-training source marker")
    patch, patch_paths = screen.repair_patch(files)
    return {
        "task_id": task_id,
        "archive": raw,
        "files": files,
        "inventory": inventory,
        "metadata": metadata,
        "patch": patch,
        "patch_paths": patch_paths,
        "source_pr_url": f"https://github.com/{repo}/pull/{instance[len(prefix) :]}",
    }


def select(records, policy, existing, per_repo=150):
    queues, excluded, seen = defaultdict(deque), [], set()
    known = {url.casefold() for url in existing["source_pr_urls"]}
    for record in sorted(records, key=lambda value: value["task_id"]):
        repo, url = record["metadata"]["repo"], record["source_pr_url"].casefold()
        identity = (repo.casefold(), sha(record["patch"]))
        if (
            repo.casefold() in policy["quarantined_repositories"]
            or url in known
            or url in seen
            or identity in seen
        ):
            excluded.append(
                {
                    "task_id": record["task_id"],
                    "reason": "benchmark/existing/duplicate source identity",
                }
            )
            continue
        seen.update((url, identity))
        if len(queues[repo]) < per_repo:
            queues[repo].append(record)
        else:
            excluded.append(
                {
                    "task_id": record["task_id"],
                    "reason": "per-repository engineering cap",
                }
            )
    selected = []
    while any(queues.values()):
        for repo in sorted(queues):
            if queues[repo]:
                selected.append(queues[repo].popleft())
    return selected, excluded


class Licenses:
    def __init__(self, output, captured, source_root=PILOT):
        self.output, self.lock, self.local = output, threading.Lock(), threading.local()
        path = output / "network.json"
        state = json.loads(path.read_bytes()) if path.exists() else {}
        self.received = state.get("received_bytes", 0)
        self.failed = state.get("failed_request_allowance_bytes", 0)
        self.pending = 0
        self.receipts = state.get("requests", [])
        if state.get("in_flight_reserved_bytes", 0):
            raise ValueError("Reconcile interrupted license requests before resuming")
        self.prior = {}
        manifest = json.loads(captured["harbor/intake-manifest.json"])["files"]
        for value in json.loads(captured["harbor/canonical/licenses-by-commit.json"]):
            name = "canonical/licenses-by-commit/" + value["task_id"] + ".LICENSE"
            raw = (source_root / "harbor" / name).read_bytes()
            if sha(raw) != manifest[name]["sha256"] or sha(raw) != value["sha256"]:
                raise ValueError("Frozen prior license changed")
            self.prior[(value["repo"], value["commit"])] = (
                raw,
                {**value, "reused_frozen_pilot25": True},
            )

    def save(self):
        atomic(
            self.output / "network.json",
            {
                "received_bytes": self.received,
                "failed_request_allowance_bytes": self.failed,
                "in_flight_reserved_bytes": self.pending,
                "cap_bytes": LIMIT,
                "requests": self.receipts,
            },
        )

    def get(self, url):
        key = sha(url.encode())
        path = self.output / "license-cache" / (key + ".json")
        if path.exists():
            record = json.loads(path.read_bytes())
            raw = (path.with_suffix(".data")).read_bytes()
            if record["url"] != url or sha(raw) != record["sha256"]:
                raise ValueError("Cached license identity differs")
            return record["http_status"], raw
        with self.lock:
            if self.received + self.failed + self.pending + FILE_LIMIT > LIMIT:
                raise ValueError("License public-read budget exhausted")
            self.pending += FILE_LIMIT
            receipt = {"url": url, "status": "started"}
            self.receipts.append(receipt)
            self.save()
        raw = bytearray()
        completed = False
        try:
            if not hasattr(self.local, "session"):
                self.local.session = requests.Session()
                self.local.session.trust_env = False
            with self.local.session.get(
                url, stream=True, timeout=(10, 30), allow_redirects=False
            ) as response:
                for chunk in response.iter_content(65536):
                    raw.extend(chunk)
                    if len(raw) > FILE_LIMIT:
                        raise ValueError("License response exceeds cap")
                status = response.status_code
            data = bytes(raw)
            record = {
                "url": url,
                "http_status": status,
                "sha256": sha(data),
                "bytes": len(data),
            }
            atomic(path.with_suffix(".data"), data)
            atomic(path, record)
            receipt.update(record, status="complete")
            completed = True
            return status, data
        finally:
            with self.lock:
                self.pending -= FILE_LIMIT
                self.received += len(raw)
                if not completed:
                    self.failed += max(0, FILE_LIMIT - len(raw))
                    receipt["status"] = "failed_or_partial"
                self.save()

    def resolve(self, record):
        metadata = record["metadata"]
        repo, commit = metadata["repo"], metadata["base_commit"]
        if (repo, commit) in self.prior:
            raw, proof = self.prior[(repo, commit)]
            return raw, {
                "url": proof["url"],
                "sha256": sha(raw),
                "spdx": classify_license(raw),
                "reused_frozen_pilot25": True,
            }
        names = list(
            dict.fromkeys(
                LICENSE_NAMES.get(repo, [])
                + ["LICENSE", "LICENSE.txt", "LICENSE.md", "LICENCE", "COPYING"]
            )
        )
        probes = []
        for name in names:
            url = f"https://raw.githubusercontent.com/{repo}/{commit}/{name}"
            status, raw = self.get(url)
            probes.append({"filename": name, "http_status": status})
            if status == 200:
                return raw, {
                    "url": url,
                    "sha256": sha(raw),
                    "spdx": classify_license(raw),
                    "probes": probes,
                    "reused_frozen_pilot25": False,
                }
            if status not in (404,):
                raise ValueError("Primary license request not successful")
        raise ValueError("No reviewed source license available at exact commit")


def candidate(record, license_proof, card):
    metadata = record["metadata"]
    expected_prefix = f"https://raw.githubusercontent.com/{metadata['repo']}/{metadata['base_commit']}/"
    if not license_proof["url"].startswith(expected_prefix):
        raise ValueError("License source pin differs from native task")
    task_id = record["task_id"]
    config = tomllib.loads(record["files"]["task.toml"][0].decode())
    return {
        "candidate_id": f"TaskTrove:{REVISION}:{task_id}",
        "task_id": task_id,
        "source_task_id": metadata["instance_id"],
        "task_path": "tasks/" + task_id,
        "provenance_path": "provenance/" + task_id + ".json",
        "inventory_path": "inventories/" + task_id + ".json",
        "source_kind": "pr",
        "source_dataset": "open-thoughts/TaskTrove",
        "original_source_dataset": metadata["source"],
        "source_repo": metadata["repo"],
        "upstream_repo": metadata["repo"],
        "repository_lineage": [metadata["repo"]],
        "source_commit": metadata["base_commit"],
        "source_pr_url": record["source_pr_url"],
        "source_revision": REVISION,
        "source_split": "train",
        "task_sha256": sha(record["archive"]),
        "task_sha256_kind": "original-native-tar-gzip",
        "native_inventory_sha256": sha(encoded(record["inventory"])),
        "patch_sha256": sha(record["patch"]),
        "instruction_sha256": sha(record["files"]["instruction.md"][0]),
        "upstream_identity_reviewed": True,
        "anti_training_reviewed": True,
        "anti_training_canary": False,
        "evaluation_only": False,
        "license_evidence": {
            "source_code": {
                **license_proof,
                "reviewed": True,
                "training_allowed": True,
                "scope": "captured exact-commit upstream software grant; all notices retained",
            },
            "task_bundle": {
                "spdx": "Apache-2.0",
                "sha256": sha(card),
                "url": f"https://huggingface.co/datasets/open-thoughts/TaskTrove/blob/{REVISION}/README.md",
                "reviewed": True,
                "training_allowed": True,
                "scope": "publisher-declared wrapper/train corpus; upstream notices remain applicable",
            },
        },
        "fail_to_pass": metadata["fail_to_pass"],
        "pass_to_pass": metadata["pass_to_pass"],
        "repair_patch_paths": record["patch_paths"],
        "native_task_config": config,
        "runtime_resource_review_required": metadata["repo"] == "Project-MONAI/MONAI"
        or bool(config.get("environment", {}).get("gpus")),
        "runtime_blockers": [
            "unqualified repository worktree preparation and patch/file handoff",
            "missing task-specific negatives and canaries",
            "unqualified immutable runtime image",
            "reference/NOP/replay and model audit not run",
        ],
        "transfer_contract": {
            "status": "blocked_missing_repository_patch_adapter",
            "allowlist": [],
        },
        "negative_controls": [],
        "usage": "quarantine_only",
        "cloud_launch_ready": False,
        "published_image_pins_qualified": False,
        "native_runtime_qualified": False,
        "target_model_calibrated": False,
        "rfc008_complete": False,
        "trainability_established": False,
        "semantic_nonoverlap_established": False,
        "training_admissible": False,
        "verified": False,
    }


def materialize(output, record, row, license_raw):
    task = output / row["task_path"]
    if task.exists():
        actual = {
            p.relative_to(task).as_posix(): {
                "sha256": sha(p.read_bytes()),
                "bytes": p.stat().st_size,
                "mode": stat.S_IMODE(p.stat().st_mode),
            }
            for p in task.rglob("*")
            if p.is_file() and not p.is_symlink()
        }
        if actual != record["inventory"] or any(
            p.is_symlink() for p in task.rglob("*")
        ):
            raise ValueError("Existing materialized tree bytes/modes differ")
    else:
        stage = Path(tempfile.mkdtemp(dir=output / "staging"))
        try:
            for name, (data, mode) in record["files"].items():
                target = stage / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
                target.chmod(mode)
            task.parent.mkdir(exist_ok=True)
            os.replace(stage, task)
        finally:
            if stage.exists():
                shutil.rmtree(stage)
    for path, data in {
        row["inventory_path"]: encoded(record["inventory"]),
        row["provenance_path"]: encoded(
            {
                "source": row,
                "original_metadata": record["metadata"],
                "original_archive_sha256": sha(record["archive"]),
                "source_file_inventory": record["inventory"],
            }
        ),
        "evidence/" + row["task_id"] + ".LICENSE": license_raw,
        "evidence/" + row["task_id"] + ".repair.patch": record["patch"],
        "archives/" + row["task_id"] + ".tar.gz": record["archive"],
        "records/" + row["task_id"] + ".json": encoded(row),
    }.items():
        atomic(output / path, data)


def build(output, limit=800, source_root=PILOT):
    if not 1 <= limit <= 800:
        raise ValueError("Use at most800 source candidates")
    if (output / "summary.json").exists():
        verify_release(output)
        return json.loads((output / "summary.json").read_bytes())
    output.mkdir(parents=True, exist_ok=True)
    output.chmod(0o700)
    (output / "staging").mkdir(exist_ok=True)
    captured = capture(source_root)
    screen, extractor, assessor = tools(captured)
    for name, raw in captured.items():
        atomic(output / "inputs" / name, raw)
    card = captured["harbor/TaskTrove.README.md"]
    if (
        "license: apache-2.0" not in card.decode().split("---", 2)[1]
        or "- split: train" not in card.decode().split("---", 2)[1]
    ):
        raise ValueError("Publisher declaration changed")
    shard = output / "inputs" / SHARD
    result = subprocess.run(
        [
            "/opt/homebrew/bin/duckdb",
            "-json",
            "-c",
            "SELECT path,to_base64(task_binary) AS archive_base64 FROM read_parquet('"
            + str(shard).replace("'", "''")
            + "') ORDER BY path",
        ],
        capture_output=True,
        check=True,
    )
    raw_rows = json.loads(result.stdout)
    metadata_index = {
        r["task_id"]: r
        for r in map(
            json.loads,
            captured["expanded-python-intake/metadata-index.jsonl"].splitlines(),
        )
    }
    if len(raw_rows) != 2428 or len({r["path"] for r in raw_rows}) != 2428:
        raise ValueError("Canonical row inventory changed")
    records = []
    unknown = []
    for row in raw_rows:
        try:
            records.append(archive_record(row, metadata_index, screen, extractor))
        except Exception as exc:
            unknown.append(
                {
                    "task_id": row["path"],
                    "stage": "native_source_parse",
                    "error_class": type(exc).__name__,
                    "reason": str(exc),
                }
            )
    policy = json.loads(captured["eligibility/policy.json"])
    existing = json.loads(captured["eligibility/existing-identities.json"])
    pool, excluded = select(records, policy, existing)
    atomic(
        output / "selection.json",
        {
            "pool_count": len(pool),
            "repositories": dict(Counter(r["metadata"]["repo"] for r in pool)),
            "source_parse_unknown": len(unknown),
            "metadata_excluded": len(excluded),
            "limit": limit,
        },
    )
    print(
        json.dumps(
            {
                "checkpoint": "source_pool",
                "pool_count": len(pool),
                "repositories": len({r["metadata"]["repo"] for r in pool}),
                "parse_unknown": len(unknown),
            }
        ),
        flush=True,
    )
    licenses = Licenses(output, captured, source_root)
    for value in json.loads(captured["harbor/canonical/licenses-by-commit.json"]):
        prior_raw, _ = licenses.prior[(value["repo"], value["commit"])]
        atomic(
            output
            / "inputs/harbor/canonical/licenses-by-commit"
            / (value["task_id"] + ".LICENSE"),
            prior_raw,
        )
    prior_records = [
        json.loads(path.read_bytes())
        for path in sorted((output / "records").glob("*.json"))
    ]
    prior_attempts = [
        json.loads(path.read_bytes())
        for path in sorted((output / "attempts").glob("*.json"))
    ]
    unknown.extend(
        attempt["error"] for attempt in prior_attempts if attempt.get("error")
    )
    by_id = {record["task_id"]: record for record in pool}
    accepted = []
    for row in prior_records:
        if (
            row["task_id"] not in by_id
            or row["intake_assessment"]["status"] != "eligible_for_controls"
        ):
            raise ValueError("Resume record differs from selected source identities")
        source = by_id[row["task_id"]]
        license_raw = (output / "evidence" / (row["task_id"] + ".LICENSE")).read_bytes()
        if sha(license_raw) != row["license_evidence"]["source_code"]["sha256"]:
            raise ValueError("Resume license bytes changed")
        materialize(output, source, row, license_raw)
        accepted.append(row)
    existing_progress = (
        json.loads((output / "progress.json").read_bytes())
        if (output / "progress.json").exists()
        else {}
    )
    attempted = max(
        existing_progress.get("attempted", 0), len(accepted), len(prior_attempts)
    )
    started = time.monotonic()
    prior25 = {
        row["task_id"]
        for row in json.loads(captured["harbor/canonical/licenses-by-commit.json"])
    }

    def resolve(record):
        try:
            raw, proof = licenses.resolve(record)
            if proof["sha256"] != sha(raw) or proof["spdx"] != classify_license(raw):
                raise ValueError("License proof differs from captured bytes")
            row = candidate(record, proof, card)
            decision = assessor.assess(row, policy, existing)
            row["intake_assessment"] = decision
            row["prior_pilot25_member"] = row["task_id"] in prior25
            return record, row, raw, None
        except Exception as exc:
            return (
                record,
                None,
                None,
                {
                    "task_id": record["task_id"],
                    "stage": "source_license_and_eligibility",
                    "error_class": type(exc).__name__,
                    "reason": str(exc),
                },
            )

    with ThreadPoolExecutor(max_workers=2) as workers:
        done = {row["task_id"] for row in accepted} | {
            row["task_id"] for row in prior_attempts
        }
        iterator = iter(record for record in pool if record["task_id"] not in done)
        pending = deque()
        for _ in range(4):
            if len(accepted) >= limit:
                break
            record = next(iterator, None)
            if record is not None:
                pending.append(workers.submit(resolve, record))
        while pending and len(accepted) < limit:
            record, row, license_raw, error = pending.popleft().result()
            attempted += 1
            if error:
                unknown.append(error)
            elif row["intake_assessment"]["status"] == "eligible_for_controls":
                materialize(output, record, row, license_raw)
                accepted.append(row)
                atomic(
                    output / "candidates.jsonl",
                    b"".join(
                        (json.dumps(r, sort_keys=True) + "\n").encode()
                        for r in sorted(accepted, key=lambda r: r["task_id"])
                    ),
                )
            else:
                excluded.append(
                    {"task_id": row["task_id"], "decision": row["intake_assessment"]}
                )
            atomic(
                output / "attempts" / (record["task_id"] + ".json"),
                {
                    "task_id": record["task_id"],
                    "error": error,
                    "decision": None if row is None else row["intake_assessment"],
                },
            )
            atomic(
                output / "progress.json",
                {
                    "source_eligible_for_controls": len(accepted),
                    "attempted": attempted,
                    "repositories": dict(Counter(r["source_repo"] for r in accepted)),
                    "elapsed_seconds": time.monotonic() - started,
                    "runtime_qualified": 0,
                },
            )
            record = next(iterator, None)
            if record is not None and len(accepted) < limit:
                pending.append(workers.submit(resolve, record))
        for future in pending:
            future.cancel()
    with licenses.lock:
        licenses.save()
    atomic(
        output / "unknown.jsonl",
        b"".join((json.dumps(r, sort_keys=True) + "\n").encode() for r in unknown),
    )
    atomic(output / "excluded.json", excluded)
    summary = {
        "schema": "scale800-expanded-python-source-v1",
        "source_revision": REVISION,
        "source_parquet_sha256": INPUTS[SHARD],
        "source_pool": len(pool),
        "source_eligible_for_controls": len(accepted),
        "attempted": attempted,
        "repositories": dict(Counter(r["source_repo"] for r in accepted)),
        "license_counts": dict(
            Counter(r["license_evidence"]["source_code"]["spdx"] for r in accepted)
        ),
        "unknown": len(unknown),
        "excluded": len(excluded),
        "prior_pilot25_overlap": sum(r["prior_pilot25_member"] for r in accepted),
        "net_new_relative_to_pilot25": sum(
            not r["prior_pilot25_member"] for r in accepted
        ),
        "native_files": sum(
            len(record["inventory"])
            for record in records
            if record["task_id"] in {r["task_id"] for r in accepted}
        ),
        "runtime_qualified": 0,
        "cloud_launch_ready": 0,
        "qwen_measured": 0,
        "training_admissible": 0,
        "elapsed_seconds": time.monotonic() - started,
        "input_hashes": {name: sha(raw) for name, raw in captured.items()},
        "producer_sha256": sha(Path(__file__).read_bytes()),
        "network": {
            "received_bytes": licenses.received,
            "failed_request_allowance_bytes": licenses.failed,
            "in_flight_reserved_bytes": licenses.pending,
            "limit": LIMIT,
        },
        "limitations": [
            "Source eligibility is not native runtime, verifier, difficulty, image or training approval",
            "Native TaskTrove wrappers require repository worktree preparation and a reviewed patch/file handoff adapter",
            "MONAI/GPU/large-dependency cases retain resource-review flags",
            "License evidence captures upstream grants and publisher declarations, not blanket ownership or semantic nonoverlap",
        ],
    }
    atomic(output / "summary.json", summary)
    inventory = {
        p.relative_to(output).as_posix(): {
            "sha256": sha(p.read_bytes()),
            "bytes": p.stat().st_size,
            "mode": stat.S_IMODE(p.stat().st_mode),
        }
        for p in sorted(output.rglob("*"))
        if p.is_file() and p.name != "file-sha256.json"
    }
    atomic(output / "file-sha256.json", inventory)
    verify_release(output)
    print(
        json.dumps(
            {
                "source_eligible": len(accepted),
                "repositories": len(summary["repositories"]),
                "network_received_bytes": licenses.received,
                "manifest_sha256": sha((output / "file-sha256.json").read_bytes()),
            }
        ),
        flush=True,
    )
    return summary


def verify_release(output):
    inventory = json.loads((output / "file-sha256.json").read_bytes())
    actual = {
        p.relative_to(output).as_posix()
        for p in output.rglob("*")
        if p.is_file() and p.name != "file-sha256.json"
    }
    if actual != set(inventory) or any(p.is_symlink() for p in output.rglob("*")):
        raise ValueError("Frozen output path set differs")
    for name, expected in inventory.items():
        path = output / name
        if (
            sha(path.read_bytes()) != expected["sha256"]
            or path.stat().st_size != expected["bytes"]
            or stat.S_IMODE(path.stat().st_mode) != expected["mode"]
        ):
            raise ValueError("Frozen output bytes/modes differ")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=HERE / "release-v1")
    parser.add_argument("--limit", type=int, default=800)
    parser.add_argument("--source-root", type=Path, default=PILOT)
    args = parser.parse_args()
    build(args.output, args.limit, args.source_root)
