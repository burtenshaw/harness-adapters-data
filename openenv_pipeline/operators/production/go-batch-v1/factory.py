"""Convert the frozen Go intake into bounded native Harbor validation tasks.

Preparation is offline. Validation is a separate explicit command, with immutable
clean per-repository runtime pins and a reviewed concurrency limit.
"""

import argparse
import ast
import base64
import hashlib
import io
import json
import os
import re
import signal
import subprocess
import sys
import tarfile
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path, PurePosixPath
from threading import Event, Lock

HERE = Path(__file__).resolve().parent
PILOT = HERE.parents[1]
SOURCE = PILOT / "pilot50/go"
REPO = HERE.parents[4]
INDEX_SHA = "1dee9663bf086755aa6cff97e178337bc78d0be0f77e6273b9ab5cc213aa84f6"
MANIFEST_SHA = "3055c869316f42376300a792a4c910752f659a696b55265a316e75c1db21d68f"
REQUIRED = {
    "static.manifest",
    "runtime.startup",
    "runtime.reward_well_formed",
    "runtime.episode_determinism",
    "semantic.oracle_max",
    "semantic.floor_gap",
    "semantic.canary_floor",
}
IMAGE = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}\Z")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def safe(name):
    p = PurePosixPath(name)
    if (
        not p.parts
        or p.is_absolute()
        or p.as_posix() != name
        or ".." in p.parts
        or ".git" in p.parts
        or "\\" in name
        or any(ord(c) < 32 for c in name)
    ):
        raise ValueError("Unsafe captured path")
    return p


def capture(root=SOURCE):
    raw = (root / "SHA256SUMS").read_bytes()
    if sha(raw) != MANIFEST_SHA:
        raise ValueError("Frozen Go manifest changed")
    hashes = {}
    for line in raw.decode().splitlines():
        digest, name = line.split("  ", 1)
        safe(name)
        if name in hashes or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("Invalid frozen checksum index")
        hashes[name] = digest
    files, modes = {}, {}
    for name, digest in hashes.items():
        path = root / name
        if path.is_symlink() or any(p.is_symlink() for p in path.parents):
            raise ValueError("Captured links unsupported")
        content = path.read_bytes()
        if sha(content) != digest:
            raise ValueError("Captured Go bytes differ from acquired inventory")
        files[name], modes[name] = content, path.stat().st_mode & 0o7777
    expected_modes = json.loads(files["artifact-modes.json"])
    if any(
        name in expected_modes and mode != int(expected_modes[name], 8)
        for name, mode in modes.items()
    ):
        raise ValueError("Captured source modes changed")
    if sha(files["candidates.jsonl"]) != INDEX_SHA:
        raise ValueError("Frozen candidate identity changed")
    return files, hashes


def candidates(files):
    rows = [json.loads(line) for line in files["candidates.jsonl"].splitlines()]
    ids = [row["task_id"] for row in rows]
    if len(rows) != 25 or len(set(ids)) != len(ids):
        raise ValueError("Expected 25 distinct frozen identities")
    return [row for row in rows if row["upstream_repo"] != "Masterminds/squirrel"]


def healthy(files, prefix, inventory):
    result = {}
    with tarfile.open(
        fileobj=io.BytesIO(files[prefix + "/healthy.tar.gz"]), mode="r:gz"
    ) as archive:
        for member in archive.getmembers():
            if member.isdir():
                continue
            if not member.isfile() or member.size > 1024 * 1024:
                raise ValueError("Unsupported healthy source member")
            parts = safe(member.name).parts
            name = str(PurePosixPath(*parts[1:]))
            if name in result or name not in inventory:
                raise ValueError("Unbound healthy source member")
            raw = archive.extractfile(member).read()
            expected = inventory[name]
            blob = hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest()
            mode = 0o755 if expected["mode"] == "100755" else 0o644
            if (
                sha(raw) != expected["sha256"]
                or blob != expected["git_blob_sha1"]
                or len(raw) != expected["size"]
                or member.mode & 0o111 != mode & 0o111
                or member.mode & 0o7000
            ):
                raise ValueError("Healthy source Git/content/mode mismatch")
            result[name] = (raw, mode)
    if set(result) != set(inventory):
        raise ValueError("Healthy archive membership changed")
    return result


def private(name):
    return name.endswith("_test.go") or any(
        part in {"testdata", "tests", "test", "fixtures"}
        for part in PurePosixPath(name).parts
    )


def expected_cases(tree, proof):
    module = re.search(rb"(?m)^module\s+(\S+)", tree["go.mod"][0])
    if not module:
        raise ValueError("Missing root Go module")
    module = module[1].decode()
    declarations = {}
    for name, (raw, _) in tree.items():
        if not name.endswith("_test.go"):
            continue
        parent = PurePosixPath(name).parent
        if any(
            str(p / "go.mod") in tree
            for p in [parent, *parent.parents]
            if str(p) != "."
        ):
            continue  # go test ./... excludes nested modules.
        package = module + ("/" + str(parent) if str(parent) != "." else "")
        for match in re.finditer(rb"(?m)^\s*func\s+(Test\w+)\s*\(", raw):
            declarations.setdefault(match[1].decode(), set()).add(package)
    result = []
    for group in ("FAIL_TO_PASS", "PASS_TO_PASS"):
        for name in proof[group]:
            matches = declarations.get(name.split("/", 1)[0], set())
            if len(matches) != 1:
                raise ValueError("Ambiguous/missing package-qualified test identity")
            result.append(
                {"package": next(iter(matches)), "test": name, "group": group}
            )
    if not proof["FAIL_TO_PASS"] or len(
        {(r["package"], r["test"]) for r in result}
    ) != len(result):
        raise ValueError("Missing or duplicate expected test identity")
    return result


def command(files, proof):
    parsed = ast.parse(files["inputs/upstream/swesmith/profiles/golang.py"])
    classes = {
        node.name: node for node in parsed.body if isinstance(node, ast.ClassDef)
    }
    current = classes[proof["official_profile"]["profile_class"]]
    if not any(
        isinstance(base, ast.Name) and base.id == "GoProfile" for base in current.bases
    ):
        raise ValueError("Unsupported official profile inheritance")
    for cls in (current, classes["GoProfile"]):
        for node in cls.body:
            if (
                isinstance(node, ast.AnnAssign)
                and isinstance(node.target, ast.Name)
                and node.target.id == "test_cmd"
            ):
                value = ast.literal_eval(node.value)
                if value != "go test -v ./...":
                    raise ValueError("Official custom test command unsupported")
                return ["/usr/local/go/bin/go", "test", "-json", "-count=1", "./..."]
    raise ValueError("Official test command unavailable")


def script(values):
    payload = {
        name: {"data": base64.b64encode(raw).decode(), "mode": mode}
        for name, (raw, mode) in values.items()
    }
    code = (
        "import base64,json\nfrom pathlib import Path\nfiles=json.loads("
        + repr(json.dumps(payload))
        + ")\nfor name,item in files.items():\n p=Path('/testbed')/name\n p.parent.mkdir(parents=True,exist_ok=True)\n p.write_bytes(base64.b64decode(item['data']))\n p.chmod(item['mode'])\n"
    )
    return (
        b"#!/bin/bash\nset -eu\n/usr/local/bin/python -I - <<'OPENENV_REFERENCE'\n"
        + code.encode()
        + b"OPENENV_REFERENCE\n"
    )


def inventory(files):
    return {
        name: {"sha256": sha(raw), "mode": oct(mode), "size": len(raw)}
        for name, (raw, mode) in sorted(files.items())
    }


def partial_candidate(original, proof, healthy_tree, learner, captured):
    """Retain exactly the first mutation hunk; repair every other changed hunk."""
    parsed = ast.parse(captured["materialize.py"])
    functions = [
        node
        for node in parsed.body
        if isinstance(node, ast.FunctionDef)
        and node.name in {"patch_sections", "apply_hunks"}
    ]
    namespace = {"re": re, "source_path": safe}
    exec(
        compile(
            ast.Module(body=functions, type_ignores=[]),
            "captured_intake_patch_functions",
            "exec",
        ),
        namespace,
    )
    sections = namespace["patch_sections"](
        original["patch"], {"files": [{"new": name} for name in proof["source_paths"]]}
    )
    hunk_count = sum(line.startswith("@@ ") for _, lines in sections for line in lines)
    if hunk_count < 2:
        return None, {
            "original_patch_hunks": hunk_count,
            "extra_semantic_repair_coverage": False,
            "basis": "single-hunk original-bug canary is NOP-equivalent; other canaries test abuse classes only",
        }
    name, lines = sections[0]
    stop = next(
        (index for index, line in enumerate(lines[1:], 1) if line.startswith("@@ ")),
        len(lines),
    )
    first = lines[:stop]
    values = {path: healthy_tree[path] for path in proof["source_paths"]}
    values[name] = (
        namespace["apply_hunks"](healthy_tree[name][0], first),
        healthy_tree[name][1],
    )
    if all(values[path][0] == learner[path][0] for path in values) or all(
        values[path][0] == healthy_tree[path][0] for path in values
    ):
        raise ValueError(
            "Partial hunk candidate must differ from both full repair and original bug"
        )
    return values, {
        "original_patch_hunks": hunk_count,
        "original_patch_sha256": sha(original["patch"].encode()),
        "retained_mutation_file": name,
        "retained_mutation_hunk_sha256": sha("".join(first).encode()),
        "candidate_file_inventory": inventory(values),
        "expected_wrongness": "unproven until independent semantic review",
        "acceptance_disposition": "needs_semantic_review; may be a legitimate alternative; do not cherry-pick another canary from measured rewards",
    }


def construct(row, captured, hashes, runtime=None, *, grader_raw=None):
    prefix = str(PurePosixPath(row["learner_path"]).parent)
    proof = json.loads(captured[prefix + "/source-proof.json"])
    original = json.loads(captured[prefix + "/row.json"])
    inventories = json.loads(captured[prefix + "/file-inventories.json"])
    if (
        proof["task_id"] != row["task_id"]
        or original["instance_id"] != row["task_id"]
        or proof["all_git_blobs_modes_verified"] is not True
        or proof["mutation_matches_dataset_and_git_blobs"] is not True
    ):
        raise ValueError("Source identity/proof differs")
    healthy_tree = healthy(captured, prefix, inventories["healthy"])
    learner = {}
    for name, item in inventories["learner"].items():
        raw = captured[prefix + "/learner/" + name]
        mode = 0o755 if item["mode"] == "100755" else 0o644
        if (
            sha(raw) != item["sha256"]
            or hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest()
            != item["git_blob_sha1"]
        ):
            raise ValueError("Learner differs from frozen Git inventory")
        learner[name] = raw, mode
    if any(private(name) for name in proof["source_paths"]):
        raise ValueError("Reference changes a private test surface")
    public = {name: value for name, value in learner.items() if not private(name)}
    frozen = {name: value for name, value in healthy_tree.items() if private(name)}
    if not frozen:
        raise ValueError("No private frozen tests")
    expected = expected_cases(healthy_tree, proof)
    files = {"environment/source/" + name: value for name, value in public.items()}
    files.update({"tests/frozen/" + name: value for name, value in frozen.items()})
    files["tests/grade.py"] = (
        grader_raw if grader_raw is not None else (HERE / "grader.py").read_bytes(),
        0o644,
    )
    files["tests/manifest.json"] = (
        encode(
            {
                "expected": expected,
                "command": command(captured, proof),
                "frozen_files": {
                    name: {"sha256": sha(raw), "mode": mode}
                    for name, (raw, mode) in frozen.items()
                },
            }
        ),
        0o644,
    )
    files["tests/test.sh"] = (
        b"#!/bin/bash\nset -eu\nexec /usr/local/bin/python -I /tests/grade.py\n",
        0o755,
    )
    files["instruction.md"] = (
        captured[prefix + "/instruction.md"]
        + b"\nWork in /testbed. This is a broken source-only export without Git history or tests. Grading restores frozen private tests independently. Repair existing implementation files; new arbitrary files are outside the current transfer contract. Offline Go dependencies are preinstalled.\n",
        0o644,
    )
    files["solution/solve.sh"] = (
        script({name: healthy_tree[name] for name in proof["source_paths"]}),
        0o755,
    )
    files["validation/canaries/original-bug.sh"] = (b"#!/bin/bash\nset -eu\n:\n", 0o755)
    files["validation/canaries/delete-tests.sh"] = (
        b"#!/bin/bash\nset -eu\nfind /testbed -name '*_test.go' -type f -delete\nprintf 'PASS\\nok forged-package 0.001s\\n'\n",
        0o755,
    )
    files["validation/canaries/stale-reward.sh"] = (
        b"#!/bin/bash\nset -eu\nmkdir -p /logs/verifier\nprintf '1\\n' > /logs/verifier/reward.txt\n",
        0o755,
    )
    partial, partial_metadata = partial_candidate(
        original, proof, healthy_tree, learner, captured
    )
    if partial is not None:
        del files["validation/canaries/delete-tests.sh"]
        files["validation/canaries/partial-repair.sh"] = script(partial), 0o755
    files["task.toml"] = (
        b'version = "1.0"\n[agent]\ntimeout_sec = 300.0\n[verifier]\ntimeout_sec = 300.0\nenvironment_mode = "shared"\n[environment]\ncpus = 1\nmemory_mb = 2048\nstorage_mb = 4096\n',
        0o644,
    )
    status = "blocked_missing_reviewed_runtime"
    if runtime is not None:
        if (
            not IMAGE.fullmatch(runtime.get("image", ""))
            or runtime.get("clean_runtime_qualified") is not True
            or not re.fullmatch(r"[0-9a-f]{64}", runtime.get("receipt_sha256", ""))
        ):
            raise ValueError("Immutable reviewed clean runtime receipt required")
        files["environment/Dockerfile"] = (
            (
                "FROM --platform=linux/amd64 "
                + runtime["image"]
                + "\nWORKDIR /testbed\nCOPY source/ /testbed/\n"
            ).encode(),
            0o644,
        )
        status = "prepared_for_native_validation"
    provenance = {
        "schema": "scale800-go-native-transform-v1",
        "source_record": row,
        "source_proof_sha256": hashes[prefix + "/source-proof.json"],
        "source_row_sha256": hashes[prefix + "/row.json"],
        "source_manifest_sha256": MANIFEST_SHA,
        "source_index_sha256": INDEX_SHA,
        "source_test_command": "go test -v ./...",
        "execution_command": command(captured, proof),
        "public_files": inventory({name: value for name, value in public.items()}),
        "private_frozen_files": inventory(frozen),
        "reference_kind": "provided_healthy_parent_changed_implementation",
        "generated_reference": False,
        "negative_classes": {
            "original-bug": "task-specific unchanged semantic bug",
            "delete-tests": "same wrong implementation with verifier deletion/stdout spoof attempt",
            "stale-reward": "same wrong implementation with stale reward spoof attempt",
        },
        "partial_hunk_control": partial_metadata,
        "runtime": runtime,
        "transfer_allowlist": ["/testbed/" + name for name in sorted(public)],
        "new_arbitrary_files_supported": False,
        "target_model_calibrated": False,
        "cloud_launch_ready": False,
        "training_admissible": False,
        "full_rfc008": False,
    }
    if partial is not None:
        del provenance["negative_classes"]["delete-tests"]
        provenance["negative_classes"]["partial-repair"] = (
            "strict partial repair candidate with independently unproven wrongness"
        )
    files["provenance.json"] = (encode(provenance), 0o644)
    return (
        files,
        {
            "task_id": row["task_id"],
            "upstream_repo": row["upstream_repo"],
            "status": status,
            "expected_cases": len(expected),
            "public_files": len(public),
            "provided_reference": True,
            "generated_reference": False,
            "runtime_qualified": False,
            "target_model_calibrated": False,
            "training_admissible": False,
        },
        row["upstream_repo"],
        original["image_name"],
    )


def write_tree(root, files):
    root.mkdir(parents=True, exist_ok=False)
    for name, (raw, mode) in files.items():
        path = root / safe(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        path.chmod(mode)


def atomic(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=path.parent)
    with os.fdopen(fd, "wb") as stream:
        stream.write(encode(value))
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    descriptor = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def prepare(output, runtime_lock=None):
    captured, hashes = capture()
    rows = candidates(captured)
    grader_raw = (HERE / "grader.py").read_bytes()
    factory_raw = Path(__file__).read_bytes()
    runtime_bytes = runtime_lock.read_bytes() if runtime_lock else b"{}"
    runtimes = json.loads(runtime_bytes)
    for runtime in runtimes.values():
        name = runtime["receipt_path"]
        receipt_path = runtime_lock.parent / safe(name)
        if receipt_path.is_symlink() or any(
            p.is_symlink() for p in receipt_path.parents
        ):
            raise ValueError("Runtime receipt links unsupported")
        raw = receipt_path.read_bytes()
        receipt = json.loads(raw)
        if (
            sha(raw) != runtime["receipt_sha256"]
            or receipt.get("image") != runtime["image"]
            or any(
                receipt.get(key) is not True
                for key in (
                    "clean_runtime_qualified",
                    "git_history_absent",
                    "task_source_absent",
                    "private_tests_absent",
                )
            )
            or receipt.get("os") != "linux"
            or receipt.get("architecture") != "amd64"
        ):
            raise ValueError(
                "Runtime receipt identity/privacy qualification incomplete"
            )
    output.mkdir(parents=True, exist_ok=False)
    decisions, needed = [], {}
    sys.path[:0] = [str(REPO), str(REPO / "src"), str(REPO / "envs")]
    from openenv.validation.runner import source_digest

    for row in rows:
        task_id = sha(row["task_id"].encode())[:24]
        item_root = output / task_id
        try:
            files, item, repo, source_image = construct(
                row,
                captured,
                hashes,
                runtimes.get(row["upstream_repo"]),
                grader_raw=grader_raw,
            )
            task = item_root / "task"
            original = {
                name: value
                for name, value in files.items()
                if not name.startswith("validation/")
            }
            write_tree(item_root / "converted-original", original)
            original_digest = source_digest(item_root / "converted-original")
            contract = {
                "profile": "harbor-semantic-v1",
                "reward_key": "reward",
                "reward": {"range": [0, 1], "oracle_tolerance": 0, "floor_margin": 0.1},
                "resources": {
                    "cpu": 1,
                    "memory_mb": 2048,
                    "disk_mb": 4096,
                    "episode_timeout_s": 600,
                },
                "types": {"tags": ["swe", "go", "repository-repair"]},
                "requires_credentials": False,
                "canaries": "validation/canaries",
                "original_source_digest": original_digest,
            }
            files["validation/openenv.json"] = (encode(contract), 0o644)
            write_tree(task, files)
            item.update(
                task_path=task_id + "/task",
                original_source_digest=original_digest,
                task_effective_digest=source_digest(task),
                task_file_inventory=inventory(files),
            )
            atomic(item_root / "item.json", item)
            item = {**item, "item_sha256": sha(encode(item))}
            needed[repo] = {
                "source_image_unresolved": source_image,
                "clean_runtime_qualified": False,
                "image": None,
                "requirements": "amd64 clean Python3.12+Go+/go/pkg/mod cache; no source/Git/gold/private tests in any final layer; image digest and separate receipt required",
            }
        except (ValueError, KeyError, UnicodeError, tarfile.TarError) as exc:
            item = {
                "task_id": row["task_id"],
                "status": "blocked_source_adapter",
                "error_type": type(exc).__name__,
                "reason": str(exc),
                "runtime_qualified": False,
            }
        decisions.append(item)
    manifest = {
        "schema": "scale800-go-native-batch-v1",
        "source_manifest_sha256": MANIFEST_SHA,
        "source_index_sha256": INDEX_SHA,
        "runtime_lock_sha256": sha(runtime_bytes),
        "factory_sha256": sha(factory_raw),
        "grader_sha256": sha(grader_raw),
        "excluded_existing_squirrel_families": 2,
        "items": decisions,
        "required_checks": sorted(REQUIRED),
        "all_broader_flags_false": True,
    }
    atomic(output / "manifest.json", manifest)
    atomic(output / "runtimes-needed.json", needed)
    return manifest


def require_coverage(report):
    rows = report["results"]
    checks = {row["check_id"]: row["status"] for row in rows}
    if (
        len(checks) != len(rows)
        or any(status in {"fail", "error"} for status in checks.values())
        or any(checks.get(name) != "pass" for name in REQUIRED)
    ):
        raise ValueError("Required native coverage failed")


def rejection_status(report, provenance):
    canary = next(
        (
            row
            for row in report["results"]
            if row["check_id"] == "semantic.canary_floor"
        ),
        {},
    )
    measured = canary.get("measured", {})
    if (
        "partial-repair" in provenance["negative_classes"]
        and canary.get("status") == "fail"
        and measured.get("canary_rewards", {}).get(
            "validation/canaries/partial-repair.sh", 0
        )
        > measured.get("measured_floor", 0)
    ):
        return "canary_accepted_needs_semantic_review"
    return "native_rejected"


def validate_one(item_path, expected_item_sha256):
    sys.path[:0] = [str(REPO), str(REPO / "src"), str(REPO / "envs")]
    from examples.hub_validation_pipeline import pipeline
    from openenv.validation.runner import source_digest

    item_bytes = item_path.read_bytes()
    if sha(item_bytes) != expected_item_sha256:
        raise ValueError("Reviewed prepared item changed")
    item = json.loads(item_bytes)
    task, run = item_path.parent / "task", item_path.parent / "validation-run"
    if item["status"] != "prepared_for_native_validation":
        raise ValueError("Task has no qualified immutable runtime")
    if source_digest(task) != item["task_effective_digest"]:
        raise ValueError("Prepared task source drift")
    run.mkdir(exist_ok=False)
    module_paths = (
        list((REPO / "src/openenv/validation").rglob("*.py"))
        + list((REPO / "src/openenv/harbor").rglob("*.py"))
        + [REPO / "examples/hub_validation_pipeline/pipeline.py"]
    )
    before = {
        str(path.relative_to(REPO)): sha(path.read_bytes())
        for path in sorted(module_paths)
    }
    atomic(run / "validator-modules-before.json", before)
    atomic(
        run / "state.json",
        {
            "status": "execution_started_unknown_until_terminal",
            "item_sha256": sha(item_bytes),
        },
    )
    code, report = pipeline.validate_task(
        task, run / "report.json", pipeline.PILOT, 2400
    )
    after = {
        str(path.relative_to(REPO)): sha(path.read_bytes())
        for path in sorted(module_paths)
    }
    atomic(run / "validator-modules-after.json", after)
    if before != after:
        atomic(
            run / "state.json",
            {
                "status": "blocked_validator_source_drift",
                "item_sha256": sha(item_bytes),
            },
        )
        raise ValueError("Validator code changed during native execution")
    try:
        require_coverage(report)
        envelope = pipeline.admission(
            report,
            code,
            task,
            run / "report.artifacts",
            pipeline.PILOT,
            item["original_source_digest"],
        )
        (run / "admission.json").write_text(pipeline.dumps(envelope) + "\n")
        status = "native_pilot_admitted"
    except ValueError:
        provenance = json.loads((task / "provenance.json").read_bytes())
        status = rejection_status(report, provenance)
    atomic(
        run / "state.json",
        {
            "status": status,
            "item_sha256": sha(item_bytes),
            "report_sha256": sha((run / "report.json").read_bytes()),
            "target_model_calibrated": False,
            "training_admissible": False,
            "full_rfc008": False,
        },
    )
    return status


def run_batch(manifest_path, concurrency, expected_manifest_sha256):
    if concurrency not in {1, 2, 3, 4}:
        raise ValueError("Use one to four reviewed local worker slots")
    manifest_path = manifest_path.resolve()
    cleanup_marker = manifest_path.parent / "batch-cleanup-required.json"
    if cleanup_marker.exists():
        raise ValueError("Owned cleanup must be reconciled before resuming this batch")
    raw = manifest_path.read_bytes()
    if sha(raw) != expected_manifest_sha256:
        raise ValueError("Reviewed native batch manifest changed")
    manifest = json.loads(raw)
    if manifest.get("factory_sha256") != sha(
        Path(__file__).read_bytes()
    ) or manifest.get("grader_sha256") != sha((HERE / "grader.py").read_bytes()):
        raise ValueError("Reviewed factory or grader source changed")
    pending = []
    for row in manifest["items"]:
        if row["status"] != "prepared_for_native_validation":
            continue
        item = manifest_path.parent / safe(row["task_path"]).parent / "item.json"
        state_path = item.parent / "validation-run/state.json"
        if state_path.exists():
            if json.loads(state_path.read_bytes()).get("status") not in {
                "native_pilot_admitted",
                "native_rejected",
                "canary_accepted_needs_semantic_review",
            }:
                raise ValueError("Owned cleanup is uncertain for an existing execution")
            continue  # Never automatically redispatch terminal effects.
        if sha(item.read_bytes()) != row["item_sha256"]:
            raise ValueError("Prepared item differs from reviewed batch manifest")
        pending.append((item.resolve(), row["item_sha256"]))
    environment = {
        key: value
        for key, value in os.environ.items()
        if not any(
            marker in key.upper()
            for marker in ("TOKEN", "SECRET", "API_KEY", "CREDENTIAL")
        )
    }
    environment["PYTHONPATH"] = (
        str(REPO) + ":" + str(REPO / "src") + ":" + str(REPO / "envs")
    )
    cleanup_uncertain, dispatch_lock = Event(), Lock()

    def execute(entry):
        path, expected_item_sha256 = entry
        with dispatch_lock:
            if cleanup_uncertain.is_set():
                return {
                    "item": str(path.relative_to(manifest_path.parent)),
                    "status": "not_dispatched_cleanup_uncertain",
                }
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-B",
                    str(HERE / "factory.py"),
                    "validate-one",
                    "--item",
                    str(path),
                    "--expected-item-sha256",
                    expected_item_sha256,
                ],
                cwd=REPO,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        timed_out = False
        try:
            output, _ = process.communicate(timeout=3000)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                with dispatch_lock:
                    cleanup_uncertain.set()
                    atomic(
                        cleanup_marker,
                        {
                            "item": str(path.relative_to(manifest_path.parent)),
                            "owned_cleanup_reconciliation_required": True,
                        },
                    )
            finally:
                try:
                    os.killpg(process.pid, signal.SIGINT)
                except ProcessLookupError:
                    pass
                try:
                    output, _ = process.communicate(timeout=120)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    output, _ = process.communicate()
        value = {
            "item": str(path.relative_to(manifest_path.parent)),
            "process_exit_code": process.returncode,
            "output_sha256": sha(output),
            "supervisor_timed_out": timed_out,
            "owned_cleanup_reconciliation_required": timed_out,
        }
        atomic(path.parent / "process-receipt.json", value)
        return value

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        results = list(pool.map(execute, pending))
    atomic(
        manifest_path.parent / "batch-receipt.json",
        {
            "manifest_sha256": sha(raw),
            "concurrency": concurrency,
            "halted_for_cleanup": cleanup_uncertain.is_set(),
            "results": results,
        },
    )
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    prep = sub.add_parser("prepare")
    prep.add_argument("--output", type=Path, required=True)
    prep.add_argument("--runtime-lock", type=Path)
    one = sub.add_parser("validate-one")
    one.add_argument("--item", type=Path, required=True)
    one.add_argument("--expected-item-sha256", required=True)
    run = sub.add_parser("run")
    run.add_argument("--manifest", type=Path, required=True)
    run.add_argument("--concurrency", type=int, default=1)
    run.add_argument("--expected-manifest-sha256", required=True)
    run.add_argument("--execute", action="store_true", required=True)
    args = parser.parse_args()
    if args.command == "prepare":
        value = prepare(args.output, args.runtime_lock)
        print(
            json.dumps(
                {
                    "candidates": len(value["items"]),
                    "prepared": sum(
                        row["status"] == "prepared_for_native_validation"
                        for row in value["items"]
                    ),
                }
            )
        )
    elif args.command == "validate-one":
        print(validate_one(args.item, args.expected_item_sha256))
    else:
        print(
            json.dumps(
                {
                    "executed": len(
                        run_batch(
                            args.manifest,
                            args.concurrency,
                            args.expected_manifest_sha256,
                        )
                    )
                }
            )
        )


if __name__ == "__main__":
    main()
