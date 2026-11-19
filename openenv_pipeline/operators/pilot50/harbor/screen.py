"""Materialize captured native bundles and apply the frozen metadata intake gate."""

import argparse
import base64
import gzip
import hashlib
import io
import json
import re
import stat
import tarfile
import types
from collections import Counter
from pathlib import Path, PurePosixPath

HERE = Path(__file__).resolve().parent
PILOT = HERE.parents[1]
SOURCE = PILOT / "harbor"
ELIGIBILITY = PILOT / "eligibility"
SOURCE_MANIFEST_SHA = "a8445d66949383c75807c2ce26d06f917db1941a7889a0fca212307531af0e5b"
POLICY_SHA = "4d9da53bf49d807086bf98c10c4761e33a295e0cc1fb4e5a53bd29ad30c71645"
EXISTING_SHA = "4cf47bfcf624ef7e02250049f3ac71a946a6e9492590b07d2ebbc73c621f91ce"
ASSESSOR_SHA = "ed3b044361e5e5fdee2595f1d72372c3f877d4f278a21f8d7ff798e338f47f30"
REVISION = "946884702046be1a7dcea2638186ad6b0d2ea103"
SHARD_SHA = "b0905406ee4d0a97154949a991a00bf91cb7e6a0a1224eb304c04689ff8f6aa0"
ANTI_TRAINING = (
    b"terminal-bench-canary",
    b"benchmark data should never appear in training",
    b"benchmark data should never",
    b"do not use this task for training",
    b"not to be used for training",
    b"do not train on this",
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def checked(data, expected, label):
    if digest(data) != expected:
        raise ValueError(f"Captured evidence hash mismatch: {label}")
    return data


def load_module(name, data, path):
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(data, str(path), "exec"), module.__dict__)
    return module


def unpack(archive, expected, native_unpack):
    checked(archive, expected["archive_sha256"], "native archive")
    files = native_unpack(archive)
    # The trusted original helper rejects links/unsafe paths and bounds expansion.
    # Also reject permission bits that its ordinary-mode inventory would mask.
    with gzip.GzipFile(fileobj=io.BytesIO(archive)) as stream:
        expanded = stream.read(8 * 1024 * 1024 + 1)
    if len(expanded) > 8 * 1024 * 1024:
        raise ValueError("Native archive expansion exceeds cap")
    with tarfile.open(fileobj=io.BytesIO(expanded), mode="r:") as stream:
        if any(member.mode & ~0o777 for member in stream):
            raise ValueError("Unsupported special permission bits")
    inventory = {
        name: {"sha256": digest(data), "bytes": len(data), "mode": mode}
        for name, (data, mode) in sorted(files.items())
    }
    if inventory != expected["files"]:
        raise ValueError("Captured native file/mode inventory mismatch")
    if not {
        "task.toml",
        "instruction.md",
        "metadata.json",
        "solution/solve.sh",
        "tests/test_patch.diff",
    }.issubset(files):
        raise ValueError("Incomplete native task bundle")
    for name in files:
        if any(
            str(parent) in files
            for parent in PurePosixPath(name).parents
            if str(parent) != "."
        ):
            raise ValueError("Native file overlaps a parent path")
    return files, inventory


def code_license(data, record, metadata):
    checked(data, record["sha256"], "upstream license")
    if (
        record["repo"] != metadata["repo"]
        or record["commit"] != metadata["base_commit"]
    ):
        raise ValueError("License source identity differs from native metadata")
    prefix = f"https://raw.githubusercontent.com/{metadata['repo']}/{metadata['base_commit']}/"
    if not record["url"].startswith(prefix):
        raise ValueError("License URL is not the exact native source pin")
    text = data.decode("utf-8").casefold()
    spdx = record["spdx_from_text"]
    if spdx == "MIT":
        if (
            "permission is hereby granted" not in text
            or "without restriction" not in text
        ):
            raise ValueError("Captured license does not contain the declared MIT grant")
    elif spdx == "Apache-2.0":
        if (
            "apache license" not in text
            or "version 2.0" not in text
            or "terms and conditions" not in text
        ):
            raise ValueError(
                "Captured license does not contain the declared Apache grant"
            )
    else:
        raise ValueError("License needs a separate review")
    return {
        "spdx": spdx,
        "sha256": digest(data),
        "url": record["url"],
        "reviewed": True,
        "training_allowed": True,
        "scope": "captured upstream software permission; all original notices retained",
    }


def repair_patch(files):
    script = files["solution/solve.sh"][0]
    marker = b"cat <<'SOLUTION_PATCH_EOF' > \"$patch_file2\"\n"
    if script.count(marker) != 1:
        raise ValueError("Native repair patch framing needs review")
    tail = script.split(marker, 1)[1]
    if tail.count(b"\nSOLUTION_PATCH_EOF\n") != 1:
        raise ValueError("Native repair patch terminator needs review")
    patch = tail.split(b"\nSOLUTION_PATCH_EOF\n", 1)[0] + b"\n"
    paths = []
    for line in patch.decode().splitlines():
        if line.startswith("diff --git "):
            match = re.fullmatch(r"diff --git a/(\S+) b/(\S+)", line)
            if match is None:
                raise ValueError("Native patch path syntax needs review")
            for name in match.groups():
                path = PurePosixPath(name)
                if (
                    path.is_absolute()
                    or ".." in path.parts
                    or "\\" in name
                    or str(path) != name
                ):
                    raise ValueError("Unsafe native repair patch path")
            paths.append({"old": match[1], "new": match[2]})
    if not paths or "@@" not in patch.decode():
        raise ValueError("Missing native repair patch")
    return patch, paths


def build(output):
    if output.exists():
        raise FileExistsError("Use a fresh output directory")
    consumed = {}

    def read(path, expected):
        data = checked(path.read_bytes(), expected, path.name)
        consumed[str(path)] = digest(data)
        return data

    manifest = json.loads(read(SOURCE / "intake-manifest.json", SOURCE_MANIFEST_SHA))

    def source(relative):
        record = manifest["files"][relative]
        data = read(SOURCE / relative, record["sha256"])
        if len(data) != record["bytes"]:
            raise ValueError("Captured source byte length mismatch")
        return data

    policy = json.loads(read(ELIGIBILITY / "policy.json", POLICY_SHA))
    existing = json.loads(read(ELIGIBILITY / "existing-identities.json", EXISTING_SHA))
    assessor = load_module(
        "frozen_eligibility",
        read(ELIGIBILITY / "eligibility.py", ASSESSOR_SHA),
        ELIGIBILITY / "eligibility.py",
    )
    extractor = load_module(
        "frozen_native_extractor",
        source("materialize_canonical.py"),
        SOURCE / "materialize_canonical.py",
    )
    card = source("TaskTrove.README.md")
    front = card.decode().split("---", 2)[1]
    if "license: apache-2.0" not in front or "- split: train" not in front:
        raise ValueError("Pinned publisher license/train declaration differs")
    source_info = json.loads(source("canonical/source.json"))
    if source_info["revision"] != REVISION or source_info["sha256"] != SHARD_SHA:
        raise ValueError("Canonical source pin differs")
    source("canonical/swegym-v5.tasks.parquet")
    selected = json.loads(source("canonical/selected25.json"))["tasks"]
    rows = json.loads(source("canonical/selected25.raw.json"))
    licenses = {
        row["task_id"]: row
        for row in json.loads(source("canonical/licenses-by-commit.json"))
    }
    if len(rows) != 25 or len(selected) != 25 or len(licenses) != 25:
        raise ValueError("Expected exactly 25 source rows")
    by_id = {row["task_id"]: row for row in selected}
    if len(by_id) != 25 or {row["path"] for row in rows} != set(by_id):
        raise ValueError("Selected task identity set differs")
    prepared = []
    for row in rows:
        task_id = row["path"]
        if not re.fullmatch(r"swegym-[0-9]{4}", task_id):
            raise ValueError("Unexpected native task identifier")
        original = by_id[task_id]
        archive = base64.b64decode(row["archive_base64"], validate=True)
        files, inventory = unpack(archive, original, extractor.unpack)
        metadata = json.loads(files["metadata.json"][0])
        if metadata != original["metadata"] or metadata["split"] != "train":
            raise ValueError("Captured task metadata differs")
        repo, commit = metadata["repo"], metadata["base_commit"]
        instance = metadata["instance_id"]
        prefix = repo.replace("/", "__") + "-"
        if not instance.startswith(prefix) or not instance[len(prefix) :].isdigit():
            raise ValueError("Upstream instance/PR identity needs review")
        if (
            repo.encode() not in files["instruction.md"][0]
            or commit.encode() not in files["instruction.md"][0]
        ):
            raise ValueError("Instruction/source identity differs")
        if (
            f"https://github.com/{repo}.git".encode()
            not in files["solution/solve.sh"][0]
        ):
            raise ValueError("Oracle/source repository identity differs")
        licence_record = licenses[task_id]
        licence_path = Path(licence_record["local_path"])
        relative = licence_path.resolve().relative_to(SOURCE.resolve()).as_posix()
        licence = source(relative)
        license_review = code_license(licence, licence_record, metadata)
        patch, patch_paths = repair_patch(files)
        canary_files = sorted(
            name
            for name, (data, _) in files.items()
            if any(marker in data.lower() for marker in ANTI_TRAINING)
        )
        candidate = {
            "candidate_id": f"TaskTrove:{REVISION}:{task_id}",
            "task_id": task_id,
            "source_task_id": instance,
            "task_path": f"tasks/{task_id}",
            "provenance_path": f"provenance/{task_id}.json",
            "inventory_path": f"inventories/{task_id}.json",
            "source_kind": "pr",
            "source_dataset": "open-thoughts/TaskTrove",
            "original_source_dataset": metadata["source"],
            "source_repo": repo,
            "upstream_repo": repo,
            "repository_lineage": [repo],
            "source_commit": commit,
            "source_pr_url": f"https://github.com/{repo}/pull/{instance[len(prefix) :]}",
            "source_revision": REVISION,
            "source_split": metadata["split"],
            "task_sha256": digest(archive),
            "task_sha256_kind": "original-native-tar-gzip",
            "native_inventory_sha256": digest(encoded(inventory)),
            "patch_sha256": digest(patch),
            "instruction_sha256": digest(files["instruction.md"][0]),
            "upstream_identity_reviewed": True,
            "anti_training_reviewed": True,
            "anti_training_canary": bool(canary_files),
            "anti_training_canary_files": canary_files,
            "evaluation_only": False,
            "license_evidence": {
                "source_code": license_review,
                "task_bundle": {
                    "spdx": "Apache-2.0",
                    "sha256": digest(card),
                    "url": f"https://huggingface.co/datasets/open-thoughts/TaskTrove/blob/{REVISION}/README.md",
                    "reviewed": True,
                    "training_allowed": True,
                    "scope": "publisher-declared wrapper license and train split; upstream notices remain applicable",
                },
            },
            "fail_to_pass": metadata["fail_to_pass"],
            "pass_to_pass": metadata["pass_to_pass"],
            "repair_patch_paths": patch_paths,
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
        prepared.append((candidate, files, inventory, licence, patch, original))
    candidates = [item[0] for item in prepared]
    decisions = list(assessor.assess_many(candidates, policy, existing))
    output.mkdir(parents=True)
    for (candidate, files, inventory, licence, patch, original), decision in zip(
        prepared, decisions
    ):
        candidate["intake_assessment"] = decision
        for name, (data, mode) in files.items():
            path = output / candidate["task_path"] / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(mode)
        for relative, data in {
            candidate["inventory_path"]: encoded(inventory),
            candidate["provenance_path"]: encoded(
                {
                    "candidate": candidate,
                    "original_metadata": original["metadata"],
                    "original_archive_sha256": original["archive_sha256"],
                    "source_file_inventory": inventory,
                }
            ),
            f"evidence/{candidate['task_id']}.LICENSE": licence,
            f"evidence/{candidate['task_id']}.repair.patch": patch,
        }.items():
            path = output / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
    for status, filename in (
        ("eligible_for_controls", "eligible.jsonl"),
        ("quarantine", "quarantined.jsonl"),
        ("unknown", "unknown.jsonl"),
    ):
        (output / filename).write_text(
            "".join(
                json.dumps(row, sort_keys=True) + "\n"
                for row in candidates
                if row["intake_assessment"]["status"] == status
            )
        )
    summary = {
        "schema": "scale800-canonical25-metadata-screen-v1",
        "source_revision": REVISION,
        "source_parquet_sha256": SHARD_SHA,
        "task_count": len(candidates),
        "native_file_count": sum(len(item[2]) for item in prepared),
        "native_bytes": sum(
            sum(row["bytes"] for row in item[2].values()) for item in prepared
        ),
        "repos": sorted({row["source_repo"] for row in candidates}),
        "statuses": dict(Counter(row["status"] for row in decisions)),
        "native_runtime_qualified": 0,
        "training_admissible": 0,
        "policy_sha256": POLICY_SHA,
        "consumed_input_sha256": consumed,
        "limitations": [
            "Metadata eligibility only, not runtime acceptance or semantic nonoverlap",
            "No task-specific negatives or transfer/image adapter is qualified",
            "License evidence is the captured declared permission and exact upstream text, not a blanket ownership claim",
            "Original task bytes, instructions, metadata and modes unchanged",
        ],
    }
    (output / "summary.json").write_bytes(encoded(summary))
    for name in ("screen.py", "test_screen.py"):
        path = output / "reproduction" / name
        path.parent.mkdir(exist_ok=True)
        path.write_bytes((HERE / name).read_bytes())
    inventory = {
        path.relative_to(output).as_posix(): {
            "sha256": digest(path.read_bytes()),
            "bytes": path.stat().st_size,
            "mode": stat.S_IMODE(path.stat().st_mode),
        }
        for path in sorted(output.rglob("*"))
        if path.is_file()
    }
    (output / "file-sha256.json").write_bytes(encoded(inventory))
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=HERE / "release-v1")
    args = parser.parse_args()
    result = build(args.output)
    print(
        json.dumps(
            {
                key: result[key]
                for key in (
                    "task_count",
                    "native_file_count",
                    "native_bytes",
                    "statuses",
                )
            }
        )
    )
