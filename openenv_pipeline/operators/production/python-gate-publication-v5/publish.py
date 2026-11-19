"""Freeze Python gate evidence; publish only after explicit owner authorization.

Import and capture perform no credential reads or remote calls. The optional
publish function requires a caller-supplied token; the dataset/card owner must
coordinate the single CAS writer before invoking it.
"""

import fcntl
import functools
import math
import os
import time
from contextlib import contextmanager
import hashlib
import json
import re
import stat
import tempfile
import types
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path, PurePosixPath

import yaml
from huggingface_hub import CommitOperationAdd, HfApi, hf_hub_download
from openenv.validation.runner import source_digest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
PRODUCTION = HERE.parent
REPO = "harness-hub/agentic-coding-envs"
PREFIX = "scale800_py_v1/20261112"
CONFIG = "scale800_py_gate_v1"
DATASET_COMMIT_LOCK = Path("/Users/ben/.local/share/openenv-hub-dataset-commit.lock")
BASE_SHA = "bc9248dd39b3615462ebd30191575263fa59f8c3a38ae9e0fb6be087ac3082df"
RUNNERS = {
    "openenv-python-hf-jobs-semantic-plan-v1": (
        "hf-check-gate-python-v1",
        "e664a0afd84eb0c545a3db0494192a244032bf850c405725522ebdcf59376823",
    ),
    "openenv-python-hf-jobs-semantic-plan-v3": (
        "hf-check-gate-python-v3",
        "c4cf837c929f68a9d81b246735523587768d9303c83cb7c11a3e4c9a47fb599f",
    ),
    "openenv-python-hf-jobs-semantic-plan-v2": (
        "hf-check-gate-python-v2",
        "fbbf6d3bfb4820acf18623c65619ccac08dbd816dac3d10176695426eb4af9ba",
    ),
}
TERMINAL = {"COMPLETED", "ERROR", "CANCELED"}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return (
        json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n"
    ).encode()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def safe(name):
    path = PurePosixPath(name)
    require(
        isinstance(name, str)
        and path.as_posix() == name
        and not path.is_absolute()
        and bool(path.parts)
        and not any(part in {".", "..", ".git"} for part in path.parts),
        "Unsafe publication path",
    )
    return path


def parsed(raw):
    def pairs(values):
        result = {}
        for key, value in values:
            require(key not in result, "Duplicate JSON key")
            result[key] = value
        return result

    return json.loads(raw, object_pairs_hook=pairs)


def captured(path, expected=None):
    require(
        path.is_file() and not path.is_symlink(),
        "Captured input must be a regular file",
    )
    raw = path.read_bytes()
    require(
        expected is None or sha(raw) == expected,
        "Captured input differs from approved hash",
    )
    return raw


def compiled(raw, path, name):
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


@functools.cache
def parent():
    path = HERE / "parent-helper.py"
    return compiled(captured(path, BASE_SHA), path, "frozen_go_publication_primitives")


def tree(path):
    return parent().tree(Path(path))


def stable(report):
    value = parsed(encode(report))
    value["manifest"].pop("name", None)
    for check in value["results"]:
        check.pop("duration_s", None)
    return value


def terminal_proof(raw, plan, fingerprint, report_raw, trials):
    proof = parsed(raw)
    require(
        proof.get("plan_sha256") == fingerprint
        and proof.get("report_sha256") == sha(report_raw),
        "Independent terminal proof does not bind approved plan/report",
    )
    require(
        proof.get("task_digest") == plan["task_digest"]
        and proof.get("task_inventory_sha256") == plan["task_inventory_sha256"],
        "Independent terminal proof source binding mismatch",
    )
    require(
        proof.get("dependency_lock_sha256") == plan["dependency_lock_sha256"],
        "Terminal proof dependency identity mismatch",
    )
    expected = {
        (row["role"], kind): row[field]
        for row in trials
        for kind, field in (("agent", "sandbox_id"), ("grader", "grade_sandbox_id"))
    }
    jobs = proof.get("jobs", [])
    require(
        len(jobs) == len(expected), "Incomplete independently inspected Job inventory"
    )
    observed, ids = {}, set()
    for job in jobs:
        key = (job.get("role"), job.get("kind"))
        require(
            key in expected
            and key not in observed
            and job.get("job_id") == expected[key],
            "Independent Job identity/role mismatch",
        )
        require(
            job["job_id"] not in ids and job.get("owner_label_image_verified") is True,
            "Independent Job ownership/image identity is unverified",
        )
        require(
            job.get("stage") in TERMINAL
            and job.get("image_ref") == plan["execution"]["agent_image"],
            "Independent Job is nonterminal or uses another image",
        )
        observed[key] = job["job_id"]
        ids.add(job["job_id"])
    require(observed == expected, "Independent terminal inventory is incomplete")
    return proof


def source_record(task_bytes, caller):
    descriptor = parsed(task_bytes["adapter.json"])
    require(
        descriptor.get("schema") == "python-git-patch-jobs-v1",
        "Unsupported Python adapter",
    )
    source = descriptor.get("source_record", {})
    canonical = parent().canonical_repo
    require(
        source.get("task_id") == caller["task_id"]
        and descriptor.get("task_id") == caller["task_id"],
        "Caller task identity differs from frozen adapter source",
    )
    require(
        canonical(source.get("upstream_repo")) == canonical(caller["upstream_repo"]),
        "Caller canonical repository differs from frozen adapter source",
    )
    require(
        descriptor.get("source_repo") == source.get("source_repo")
        and descriptor.get("source_base_commit") == source.get("source_commit"),
        "Frozen source repository/BASE identity mismatch",
    )
    require(
        sha(task_bytes["instruction.md"]) == source.get("instruction_sha256"),
        "Native instruction differs from frozen source",
    )
    assessment = source.get("intake_assessment", source.get("eligibility", {}))
    require(
        assessment.get("status") == "eligible_for_controls",
        "Source did not pass unchanged holdout/rights intake",
    )
    require(
        source.get("semantic_nonoverlap_established") is False
        and source.get("training_admissible") is False,
        "Unexpected source qualification flags",
    )
    return source


def capture(rows, destination, batch_id):
    require(1 <= len(rows) <= 24, "A Python capture requires1..24 reviewed rows")
    publisher_raw = captured(HERE / "publish.py")
    destination = Path(destination)
    require(
        re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", batch_id) is not None,
        "Safe bounded batch ID required",
    )
    if destination.exists():
        raise FileExistsError(
            "Capture is immutable; reconcile existing plan or use a new destination"
        )
    files, index, captures, modes = {}, [], [], {}
    for caller in rows:
        plan_path = Path(caller["plan_path"]).resolve()
        plan_raw = captured(plan_path, caller["plan_sha256"])
        plan = parsed(plan_raw)
        require(plan.get("schema") in RUNNERS, "Unsupported closed Python plan schema")
        folder, pin = RUNNERS[plan["schema"]]
        runner_path = PRODUCTION / folder / "run.py"
        runner = compiled(
            captured(runner_path, pin), runner_path, "fixed_python_publication_runner"
        )
        checked, fingerprint = runner.prepared(plan_path, caller["plan_sha256"])
        require(
            checked == plan and fingerprint == sha(plan_raw),
            "Prepared plan changed during capture",
        )
        task_bytes, inventory = tree(plan_path.parent / "task")
        evidence, _ = tree(plan_path.parent / "execution-run")
        image_raw = captured(
            plan_path.parent / "image-receipt.json", plan["image_receipt_sha256"]
        )
        image = parsed(image_raw)
        require(
            image.get("image")
            == plan["execution"]["agent_image"]
            == plan["execution"]["verifier_image"]
            and image.get("config", {}).get("architecture") == "amd64"
            and image["config"].get("os") == "linux",
            "Captured image receipt does not bind actual linux/amd64 runtime",
        )
        require(
            plan["execution"].get("adapter_kind") == "python-git-patch-v1"
            and plan["execution"].get("dependency_lock_sha256")
            == plan.get("dependency_lock_sha256")
            and re.fullmatch(r"[a-f0-9]{64}", plan.get("dependency_lock_sha256", ""))
            is not None,
            "Python execution dependency lock/adapter binding is incomplete",
        )
        require(
            sha(task_bytes["adapter.json"]) == plan["seed_digest"],
            "Captured Python seed descriptor differs from qualified plan",
        )
        require(
            inventory == plan["task_files"],
            "Captured task bytes or modes differ from qualified inventory",
        )
        require(bool(inventory), "Empty qualified task inventory")
        expected = {}
        for line in evidence["SHA256SUMS"].decode().splitlines():
            digest, name = line.split("  ", 1)
            safe(name)
            require(
                name not in expected
                and re.fullmatch(r"[0-9a-f]{64}", digest) is not None,
                "Malformed/duplicate evidence checksum entry",
            )
            expected[name] = digest
        require(
            {name: sha(raw) for name, raw in evidence.items() if name != "SHA256SUMS"}
            == expected,
            "Captured evidence differs from complete checksum inventory",
        )
        report_raw = evidence["report.json"]
        require(
            sha(report_raw) == caller["report_sha256"],
            "Qualified report differs from approved hash",
        )
        report = parsed(report_raw)
        require(
            report.get("admitted") is True
            and report.get("profile") == "harbor-semantic-jobs-v1"
            and report.get("adapter_kind") == "python-git-patch-v1",
            "Python Jobs report is not admitted",
        )
        require(
            report.get("task_inventory_sha256") == plan["task_inventory_sha256"],
            "Report inventory differs from qualified plan",
        )
        trials = []
        for number, role in enumerate(plan["roles"]):
            prefix = f"trials/{number:04d}/"
            trial = parsed(evidence[prefix + "trial.json"])
            require(
                trial.get("role") == role["role"], "Trial role differs from frozen plan"
            )
            trial["raw_reward"] = evidence[prefix + "reward.raw"]
            trials.append(trial)
        terminal_raw = captured(
            Path(caller["terminal_proof_path"]), caller["terminal_proof_sha256"]
        )
        terminal_proof(terminal_raw, plan, fingerprint, report_raw, trials)
        with tempfile.TemporaryDirectory(
            prefix="python-publication-replay-"
        ) as directory:
            frozen = Path(directory)
            for name, raw in task_bytes.items():
                path = frozen / safe(name)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
                path.chmod(int(inventory[name]["mode"], 8))
            require(
                source_digest(frozen) == plan["task_digest"],
                "Captured task digest differs from qualified source",
            )
            assessed = runner.load_module("gate").assess(
                frozen,
                trials,
                plan["task_digest"],
                plan["execution"]["agent_image"],
                expected_dependency_lock_sha256=plan["dependency_lock_sha256"],
            )
        require(
            assessed.get("admitted") is True and stable(assessed) == stable(report),
            "Current pure Python gate disagrees with qualified report",
        )
        checks = {check["check_id"]: check["status"] for check in assessed["results"]}
        require(
            checks.get("runtime.dependency_identity") == "pass"
            and all(status == "pass" for status in checks.values()),
            "Every required Python check must PASS",
        )
        source = source_record(task_bytes, caller)
        key = sha(source["task_id"].encode())[:24]
        task_path = f"{PREFIX}/tasks/{key}"
        for name, raw in task_bytes.items():
            files[task_path + "/" + name] = raw
            modes[task_path + "/" + name] = inventory[name]["mode"]
        for name, raw in evidence.items():
            files[f"{PREFIX}/gate-evidence/{key}/" + name] = raw
        files[f"{PREFIX}/terminal-proof/{key}.json"] = terminal_raw
        files[f"{PREFIX}/plans/{key}.json"] = plan_raw
        execution = dict(
            plan["execution"],
            expected_task_inventory_sha256=plan["task_inventory_sha256"],
        )
        require(
            "public_source_files" not in execution,
            "Python Git-patch source cannot use Go fixed-file seeding",
        )
        execution_path, inventory_path, receipt_path = (
            f"{PREFIX}/{kind}/{key}.json"
            for kind in ("execution", "inventories", "images")
        )
        files[execution_path], files[inventory_path], files[receipt_path] = (
            encode(execution),
            encode(inventory),
            image_raw,
        )
        implementation = sha(encode(plan["module_sha256"]))[:24]
        implementation_path = f"{PREFIX}/implementations/{implementation}"
        for name, digest in plan["module_sha256"].items():
            safe(name)
            raw = captured(ROOT / name, digest)
            files[implementation_path + "/repo/" + name] = raw
        files[implementation_path + "/module-sha256.json"] = encode(
            plan["module_sha256"]
        )
        require(
            runner.modules() == plan["module_sha256"],
            "Closed Python runtime changed during captured publication",
        )
        provenance_path = f"{PREFIX}/provenance/{key}.json"
        files[provenance_path] = encode(
            {
                "source_record": source,
                "plan_sha256": fingerprint,
                "report_sha256": sha(report_raw),
                "terminal_proof_sha256": sha(terminal_raw),
                "qualified_task_modified": False,
                "native_modes_require_restoration_after_download": True,
                "provider_image_source_attestation": False,
            }
        )
        canonical = parent().canonical_repo(source["upstream_repo"])
        index.append(
            {
                "task_id": source["task_id"],
                "task_path": task_path,
                "instruction": task_bytes["instruction.md"].decode(),
                "source_repo": source["source_repo"],
                "upstream_repo": canonical,
                "source_dataset": source["source_dataset"],
                "source_revision": source["source_revision"],
                "source_split": source["source_split"],
                "source_commit": source["source_commit"],
                "source_pr_url": source.get("source_pr_url"),
                "source_license_spdx": source["license_evidence"]["source_code"][
                    "spdx"
                ],
                "task_bundle_license_spdx": source["license_evidence"]["task_bundle"][
                    "spdx"
                ],
                "usage": source["usage"],
                "evaluation_only": source.get(
                    "evaluation_only", source["source_split"] != "train"
                ),
                "semantic_nonoverlap_established": False,
                "provenance_path": provenance_path,
                "task_file_inventory_path": inventory_path,
                "task_inventory_sha256": plan["task_inventory_sha256"],
                "task_source_sha256": plan["task_digest"],
                "adapter_seed_sha256": plan["seed_digest"],
                "execution_path": execution_path,
                "image_receipt_path": receipt_path,
                "gate_report_path": f"{PREFIX}/gate-evidence/{key}/report.json",
                "terminal_proof_path": f"{PREFIX}/terminal-proof/{key}.json",
                "adapter_kind": "python-git-patch-v1",
                "adapter_implementation_path": implementation_path,
                "adapter_module_hashes_path": implementation_path
                + "/module-sha256.json",
                "dependency_lock_sha256": plan["dependency_lock_sha256"],
                "validation_profile": "harbor-semantic-jobs-v1",
                "gate_passed": True,
                "provided_reference": True,
                "generated_reference": False,
                "language": "python",
                "image_pull_qualified": True,
                "provider_image_source_attestation": False,
                "cloud_launch_ready": False,  # Gate-ready; 2m model adapter qualification is separate.
                "target_model": "Qwen/Qwen3.8-27B",
                "target_model_calibrated": False,
                "difficulty_status": "unmeasured",
                "rfc008_complete": False,
                "trainability_established": False,
                "training_admissible": False,
                "verified": False,
            }
        )
        backend_relative = str((PRODUCTION / folder / "backend.py").relative_to(ROOT))
        restore_relative = str((PRODUCTION / folder / "restore.py").relative_to(ROOT))
        index[-1].update(
            adapter_plan_schema=plan["schema"],
            adapter_backend_path=implementation_path + "/repo/" + backend_relative,
            adapter_restore_path=(implementation_path + "/repo/" + restore_relative)
            if restore_relative in plan["module_sha256"]
            else None,
        )
        captures.append(
            {
                "task_id": source["task_id"],
                "plan_sha256": fingerprint,
                "report_sha256": sha(report_raw),
                "terminal_proof_sha256": sha(terminal_raw),
                "evidence_checksums": len(expected),
                "job_ids": report["job_ids"],
                "checks": checks,
            }
        )
    require(
        bool(index) and len({row["task_id"] for row in index}) == len(index),
        "Empty or duplicate publication tasks",
    )
    counts = Counter(row["upstream_repo"] for row in index)
    require(
        all(count <= 40 for count in counts.values()),
        "Batch exceeds canonical repository cap40",
    )
    split = f"splits/{CONFIG}-{batch_id}.jsonl"
    files[split] = b"".join(
        (json.dumps(row, sort_keys=True) + "\n").encode() for row in index
    )
    summary = {
        "profile": "harbor-semantic-jobs-v1",
        "tasks": len(index),
        "per_repository": dict(counts),
        "per_language": {"python": len(index)},
        "qwen_measured": 0,
        "full_rfc008_qualified": 0,
        "training_admissible": 0,
        "split_path": split,
        "per_repository_accepted_cap": 40,
        "task_bytes_and_modes_unchanged": True,
    }
    files[f"{PREFIX}/batches/{batch_id}/summary.json"] = encode(summary)
    files[f"{PREFIX}/batches/{batch_id}/capture-replay.json"] = encode(captures)
    manifest = {
        name: {"sha256": sha(raw), "size": len(raw)}
        for name, raw in sorted(files.items())
    }
    files[f"{PREFIX}/batches/{batch_id}/file-sha256.json"] = encode(manifest)
    require(len(files) + 1 <= 5000, "Captured Python transaction exceeds5000operations")
    parent().scan(files, ())
    destination.mkdir(parents=True, mode=0o700)
    for name, raw in files.items():
        path = destination / "files" / safe(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        path.chmod(int(modes.get(name, "0o644"), 8))
    require(
        captured(HERE / "publish.py") == publisher_raw,
        "Publisher source changed during captured preparation",
    )
    plan = {
        "schema": "scale800-python-private-gate-publication-v1",
        "batch_id": batch_id,
        "config": CONFIG,
        "split_path": split,
        "files": {name: sha(raw) for name, raw in files.items()},
        "file_modes": {name: modes.get(name, "0o644") for name in files},
        "summary": summary,
        "captures": captures,
        "requires_owner_go_before_any_api_write": True,
        "parent_helper_sha256": BASE_SHA,
        "publisher_sha256": sha(publisher_raw),
    }
    (destination / "plan.json").write_bytes(encode(plan))
    return plan


def accepted_paths(metadata):
    """Count all scale800 accepted configs together, across languages and batches."""
    paths = set()
    for config in metadata.get("configs", []):
        if not config["config_name"].startswith("scale800"):
            continue
        for item in config.get("data_files", []):
            if item["split"] == "accepted":
                values = (
                    item["path"] if isinstance(item["path"], list) else [item["path"]]
                )
                for value in values:
                    safe(value)
                    require(
                        value.startswith("splits/")
                        and value.endswith(".jsonl")
                        and not any(char in value for char in "*?[]"),
                        "Global accepted cap requires exact immutable index paths",
                    )
                    paths.add(value)
    return sorted(paths)


def merge_card(oldcard, plan, files, prior_indices):
    header, body = oldcard.decode().split("\n---\n", 1)
    require(header.startswith("---\n"), "Dataset YAML header required")
    metadata = yaml.safe_load(header[4:])
    before = parsed(encode(metadata))
    paths = accepted_paths(metadata)
    require(
        set(prior_indices) == set(paths), "All accepted configurations must be counted"
    )
    ids, counts = set(), Counter()
    for raw in [prior_indices[path] for path in paths] + [files[plan["split_path"]]]:
        for line in raw.splitlines():
            row = parsed(line)
            require(row["task_id"] not in ids, "Task identity already accepted")
            ids.add(row["task_id"])
            counts[parent().canonical_repo(row["upstream_repo"])] += 1
    require(
        all(count <= 40 for count in counts.values()),
        "Global canonical repository cap40 exceeded",
    )
    configs = metadata.setdefault("configs", [])
    require(
        len({config["config_name"] for config in configs}) == len(configs),
        "Duplicate config names",
    )
    owned = next(
        (config for config in configs if config["config_name"] == CONFIG), None
    )
    if owned is None:
        owned = {"config_name": CONFIG, "data_files": []}
        configs.append(owned)
    accepted = next(
        (item for item in owned["data_files"] if item["split"] == "accepted"), None
    )
    if accepted is None:
        owned["data_files"].append({"split": "accepted", "path": [plan["split_path"]]})
    else:
        accepted["path"] = (
            [accepted["path"]]
            if isinstance(accepted["path"], str)
            else accepted["path"]
        ) + [plan["split_path"]]
    for config in before.get("configs", []):
        if config["config_name"] != CONFIG:
            require(config in configs, "An unowned config changed")
    card = (
        "---\n"
        + yaml.safe_dump(metadata, sort_keys=False, allow_unicode=True)
        + "---\n"
        + body
    ).encode()
    require(card.decode().split("\n---\n", 1)[1] == body, "Dataset body changed")
    return card


@functools.cache
def transport():
    path = HERE / "transport-helper.py"
    return compiled(
        captured(
            path, "7eed4fc70537b0736b718f5cb2b57b5d1a445efce003df4ca31bb8c1b39deed8"
        ),
        path,
        "approved_scoped_transport_primitives",
    )


@functools.cache
def direct_module():
    path = HERE / "immutable_get.py"
    return compiled(
        captured(
            path, "69016ba7e5f1de4825b10459bf96ad6310908a62169ece74b90ad35c4777ff9a"
        ),
        path,
        "approved_python_immutable_GET",
    )


def frozen_publication(destination, expected_plan_sha256):
    destination = Path(destination)
    plan = parsed(captured(destination / "plan.json", expected_plan_sha256))
    require(
        plan.get("schema") == "scale800-python-private-gate-publication-v1"
        and plan["config"] == CONFIG,
        "Reviewed Python publication plan required",
    )
    captured(HERE / "publish.py", plan["publisher_sha256"])
    files = {
        name: captured(destination / "files" / safe(name), digest)
        for name, digest in plan["files"].items()
    }
    require(
        set(plan["file_modes"]) == set(files),
        "Captured publication mode inventory is incomplete",
    )
    for name, expected_mode in plan["file_modes"].items():
        require(
            oct(stat.S_IMODE((destination / "files" / name).stat().st_mode))
            == expected_mode,
            "Captured publication file mode changed",
        )
    require(
        len(files) + 1 <= 5000 and plan["summary"]["tasks"] <= 24,
        "Python transaction resource envelope exceeded",
    )
    return plan, files


def explicit_values(token, credential_values, workers):
    require(
        isinstance(token, str) and bool(token),
        "Owner must supply authorized token explicitly",
    )
    require(
        type(workers) is int and 1 <= workers <= 64, "Readback workers must be1..64"
    )
    return [token, *credential_values]


@contextmanager
def dataset_commit_mutex(path=None, *, timeout_s=120, poll_s=0.1):
    """Serialize only the final CAS transaction with cooperating dataset writers.

    Acquisition failure occurs before any commit attempt. The OS releases the
    advisory lock on process exit; no stale-file deletion or blind retry occurs.
    """
    if (
        type(timeout_s) not in (int, float)
        or not math.isfinite(timeout_s)
        or timeout_s < 0
        or type(poll_s) not in (int, float)
        or not math.isfinite(poll_s)
        or poll_s <= 0
    ):
        raise ValueError(
            "Finite nonnegative acquisition timeout and positive poll required"
        )
    path = Path(path) if path is not None else DATASET_COMMIT_LOCK
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o600,
            "Dataset commit mutex must be an owned0600 regular file",
        )
        deadline = time.monotonic() + timeout_s
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(
                        "Dataset commit mutex unavailable; no commit attempted"
                    ) from None
                time.sleep(min(poll_s, remaining))
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def final_parent(api, read, baseline, baseline_card, additions, token):
    """Refresh once under the shared writer lock; only this publisher owns paths.

    Model-result writers may append elsewhere. An unchanged complete README
    preserves all counted accepted indices, caps, features, configs and body.
    A moved head is never retried after create_commit; its CAS still decides.
    """
    require(
        all(type(operation) is CommitOperationAdd for operation in additions),
        "Final refresh requires exclusively Add operations",
    )
    require(
        all(
            operation.path_in_repo == "README.md"
            or operation.path_in_repo.startswith(PREFIX + "/")
            or re.fullmatch(
                r"splits/scale800_py_gate_v1-[a-z0-9][a-z0-9._-]{0,63}\.jsonl",
                operation.path_in_repo,
            )
            for operation in additions
        ),
        "Final refresh requires exclusively owned publication paths",
    )
    latest = api.dataset_info(REPO, token=token, timeout=120)
    require(latest.private is True, "Destination became public before commit")
    require(
        read("README.md", latest.sha) == baseline_card,
        "Dataset card changed during publication preparation",
    )
    return latest, {
        "validated_parent": baseline.sha,
        "refreshed_parent": latest.sha,
        "card_unchanged": True,
        "basis": "identical_complete_card_and_shared_single_writer_owned_paths",
        "create_commit_retries": 0,
    }


def commit(
    destination,
    expected_plan_sha256,
    *,
    token,
    credential_values=(),
    api=None,
    download=None,
    readback_workers=64,
):
    """Preupload identical Add instances, then exactly one fresh-parent private CAS."""
    destination = Path(destination)
    receipt_path = destination / "publication.json"
    if receipt_path.exists():
        raise FileExistsError("Reconcile recorded publication attempt before retry")
    plan, files = frozen_publication(destination, expected_plan_sha256)
    values = explicit_values(token, credential_values, readback_workers)
    parent().scan(files, values)
    api = api if api is not None else HfApi(token=token)
    download = download if download is not None else hf_hub_download

    def read(path, revision):
        result = download(
            REPO, path, repo_type="dataset", revision=revision, token=token
        )
        return result if isinstance(result, bytes) else Path(result).read_bytes()

    require(
        api.dataset_info(REPO, token=token, timeout=120).private is True,
        "Destination dataset must stay private",
    )
    additions = [
        CommitOperationAdd(path_in_repo=name, path_or_fileobj=data)
        for name, data in sorted(files.items())
    ]
    receipt = {
        "status": "preupload_only_no_dataset_commit",
        "plan_sha256": expected_plan_sha256,
        "batch_id": plan["batch_id"],
        "source_operations": len(additions),
        "preupload_threads": 16,
        "free_memory": False,
        "publisher_sha256": sha(captured(HERE / "publish.py")),
        "readback_workers": readback_workers,
    }
    transport().atomic(receipt_path, receipt)
    api.preupload_lfs_files(
        REPO,
        additions,
        repo_type="dataset",
        token=token,
        num_threads=16,
        free_memory=False,
    )
    receipt.update(status="preupload_complete_no_dataset_commit")
    transport().atomic(receipt_path, receipt)
    info = api.dataset_info(REPO, token=token, timeout=120)
    require(info.private is True, "Destination visibility changed after preupload")
    previous = transport().targeted_paths(api, files, info.sha, token)
    with ThreadPoolExecutor(max_workers=readback_workers) as pool:
        existing = dict(
            pool.map(lambda name: (name, read(name, info.sha)), sorted(previous))
        )
    require(
        all(raw == files[name] for name, raw in existing.items()),
        "Existing dataset path would change",
    )
    oldcard = read("README.md", info.sha)
    metadata = yaml.safe_load(oldcard.decode().split("\n---\n", 1)[0][4:])
    with ThreadPoolExecutor(max_workers=readback_workers) as pool:
        indices = dict(
            pool.map(
                lambda name: (name, read(name, info.sha)), accepted_paths(metadata)
            )
        )
    card = merge_card(oldcard, plan, files, indices)
    parent().scan({"README.md": card}, values)
    (destination / "commit-card.md").write_bytes(card)
    additions.append(CommitOperationAdd(path_in_repo="README.md", path_or_fileobj=card))
    require(
        all(type(operation) is CommitOperationAdd for operation in additions),
        "Only Add operations authorized",
    )
    with dataset_commit_mutex():
        info, parent_refresh = final_parent(api, read, info, oldcard, additions, token)
        receipt.update(
            status="commit_uncertain",
            parent_refresh=parent_refresh,
            dataset_commit_mutex_path=str(DATASET_COMMIT_LOCK),
            dataset_commit_mutex_scope="final_refresh_through_known_CID_journal",
            parent=info.sha,
            expected_paths=sorted([*files, "README.md"]),
            card_before_sha256=sha(oldcard),
            card_after_sha256=sha(card),
            summary=plan["summary"],
            preservation_proof="exact_parent_add_only_and_collision_readback",
            full_repository_walk=False,
        )
        transport().atomic(receipt_path, receipt)
        committed = api.create_commit(
            REPO,
            repo_type="dataset",
            parent_commit=info.sha,
            commit_message="Append private Python HF Jobs-gated task batch "
            + plan["batch_id"],
            operations=additions,
            token=token,
        )
        receipt.update(status="committed_readback_pending", revision=committed.oid)
        transport().atomic(receipt_path, receipt)
    return receipt


def verify_readback(
    destination,
    expected_plan_sha256,
    *,
    token,
    credential_values=(),
    api=None,
    download=None,
    readback_workers=64,
    download_pool=None,
):
    """Known-CID-only full byte verification, independently resumable without a write."""
    destination = Path(destination)
    plan, files = frozen_publication(destination, expected_plan_sha256)
    explicit_values(token, credential_values, readback_workers)
    receipt = parsed(captured(destination / "publication.json"))
    require(
        receipt.get("status") == "committed_readback_pending"
        and receipt["plan_sha256"] == expected_plan_sha256,
        "Known committed snapshot required",
    )
    require(
        receipt.get("source_operations") == len(files),
        "Add-only operation inventory differs",
    )
    card = captured(destination / "commit-card.md", receipt["card_after_sha256"])
    files["README.md"] = card
    api = api if api is not None else HfApi(token=token)
    require(
        transport().targeted_paths(api, files, receipt["revision"], token)
        == set(files),
        "Immutable proposed path inventory incomplete",
    )
    reader = None
    if download is None:
        reader = direct_module().ImmutableGet(
            receipt["revision"], files, destination / "immutable-readback-cache"
        )
        download = reader.download

    def verify(item):
        name, payload = item
        result = download(
            REPO, name, repo_type="dataset", revision=receipt["revision"], token=token
        )
        raw = result if isinstance(result, bytes) else Path(result).read_bytes()
        require(raw == payload, "Immutable readback differs: " + name)
        return len(raw)

    try:
        if download_pool is None:
            with ThreadPoolExecutor(max_workers=readback_workers) as pool:
                amounts = list(pool.map(verify, files.items()))
        else:
            amounts = list(download_pool.map(verify, files.items()))
    finally:
        if reader is not None:
            reader.close()
    receipt.update(
        status="immutable_readback_verified",
        files=len(files),
        bytes_verified=sum(amounts),
        config=CONFIG,
        split="accepted",
        split_path=plan["split_path"],
        summary=plan["summary"],
        remote_POSIX_modes_verified=False,
        readback_path_scope="all-proposed-paths-exact-immutable-bytes",
        preservation_proof="exact_parent_add_only_and_collision_readback",
    )
    transport().atomic(destination / "publication.json", receipt)
    return receipt


def publish(
    destination,
    expected_plan_sha256,
    *,
    token,
    credential_values=(),
    api=None,
    download=None,
    readback_workers=64,
):
    """One owner-authorized commit followed by immutable full readback; never retries."""
    commit(
        destination,
        expected_plan_sha256,
        token=token,
        credential_values=credential_values,
        api=api,
        download=download,
        readback_workers=readback_workers,
    )
    return verify_readback(
        destination,
        expected_plan_sha256,
        token=token,
        credential_values=credential_values,
        api=api,
        download=download,
        readback_workers=readback_workers,
    )
