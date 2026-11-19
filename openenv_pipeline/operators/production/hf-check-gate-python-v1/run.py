"""Freeze and execute one private, source-bound HF Jobs semantic gate.

Preparation is offline. Execution is one-shot, requires a reviewed plan hash and
an explicit shared-ledger reservation, and makes no inference requests.
"""

import argparse
import base64
import hashlib
import importlib.util
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from decimal import Decimal
from fractions import Fraction
from pathlib import Path, PurePosixPath
from threading import Event, Lock

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[4]
sys.path[:0] = [str(REPO), str(REPO / "src"), str(REPO / "envs")]

from examples.hub_validation_pipeline import spend
from openenv.validation.parsers.harbor_toml import (
    canary_scripts,
    HarborTaskParser,
    read_harbor_contract,
)
from openenv.validation.runner import source_digest

SCHEMA = "openenv-python-hf-jobs-semantic-plan-v1"
ADAPTER_KIND = "python-git-patch-v1"
ADAPTER_DIR = HERE.parent / "python-jobs-wave-v1"
DEADLINE = "2026-11-13T11:39:00Z"
EXECUTION_KEYS = {
    "adapter_kind",
    "dependency_lock_sha256",
    "agent_image",
    "verifier_image",
    "workdir",
    "namespace",
    "flavor",
    "timeout_seconds",
    "submission_paths",
    "private_paths",
    "verifier_command",
    "reward_key",
    "reward_path",
    "max_submission_bytes",
    "max_tool_output_bytes",
    "max_script_bytes",
    "cleanup_attempts",
    "cleanup_timeout_seconds",
}


def load_module(name):
    spec = importlib.util.spec_from_file_location(
        "hf_jobs_gate_" + name, HERE / (name + ".py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return (
        json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n"
    ).encode()


def atomic(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(encode(value))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(temporary).unlink(missing_ok=True)


def utc(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(None):
        raise ValueError("Deadline must explicitly use UTC")
    return parsed


def remaining(plan):
    return (utc(plan["deadline_utc"]) - datetime.now(timezone.utc)).total_seconds()


def modules():
    paths = [HERE / name for name in ("run.py", "backend.py", "gate.py")]
    paths += [
        ADAPTER_DIR / name for name in ("adapter.py", "collect.py", "pytest_result.py")
    ]
    paths += list((REPO / "src/openenv/validation").rglob("*.py"))
    paths += [
        REPO / "examples/coding_audit/hf.py",
        REPO / "examples/coding_audit/runner.py",
        REPO / "examples/hub_validation_pipeline/spend.py",
    ]
    return {
        str(path.relative_to(REPO)): sha(path.read_bytes()) for path in sorted(paths)
    }


def read_json(path, expected=None):
    # Capture once: the bytes hashed here are the bytes parsed below.
    raw = path.read_bytes()
    if len(raw) > 8 * 1024**2 or expected is not None and sha(raw) != expected:
        raise ValueError("Reviewed JSON bytes changed or exceed the envelope")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate plan key")
            result[key] = value
        return result

    return json.loads(raw, object_pairs_hook=pairs), raw


def prepared(plan_path, expected):
    plan_path = Path(plan_path).resolve()
    if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ValueError("An explicit reviewed plan hash is required")
    plan, raw = read_json(plan_path, expected)
    if plan.get("schema") != SCHEMA or plan.get("module_sha256") != modules():
        raise ValueError(
            "Prepared runner or semantic code differs from the reviewed plan"
        )
    root = plan_path.parent / "task"
    if (
        sha((plan_path.parent / "image-receipt.json").read_bytes())
        != plan["image_receipt_sha256"]
    ):
        raise ValueError("Prepared image receipt changed")
    with tempfile.TemporaryDirectory(prefix="openenv-hf-job-plan-") as directory:
        inventory = load_module("gate")._capture(root, Path(directory))
        if (
            inventory != plan["task_files"]
            or source_digest(Path(directory)) != plan["task_digest"]
        ):
            raise ValueError(
                "Prepared task bytes or modes differ from the reviewed plan"
            )
        if (
            role_plan(Path(directory), plan["execution"].get("max_script_bytes", 65536))
            != plan["roles"]
        ):
            raise ValueError(
                "Prepared role scripts differ from the declared task controls"
            )
    return plan, sha(raw)


def role_plan(root, limit):
    manifest = HarborTaskParser().parse(root)
    contract = read_harbor_contract(root)
    if manifest.capabilities.oracle is None or contract.canaries is None:
        raise ValueError(
            "A provided reference and declared wrong-answer controls are required"
        )
    canaries = canary_scripts(root, contract.canaries)
    roles = [{"role": "nop", "script_path": None, "script_sha256": sha(b":")}]
    for role, path in [
        ("oracle", "solution/solve.sh"),
        ("oracle-replay", "solution/solve.sh"),
        *((name, name) for name in canaries),
    ]:
        raw = (root / path).read_bytes()
        raw.decode("utf-8")
        if len(raw) > limit:
            raise ValueError(
                "A declared control script exceeds the execution byte limit"
            )
        roles.append({"role": role, "script_path": path, "script_sha256": sha(raw)})
    return roles


def prepare(
    task_root,
    execution,
    image_receipt,
    output,
    *,
    expected_task_digest,
    budget_usd,
    deadline_utc=DEADLINE,
):
    """Capture a reviewable private plan without credentials or remote work."""
    amount = spend._amount(budget_usd)
    if amount <= 0:
        raise ValueError("An explicit positive modeled reservation is required")
    utc(deadline_utc)
    before = modules()
    receipt, receipt_raw = read_json(Path(image_receipt))
    execution = json.loads(encode(execution))
    if not isinstance(execution, dict) or set(execution) - EXECUTION_KEYS:
        raise ValueError(
            "Unknown execution fields; credentials belong only in runtime environment"
        )
    if execution.get("adapter_kind") != ADAPTER_KIND:
        raise ValueError(
            "Unsupported native shape: explicit python-git-patch-v1 adapter required"
        )
    lock = execution.get("dependency_lock_sha256")
    if lock is not None and (
        not isinstance(lock, str) or not re.fullmatch(r"[0-9a-f]{64}", lock)
    ):
        raise ValueError(
            "Dependency lock must be an exact measured SHA256 or absent for qualification only"
        )
    if execution.get("workdir") != "/testbed" or execution.get("submission_paths") != [
        "/testbed/submission.patch"
    ]:
        raise ValueError(
            "Python repository transfer requires the fixed Git patch boundary"
        )
    image = execution.get("agent_image")
    gate = load_module("gate")
    if (
        not isinstance(image, str)
        or not gate.IMAGE.fullmatch(image)
        or execution.get("verifier_image") != image
        or receipt.get("image") != image
        or receipt.get("config", {}).get("architecture") != "amd64"
        or receipt["config"].get("os") != "linux"
    ):
        raise ValueError("Use one actual immutable linux/amd64 runtime image receipt")
    workdir = execution.get("workdir")
    if (
        not isinstance(workdir, str)
        or not workdir.startswith("/")
        or PurePosixPath(workdir).as_posix() != workdir
        or ".." in PurePosixPath(workdir).parts
        or workdir == "/"
    ):
        raise ValueError("A normalized non-root workdir is required")
    timeout = execution.get("timeout_seconds", 600)
    if type(timeout) is not int or not 1 <= timeout <= 3600:
        raise ValueError("Execution timeout must be an integer in1..3600")
    if execution.get("flavor", "cpu-basic") != "cpu-basic" or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9-]{0,95}", execution.get("namespace", "")
    ):
        raise ValueError(
            "Use a reviewed cpu-basic execution namespace for this profile"
        )
    if output.exists() or output.is_symlink():
        raise FileExistsError("Prepare requires a fresh output directory")
    if output.resolve().is_relative_to(Path(task_root).resolve()):
        raise ValueError("Prepared output must be outside the source task")
    output.mkdir(parents=True, mode=0o700)
    frozen = output / "task"
    inventory = gate._capture(Path(task_root), frozen)
    if source_digest(frozen) != expected_task_digest:
        raise ValueError("Captured task differs from the acquired source digest")
    manifest = HarborTaskParser().parse(frozen)
    contract = read_harbor_contract(frozen)
    if manifest.capabilities.oracle is None or contract.canaries is None:
        raise ValueError(
            "A provided reference and declared wrong-answer controls are required"
        )
    if manifest.resources.gpus or contract.requires_credentials:
        raise ValueError(
            "This execution profile requires CPU tasks without credentials"
        )
    if (
        execution.get("verifier_command", ["/bin/bash", "/tests/test.sh"])
        != ["/bin/bash", "/tests/test.sh"]
        or execution.get("reward_key", contract.reward_key) != contract.reward_key
    ):
        raise ValueError(
            "Execution must invoke the captured verifier and declared reward key"
        )
    roles = role_plan(frozen, execution.get("max_script_bytes", 65536))
    descriptor_path = frozen / "adapter.json"
    if not descriptor_path.is_file():
        raise ValueError(
            "Unsupported native shape: task requires the frozen Python repository adapter"
        )
    descriptor, descriptor_raw = read_json(descriptor_path)
    if descriptor.get("schema") != "python-git-patch-jobs-v1":
        raise ValueError("Unsupported native Python adapter schema")
    helper = load_module("backend").adapter
    try:
        helper.validate_patch((frozen / "provided-gold.diff").read_bytes())
    except (ValueError, OSError):
        raise ValueError("Unsupported native gold patch shape") from None
    if descriptor.get("gold_patch_sha256") != sha(
        (frozen / "provided-gold.diff").read_bytes()
    ):
        raise ValueError(
            "Captured provided reference patch differs from its native binding"
        )
    if before != modules():
        raise ValueError("Runner source changed during preparation")
    plan = {
        "schema": SCHEMA,
        "profile": gate.PROFILE,
        "task_digest": expected_task_digest,
        "verifier_digest": source_digest(frozen / "tests"),
        "task_files": inventory,
        "task_inventory_sha256": sha(
            json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()
        ),
        "seed_digest": sha(descriptor_raw),
        "adapter_kind": ADAPTER_KIND,
        "dependency_lock_sha256": lock,
        "admission_blocked_pending_dependency_lock": lock is None,
        "execution": execution,
        "image_receipt_sha256": sha(receipt_raw),
        "roles": roles,
        "budget_usd": str(budget_usd),
        "deadline_utc": deadline_utc,
        "module_sha256": before,
        "native_validation": False,
        "model_calls": 0,
        "mode_changes_supported": True,
        "new_files_supported": True,
    }
    _private_bytes(output / "image-receipt.json", receipt_raw, [])
    atomic(output / "plan.json", plan)
    return plan


def reservation(plan, fingerprint, claim):
    with spend._ledger(claim["spend_ledger"]) as data:
        row = data["reservations"].get(claim["reservation_id"])
        if (
            spend._report(data)["over_budget"]
            or row is None
            or row["status"] != "reserved"
            or Fraction(row["reserved_usd"]) != Fraction(Decimal(plan["budget_usd"]))
            or row.get("plan_costs")
            != {fingerprint: str(Fraction(Decimal(plan["budget_usd"])))}
        ):
            raise ValueError(
                "The exact reviewed plan needs an active matching shared reservation"
            )


def _private_bytes(path, raw, credentials):
    if any(
        value.encode() in raw or base64.b64encode(value.encode()) in raw
        for value in credentials
        if value
    ):
        raise ValueError("Credential detected in private evidence")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def worker(plan_path, fingerprint, index, *, backend_class=None):
    plan_path = Path(plan_path).resolve()
    plan, _ = prepared(plan_path, fingerprint)
    if (
        type(index) is not int
        or not 0 <= index < len(plan["roles"])
        or remaining(plan) <= 30
    ):
        raise ValueError("Invalid trial index or expired execution deadline")
    root = plan_path.parent
    claim, _ = read_json(root / "execution-run/claim.json")
    if (
        claim["plan_sha256"] != fingerprint
        or claim.get("status") != "reserved_execution_one_shot"
    ):
        raise ValueError("Parent claim differs from the consumed plan")
    reservation(plan, fingerprint, claim)
    folder = root / "execution-run/trials" / f"{index:04d}"
    folder.mkdir(parents=True, exist_ok=True)
    fd = os.open(
        folder / "worker-claim.json", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600
    )
    with os.fdopen(fd, "wb") as stream:
        stream.write(encode({"plan_sha256": fingerprint, "index": index}))
        stream.flush()
        os.fsync(stream.fileno())
    credentials = [os.environ.get("HF_SANDBOX_TOKEN", "")]

    def checkpoint(value):
        raw = encode({"at_utc": datetime.now(timezone.utc).isoformat(), "event": value})
        if any(secret.encode() in raw for secret in credentials if secret):
            raise ValueError("Credential in lifecycle evidence")
        with (folder / "lifecycle.jsonl").open("ab") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())

    backend = None
    trial = {
        "role": plan["roles"][index]["role"],
        "agent_exit_code": None,
        "verifier_exit_code": None,
        "task_digest": plan["task_digest"],
        "task_inventory_sha256": None,
        "verifier_digest": plan["verifier_digest"],
        "image_ref": plan["execution"]["agent_image"],
        "grader_image_ref": None,
        "sandbox_id": None,
        "grade_sandbox_id": None,
        "cleanup_verified": False,
        "error": "controller did not complete",
    }
    try:
        execution = dict(plan["execution"])
        execution["timeout_seconds"] = min(
            execution.get("timeout_seconds", 600), max(1, int(remaining(plan) / 2) - 15)
        )
        cls = backend_class or load_module("backend").Backend
        backend = cls(
            root / "task",
            execution,
            expected_task_digest=plan["task_digest"],
            expected_seed_digest=plan["seed_digest"],
            expected_task_inventory_sha256=plan["task_inventory_sha256"],
            checkpoint=checkpoint,
        )
        role = plan["roles"][index]
        trial["task_inventory_sha256"] = backend.task_inventory_sha256
        raw = (
            b":"
            if role["script_path"] is None
            else (root / "task" / role["script_path"]).read_bytes()
        )
        if sha(raw) != role["script_sha256"]:
            raise ValueError("Frozen private script changed")
        agent = backend.run_control(raw.decode(), role["role"])
        grade = (
            backend.grade(agent)
            if agent.get("error") is None
            else {
                "error": "agent infrastructure failed",
                "cleanup_verified": False,
                "transcript": [],
            }
        )
        traces = grade.get("transcript", [])
        exit_code = traces[-1].get("exit_code") if traces else None
        trial.update(
            dependency_lock_sha256=agent.get("dependency_lock_sha256"),
            grader_dependency_lock_sha256=grade.get("dependency_lock_sha256"),
            agent_exit_code=agent.get("agent_exit_code"),
            verifier_exit_code=exit_code,
            image_ref=agent.get("image_ref"),
            grader_image_ref=grade.get("verifier_image_ref"),
            sandbox_id=agent.get("sandbox_id"),
            grade_sandbox_id=grade.get("grade_sandbox_id"),
            cleanup_verified=agent.get("cleanup_verified") is True
            and grade.get("cleanup_verified") is True,
            error=agent.get("error") or grade.get("error"),
        )
        reward = grade.get("rawreward", b"")
        if not isinstance(reward, bytes):
            raise ValueError("Verifier did not retain exact raw bytes")
        _private_bytes(folder / "reward.raw", reward, credentials)
        for name, data in agent.get("files", {}).items():
            relative = PurePosixPath(name).relative_to(plan["execution"]["workdir"])
            if ".." in relative.parts:
                raise ValueError("Submission artifact escaped its root")
            _private_bytes(
                folder / "submission" / relative.as_posix(), data, credentials
            )
        metadata = {
            "agent": {k: v for k, v in agent.items() if k != "files"},
            "grader": {k: v for k, v in grade.items() if k != "rawreward"},
        }
        _private_bytes(folder / "records.json", encode(metadata), credentials)
        trial["raw_reward_path"] = "reward.raw"
        trial["raw_reward_sha256"] = sha(reward)
    except (Exception, KeyboardInterrupt) as exc:
        trial.update(
            error="trial controller failed (" + type(exc).__name__ + ")",
            cleanup_verified=False,
        )
    finally:
        try:
            if backend is not None:
                backend.close()
        except Exception as exc:
            trial.update(
                error="private snapshot cleanup failed (" + type(exc).__name__ + ")",
                cleanup_verified=False,
            )
        finally:
            atomic(folder / "trial.json", trial)
    return trial


def execute(
    plan_path,
    expected_plan_sha256,
    *,
    spend_ledger,
    reservation_id,
    concurrency=6,
    execute_remote=False,
    popen=None,
):
    plan_path = Path(plan_path).resolve()
    if (
        execute_remote is not True
        or not spend_ledger
        or not isinstance(reservation_id, str)
        or not reservation_id.strip()
    ):
        raise ValueError(
            "Remote execution requires --execute, a ledger and a fresh reservation ID"
        )
    plan, fingerprint = prepared(plan_path, expected_plan_sha256)
    if (
        type(concurrency) is not int
        or not 1 <= concurrency <= 11
        or remaining(plan) <= 30
    ):
        raise ValueError("Invalid concurrency or expired execution deadline")
    output = plan_path.parent / "execution-run"
    output.mkdir(mode=0o700, exist_ok=False)
    claim = {
        "plan_sha256": fingerprint,
        "spend_ledger": str(Path(spend_ledger).resolve()),
        "reservation_id": reservation_id,
        "status": "reserve_pending",
    }
    atomic(output / "claim.json", claim)
    spend.reserve(
        spend_ledger,
        reservation_id,
        plan["budget_usd"],
        "HF Jobs semantic check trials",
        evidence="reviewed plan " + fingerprint,
        plan_costs={fingerprint: str(Fraction(Decimal(plan["budget_usd"])))},
    )
    claim["status"] = "reserved_execution_one_shot"
    atomic(output / "claim.json", claim)
    environment = {
        key: value
        for key, value in os.environ.items()
        if key
        in {
            "PATH",
            "HOME",
            "TMPDIR",
            "LANG",
            "LC_ALL",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
            "REQUESTS_CA_BUNDLE",
            "CURL_CA_BUNDLE",
            "HTTPS_PROXY",
            "HTTP_PROXY",
            "NO_PROXY",
            "HF_SANDBOX_TOKEN",
        }
    }
    environment["PYTHONPATH"] = (
        str(REPO) + ":" + str(REPO / "src") + ":" + str(REPO / "envs")
    )
    halted, lock = Event(), Lock()
    spawn = popen or subprocess.Popen

    def run(index):
        with lock:
            if halted.is_set() or remaining(plan) <= 30:
                return {"index": index, "status": "not_dispatched"}
            reservation(plan, fingerprint, claim)
            process = spawn(
                [
                    sys.executable,
                    "-B",
                    str(HERE / "run.py"),
                    "worker",
                    "--plan",
                    str(plan_path),
                    "--expected-plan-sha256",
                    fingerprint,
                    "--index",
                    str(index),
                ],
                cwd=REPO,
                env=environment,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        timed_out = False
        try:
            process.wait(
                timeout=min(
                    2 * plan["execution"].get("timeout_seconds", 600) + 240,
                    max(1, remaining(plan)),
                )
            )
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                with lock:
                    halted.set()
                    atomic(
                        output / "cleanup-required.json",
                        {"index": index, "cleanup_uncertain": True},
                    )
            finally:
                try:
                    os.killpg(process.pid, signal.SIGINT)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=120)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait()
        record = {
            "index": index,
            "process_exit_code": process.returncode,
            "supervisor_timed_out": timed_out,
        }
        path = output / "trials" / f"{index:04d}" / "trial.json"
        trial = read_json(path)[0] if path.exists() else None
        if timed_out or trial is None or trial.get("cleanup_verified") is not True:
            with lock:
                halted.set()
                atomic(
                    output / "cleanup-required.json",
                    {"index": index, "cleanup_uncertain": True},
                )
        atomic(output / "processes" / f"{index:04d}.json", record)
        return record

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        receipts = list(pool.map(run, range(len(plan["roles"]))))
    prepared(plan_path, fingerprint)
    trials = []
    for index in range(len(plan["roles"])):
        folder = output / "trials" / f"{index:04d}"
        if not (folder / "trial.json").exists():
            continue
        row, _ = read_json(folder / "trial.json")
        row["raw_reward"] = (
            (folder / "reward.raw").read_bytes()
            if (folder / "reward.raw").exists()
            else b""
        )
        if (
            row.get("raw_reward_sha256")
            and sha(row["raw_reward"]) != row["raw_reward_sha256"]
        ):
            raise ValueError("Raw reward artifact changed")
        trials.append(row)
    report = load_module("gate").assess(
        plan_path.parent / "task",
        trials,
        plan["task_digest"],
        plan["execution"]["agent_image"],
        expected_dependency_lock_sha256=plan["dependency_lock_sha256"],
    )
    atomic(output / "report.json", report)
    atomic(
        output / "controller-receipt.json",
        {
            "plan_sha256": fingerprint,
            "reservation_id": reservation_id,
            "processes": receipts,
            "halted_for_cleanup": halted.is_set(),
            "native_validation": False,
            "inference_calls": 0,
            "admitted": report["admitted"],
        },
    )
    hashes = {
        p.relative_to(output).as_posix(): sha(p.read_bytes())
        for p in sorted(output.rglob("*"))
        if p.is_file()
    }
    (output / "SHA256SUMS").write_text(
        "".join(digest + "  " + name + "\n" for name, digest in hashes.items())
    )
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prep = commands.add_parser("prepare")
    prep.add_argument("--task", type=Path, required=True)
    prep.add_argument("--task-sha256", required=True)
    prep.add_argument("--execution", type=Path, required=True)
    prep.add_argument("--image-receipt", type=Path, required=True)
    prep.add_argument("--output", type=Path, required=True)
    prep.add_argument("--budget-usd", required=True)
    prep.add_argument("--deadline-utc", default=DEADLINE)
    for command in ("execute", "worker"):
        p = commands.add_parser(command)
        p.add_argument("--plan", type=Path, required=True)
        p.add_argument("--expected-plan-sha256", required=True)
        if command == "worker":
            p.add_argument("--index", type=int, required=True)
        else:
            p.add_argument("--spend-ledger", required=True)
            p.add_argument("--reservation-id", required=True)
            p.add_argument("--concurrency", type=int, default=6)
            p.add_argument("--execute", action="store_true", required=True)
    args = parser.parse_args()
    if args.command == "prepare":
        prepare(
            args.task,
            read_json(args.execution)[0],
            args.image_receipt,
            args.output,
            expected_task_digest=args.task_sha256,
            budget_usd=args.budget_usd,
            deadline_utc=args.deadline_utc,
        )
        result = {
            "status": "prepared_no_remote_work",
            "plan_sha256": sha((args.output / "plan.json").read_bytes()),
        }
    elif args.command == "worker":
        result = worker(args.plan, args.expected_plan_sha256, args.index)
    else:
        result = execute(
            args.plan,
            args.expected_plan_sha256,
            spend_ledger=args.spend_ledger,
            reservation_id=args.reservation_id,
            concurrency=args.concurrency,
            execute_remote=args.execute,
        )
    summary = {
        "status": result.get("status", "completed"),
        "admitted": result.get("admitted", False),
    }
    if "plan_sha256" in result:
        summary["plan_sha256"] = result["plan_sha256"]
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
