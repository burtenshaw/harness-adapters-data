"""Pure, source-bound semantic admission for fresh HF Jobs evidence."""

import hashlib
import json
import os
import re
import stat
import tempfile
from decimal import Decimal
from fractions import Fraction
from pathlib import Path

from openenv.validation.graders import Subject
from openenv.validation.graders.semantic import (
    CanaryFloorGrader,
    FloorGapGrader,
    OracleMaxGrader,
)
from openenv.validation.manifest import ManifestError
from openenv.validation.parsers.harbor_toml import (
    canary_scripts,
    HarborTaskParser,
    read_harbor_contract,
)
from openenv.validation.runner import _DIGEST_EXCLUDED_DIRS, source_digest
from openenv.validation.runtime.contracts import OracleEvidence

PROFILE = "harbor-semantic-jobs-v1"
CHECKS = (
    "static.manifest",
    "runtime.startup",
    "runtime.reward_well_formed",
    "runtime.episode_determinism",
    "semantic.oracle_max",
    "semantic.floor_gap",
    "semantic.canary_floor",
)
FIELDS = {
    "role",
    "agent_exit_code",
    "verifier_exit_code",
    "raw_reward",
    "task_digest",
    "task_inventory_sha256",
    "verifier_digest",
    "image_ref",
    "sandbox_id",
    "grade_sandbox_id",
    "cleanup_verified",
    "error",
}
IMAGE = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _result(check_id, status, reason, measured=None):
    return {
        "check_id": check_id,
        "status": status,
        "evidence": [reason],
        "measured": measured or {},
    }


def _capture(root, destination):
    """Capture exactly the library digest scope without dereferencing links."""
    inventory, total = {}, 0
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if any(part in _DIGEST_EXCLUDED_DIRS for part in relative.parts):
            continue
        before = path.lstat()
        if stat.S_ISDIR(before.st_mode):
            continue
        if not stat.S_ISREG(before.st_mode) or before.st_mode & 0o7000:
            raise ValueError("Task source must contain ordinary regular files")
        if before.st_size > 8 * 1024**2 or len(inventory) >= 4096:
            raise ValueError("Task capture envelope exceeded")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or not os.path.samestat(before, opened):
                raise ValueError("Task source changed before capture")
            raw = stream.read(8 * 1024**2 + 1)
        if len(raw) != opened.st_size:
            raise ValueError("Task source size changed during capture")
        total += len(raw)
        if total > 64 * 1024**2:
            raise ValueError("Task capture envelope exceeded")
        mode = stat.S_IMODE(opened.st_mode)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        target.chmod(mode)
        inventory[relative.as_posix()] = {
            "sha256": _sha(raw),
            "mode": oct(mode),
            "size": len(raw),
        }
    return inventory


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate reward key")
        result[key] = value
    return result


def _invalid_constant(value):
    raise ValueError("Non-finite reward")


def _rewards(raw, reward_key, low, high):
    if type(raw) is not bytes or not 0 < len(raw) <= 65536:
        raise ValueError("Reward must be bounded raw bytes")
    text = raw.decode("utf-8").strip()
    value = (
        json.loads(
            text,
            parse_float=Decimal,
            parse_int=Decimal,
            parse_constant=_invalid_constant,
            object_pairs_hook=_unique,
        )
        if text.startswith("{")
        else {reward_key: Decimal(text)}
    )
    if not isinstance(value, dict) or not value or reward_key not in value:
        raise ValueError("Reward map lacks the declared key")
    result = {}
    for key, number in value.items():
        if (
            not isinstance(key, str)
            or not key
            or not isinstance(number, Decimal)
            or not number.is_finite()
        ):
            raise ValueError("Rewards must be finite nonboolean numeric data")
        # Bound exact-rational construction before allocating exponent-sized ints.
        if (
            abs(number.as_tuple().exponent) > 10000
            or len(number.as_tuple().digits) > 10000
        ):
            raise ValueError("Reward numeric envelope exceeded")
        exact = Fraction(number)
        if not low <= exact <= high:
            raise ValueError("Reward lies outside the declared range")
        result[key] = exact
    return result


def assess(task_root, trials, expected_source_digest, expected_image_ref):
    """Admit only complete, bound, deterministic fresh-Job semantic evidence."""
    results = {
        name: _result(name, "skip", "unmet execution prerequisites") for name in CHECKS
    }
    report = {
        "profile": PROFILE,
        "schema_version": 1,
        "admitted": False,
        "execution_backend": "huggingface-sandbox-jobs",
        "image_ref": expected_image_ref,
        "expected_source_digest": expected_source_digest,
        "raw_reward_sha256": {},
        "exact_reward_maps": {},
        "native_validation": False,
        "rfc008_complete": False,
        "target_model_calibrated": False,
        "trainability_established": False,
        "training_admissible": False,
        "hostile_code_verifier_integrity_qualified": False,
        "limitations": [
            "Operator-collected Job evidence; this is not a native ValidationReport.",
            "The collector must inspect actual image, ownership and terminal cleanup of both Jobs per trial.",
            "Content hashes alone do not attest remote modes, architecture or hostile-code verifier isolation.",
        ],
    }

    def finish():
        report["results"] = list(results.values())
        report["admitted"] = all(row["status"] == "pass" for row in results.values())
        return report

    if (
        not isinstance(expected_source_digest, str)
        or not DIGEST.fullmatch(expected_source_digest)
        or not isinstance(expected_image_ref, str)
        or not IMAGE.fullmatch(expected_image_ref)
    ):
        results["runtime.startup"] = _result(
            "runtime.startup",
            "error",
            "invalid expected source or immutable image binding",
        )
        return finish()
    with tempfile.TemporaryDirectory(prefix="openenv-hf-gate-") as directory:
        frozen = Path(directory)
        try:
            inventory = _capture(Path(task_root), frozen)
            digest = source_digest(frozen)
            if digest != expected_source_digest:
                raise ValueError(
                    "Captured task differs from the expected source digest"
                )
            if not {"task.toml", "instruction.md", "tests/test.sh"} <= inventory.keys():
                raise ValueError("Required native task files are missing")
            verifier_digest = source_digest(frozen / "tests")
            report.update(
                task_digest=digest,
                verifier_digest=verifier_digest,
                task_files=inventory,
                task_inventory_sha256=_sha(
                    json.dumps(
                        inventory, sort_keys=True, separators=(",", ":")
                    ).encode()
                ),
            )
        except (OSError, ValueError, RuntimeError):
            results["static.manifest"] = _result(
                "static.manifest", "error", "source capture or identity failed"
            )
            return finish()
        try:
            manifest = HarborTaskParser().parse(frozen)
            contract = read_harbor_contract(frozen)
            if manifest.capabilities.oracle is None:
                results["semantic.oracle_max"] = _result(
                    "semantic.oracle_max", "fail", "solution/solve.sh is missing"
                )
            if contract.canaries is None:
                raise ValueError("This Jobs profile requires declared canaries")
            canaries = canary_scripts(frozen, contract.canaries)
            if source_digest(frozen) != digest:
                raise ValueError("Parsed task snapshot changed")
            report["manifest"] = manifest.model_dump(mode="json")
            results["static.manifest"] = _result(
                "static.manifest",
                "pass",
                "captured Harbor declarations parsed; canaries are mandatory",
            )
        except (ManifestError, ValueError, OSError, RuntimeError):
            results["static.manifest"] = _result(
                "static.manifest",
                "fail",
                "Harbor declarations or mandatory canaries are invalid",
            )
            return finish()
        if results["semantic.oracle_max"]["status"] == "fail":
            return finish()
        roles = ("nop", "oracle", "oracle-replay", *canaries)
        report["expected_roles"] = list(roles)
        try:
            if (
                not isinstance(trials, list)
                or len(trials) != len(roles)
                or any(
                    not isinstance(trial, dict) or not FIELDS <= trial.keys()
                    for trial in trials
                )
            ):
                raise ValueError("Incomplete trial records")
            if any(not isinstance(trial["role"], str) for trial in trials) or {
                trial["role"] for trial in trials
            } != set(roles):
                raise ValueError("Trial roles differ from the declared plan")
            by_role = {trial["role"]: trial for trial in trials}
            if len(by_role) != len(roles):
                raise ValueError("Duplicate trial role")
            job_ids = []
            for trial in trials:
                if (
                    trial["task_digest"] != digest
                    or trial["task_inventory_sha256"] != report["task_inventory_sha256"]
                    or trial["verifier_digest"] != verifier_digest
                    or trial["image_ref"] != expected_image_ref
                    or trial.get("grader_image_ref", expected_image_ref)
                    != expected_image_ref
                ):
                    raise ValueError("Trial identity drift")
                if (
                    trial["cleanup_verified"] is not True
                    or trial["error"] is not None
                    or type(trial["verifier_exit_code"]) is not int
                    or trial["verifier_exit_code"] != 0
                    or type(trial["agent_exit_code"]) is not int
                ):
                    raise ValueError("Trial infrastructure or cleanup failed")
                for key in ("sandbox_id", "grade_sandbox_id"):
                    identity = trial[key]
                    if not isinstance(identity, str) or not re.fullmatch(
                        r"[A-Za-z0-9._:-]{1,128}", identity
                    ):
                        raise ValueError("Job identity missing or malformed")
                    job_ids.append(identity)
            if len(set(job_ids)) != len(job_ids):
                raise ValueError("Jobs were reused across trials")
            report["job_ids"] = job_ids
            results["runtime.startup"] = _result(
                "runtime.startup",
                "pass",
                "all declared trials have distinct, bound, clean Job pairs",
                measured={
                    "agent_exit_codes": {
                        role: by_role[role]["agent_exit_code"] for role in roles
                    }
                },
            )
        except (ValueError, TypeError):
            results["runtime.startup"] = _result(
                "runtime.startup",
                "error",
                "trial plan, identity, execution or cleanup is incomplete",
            )
            return finish()
        try:
            low, high = (Fraction(str(value)) for value in manifest.reward.range)
            rewards = {
                role: _rewards(
                    by_role[role]["raw_reward"], contract.reward_key, low, high
                )
                for role in roles
            }
            report["raw_reward_sha256"] = {
                role: _sha(by_role[role]["raw_reward"]) for role in roles
            }
            report["exact_reward_maps"] = {
                role: {key: str(value) for key, value in values.items()}
                for role, values in rewards.items()
            }
            results["runtime.reward_well_formed"] = _result(
                "runtime.reward_well_formed",
                "pass",
                "all exact raw reward maps satisfy the declared range",
            )
        except (ValueError, TypeError, ArithmeticError, RecursionError):
            results["runtime.reward_well_formed"] = _result(
                "runtime.reward_well_formed",
                "fail",
                "a raw reward map is malformed, unbounded or outside the declared range",
            )
            return finish()
        if (
            rewards["oracle"] != rewards["oracle-replay"]
            or by_role["oracle"]["agent_exit_code"]
            != by_role["oracle-replay"]["agent_exit_code"]
        ):
            results["runtime.episode_determinism"] = _result(
                "runtime.episode_determinism",
                "fail",
                "oracle replay changed its full reward map or exit code",
            )
            return finish()
        results["runtime.episode_determinism"] = _result(
            "runtime.episode_determinism",
            "pass",
            "oracle replay reproduced the full exact reward map and exit code",
        )
        evidence = OracleEvidence(
            floor=rewards["nop"][contract.reward_key],
            oracle=tuple(
                rewards[role][contract.reward_key]
                for role in ("oracle", "oracle-replay")
            ),
            oracle_exit_codes=tuple(
                by_role[role]["agent_exit_code"] for role in ("oracle", "oracle-replay")
            ),
            canaries=tuple(
                (role, rewards[role][contract.reward_key]) for role in canaries
            ),
        )
        subject = Subject(
            root=frozen,
            manifest=manifest,
            image_ref=expected_image_ref,
            running=None,
            outputs_dir=frozen,
            oracle_evidence=evidence,
        )
        for grader in (OracleMaxGrader(), FloorGapGrader(), CanaryFloorGrader()):
            result = grader.run(subject)
            results[result.check_id] = result.model_dump(mode="json")
    return finish()
