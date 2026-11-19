"""Pure deterministic derived indexes over captured accepted environment rows."""

import copy
import hashlib
import json
import math
import re
from pathlib import Path

import yaml

CONFIGS = {"scale800_gate_v1": "go", "scale800_py_gate_v1": "python"}
PROTOCOL = "qwen38-auto48-64k-2m-nothink-r3-v1"
PROTOCOL_PREFIX = "qwen38-auto48-64k-2m-nothink"
TARGET_MODEL = "Qwen/Qwen3.8-27B"
MAIN = "scale800_v1"
BEST = "scale800_best_v1"
LEGACY_DEFAULT = "legacy_default_v1"
VIEW_PATHS = {
    MAIN: "views/scale800_v1/train.jsonl",
    BEST: "views/scale800_best_v1/train.jsonl",
}
DERIVED_TYPES = {
    "qwen_protocol": "string",
    "qwen_status": "string",
    "qwen_solved": "int64",
    "qwen_valid_attempts": "int64",
    "qwen_solve_rate": "float64",
    "qwen_wilson95_low": "float64",
    "qwen_wilson95_high": "float64",
    "qwen_difficulty": "float64",
    "generated_alternatives_run": "bool",
    "leak_audit_run": "bool",
    "in_stratified_sample": "bool",
}


def encode(value):
    return (
        json.dumps(
            value,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        )
        + "\n"
    ).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def parsed(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON key")
            result[key] = value
        return result

    def invalid(value):
        raise ValueError("Nonfinite JSON number")

    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)


def scalar_type(values):
    values = [value for value in values if value is not None]
    if not values or all(type(value) is str for value in values):
        return "string"
    if all(type(value) is bool for value in values):
        return "bool"
    if all(type(value) is int for value in values):
        if not all(-(2**63) <= value < 2**63 for value in values):
            raise ValueError("Integer field exceeds int64")
        return "int64"
    if all(type(value) in {int, float} and math.isfinite(value) for value in values):
        return "float64"
    raise ValueError("Derived indexes support consistent finite scalar fields only")


def unify(accepted):
    """Accept only the two named accepted configs and reject conflicting IDs."""
    if "configs" in accepted:
        if (
            not isinstance(accepted["configs"], list)
            or len(accepted["configs"]) != 2
            or set(accepted["configs"]) != set(CONFIGS)
            or accepted.get("repo_id") != "harness-hub/agentic-coding-envs"
            or not isinstance(accepted.get("revision"), str)
            or not re.fullmatch(r"[0-9a-f]{40}", accepted["revision"])
            or not isinstance(accepted.get("rows"), list)
            or not all(
                isinstance(row, dict) and row.get("language") in CONFIGS.values()
                for row in accepted["rows"]
            )
        ):
            raise ValueError("Accepted capture source/config identity differs")
        accepted = {
            name: {
                "split": "accepted",
                "rows": [
                    row for row in accepted["rows"] if row["language"] == language
                ],
            }
            for name, language in CONFIGS.items()
        }
    if set(accepted) != set(CONFIGS):
        raise ValueError("Use exactly the Go and Python accepted config captures")
    inputs = []
    for name in sorted(CONFIGS):
        capture = accepted[name]
        if capture.get("split") != "accepted" or not isinstance(
            capture.get("rows"), list
        ):
            raise ValueError("Only explicit accepted splits are eligible")
        for original in capture["rows"]:
            row = copy.deepcopy(original)
            if (
                not isinstance(row, dict)
                or not isinstance(row.get("task_id"), str)
                or not row["task_id"]
                or row.get("language") != CONFIGS[name]
                or row.get("gate_passed") is not True
                or row.get("corpus_admitted") is False
                or row.get("exclude_from_800") is True
                or row.get("exclude_from_qwen") is True
            ):
                raise ValueError(
                    "Captured source is not an accepted language-bound task"
                )
            if set(row).intersection(DERIVED_TYPES):
                raise ValueError("Source row already contains reserved derived fields")
            for key in ("task_source_sha256", "task_inventory_sha256"):
                if not re.fullmatch(r"[0-9a-f]{64}", row.get(key, "")):
                    raise ValueError(
                        "Accepted full source and mode inventory hashes are required"
                    )
            if row.get("target_model", TARGET_MODEL) != TARGET_MODEL:
                raise ValueError("Accepted row names a different target model")
            inputs.append(row)
    keys = sorted({key for row in inputs for key in row})
    for key in keys:
        scalar_type([row.get(key) for row in inputs])
    by_id = {}
    duplicates = 0
    for row in inputs:
        normalized = {key: row.get(key) for key in keys}
        identity = row["task_id"]
        if identity in by_id:
            if encode(by_id[identity]) != encode(normalized):
                raise ValueError("Conflicting accepted rows share one task_id")
            duplicates += 1
        else:
            by_id[identity] = normalized
    return [by_id[key] for key in sorted(by_id)], duplicates


def features(rows):
    keys = sorted(
        {"task_id", "language", *DERIVED_TYPES, *(key for row in rows for key in row)}
    )
    return [
        {
            "name": key,
            "dtype": DERIVED_TYPES.get(key)
            or scalar_type([row.get(key) for row in rows]),
        }
        for key in keys
    ]


def render(main, best):
    """Return only the two owned dataset indexes; empty indexes have no sentinel."""
    return {
        VIEW_PATHS[MAIN]: b"".join(
            encode(row) for row in sorted(main, key=lambda r: r["task_id"])
        ),
        VIEW_PATHS[BEST]: b"".join(
            encode(row) for row in sorted(best, key=lambda r: r["task_id"])
        ),
    }


class _UniqueYaml(yaml.SafeLoader):
    pass


def _mapping(loader, node, deep=False):
    result = {}
    for key, value in node.value:
        name = loader.construct_object(key, deep=deep)
        if name in result:
            raise ValueError("Duplicate dataset-card YAML key")
        result[name] = loader.construct_object(value, deep=deep)
    return result


_UniqueYaml.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def card_bytes(old, declared_features):
    """Register views and alias the literal legacy default without source changes."""
    header, body = old.decode().split("\n---\n", 1)
    if not header.startswith("---\n"):
        raise ValueError("Malformed dataset card")
    metadata = yaml.load(header[4:], Loader=_UniqueYaml)
    before = copy.deepcopy(metadata)
    configs = metadata.setdefault("configs", [])
    if not isinstance(configs, list):
        raise ValueError("Dataset configs must be a list")
    names = [item["config_name"] for item in configs]
    if len(set(names)) != len(names):
        raise ValueError("Duplicate dataset config")
    if "default" in names and LEGACY_DEFAULT in names:
        raise ValueError("Legacy default alias collides with an existing config")
    if any(
        item.get("default") is True
        and item["config_name"] not in {"default", MAIN, BEST}
        for item in configs
    ):
        raise ValueError("Unexpected default config cannot be silently changed")
    for item in configs:
        if item["config_name"] == "default":
            item["config_name"] = LEGACY_DEFAULT
            item.pop("default", None)
    for name in (MAIN, BEST):
        item = next((entry for entry in configs if entry["config_name"] == name), None)
        if item is None:
            item = {"config_name": name}
            configs.append(item)
        item["features"] = copy.deepcopy(declared_features)
        item["data_files"] = [{"split": "train", "path": VIEW_PATHS[name]}]
        if name == MAIN:
            item["default"] = True
        else:
            item.pop("default", None)
    for original in before.get("configs", []):
        if original["config_name"] in {MAIN, BEST}:
            continue
        expected = copy.deepcopy(original)
        if original["config_name"] == "default":
            expected["config_name"] = LEGACY_DEFAULT
            expected.pop("default", None)
        if (
            next(
                item
                for item in configs
                if item["config_name"] == expected["config_name"]
            )
            != expected
        ):
            raise ValueError("Unowned source config changed")
    if {key: val for key, val in before.items() if key != "configs"} != {
        key: val for key, val in metadata.items() if key != "configs"
    }:
        raise ValueError("Unowned metadata changed")
    return (
        "---\n"
        + yaml.safe_dump(metadata, sort_keys=False, allow_unicode=True)
        + "---\n"
        + body
    ).encode()


MODEL = {
    "model_id": TARGET_MODEL,
    "revision": "37561816e66b5b9153b1b64c10968c18c1e6f4a0",
}
_REQUIRED_GATE = {
    "static.manifest",
    "runtime.startup",
    "runtime.reward_well_formed",
    "runtime.episode_determinism",
    "semantic.oracle_max",
    "semantic.floor_gap",
    "semantic.canary_floor",
}
_NUMERIC = [key for key, kind in DERIVED_TYPES.items() if kind in {"int64", "float64"}]


def _require(condition, reason):
    if not condition:
        raise ValueError(reason)


def _document(value):
    if isinstance(value, bytes):
        return parsed(value)
    if isinstance(value, str):
        return parsed(value.encode())
    _require(isinstance(value, dict), "JSON object required")
    return copy.deepcopy(value)


def _checksums(raw):
    _require(isinstance(raw, bytes), "Audit checksums must be captured bytes")
    result = {}
    for line in raw.decode().splitlines():
        digest, name = line.split("  ", 1)
        _require(
            re.fullmatch(r"[0-9a-f]{64}", digest) and name not in result,
            "Malformed or duplicate audit checksum",
        )
        result[name] = digest
    _require(
        {"config.json", "evidence.json", "report.json"} <= set(result),
        "Audit checksum inventory is incomplete",
    )
    return result


def _inventory(value):
    inventory = _document(value)
    for name, item in inventory.items():
        _require(
            isinstance(name, str)
            and name
            and not name.startswith("/")
            and ".." not in Path(name).parts
            and "\\" not in name,
            "Unsafe full inventory path",
        )
        _require(
            isinstance(item, dict)
            and re.fullmatch(r"[0-9a-f]{64}", item.get("sha256", ""))
            and type(item.get("size")) is int
            and item["size"] >= 0,
            "Malformed full inventory member",
        )
        _require(
            isinstance(item.get("mode"), str)
            and re.fullmatch(r"0o[0-7]{3}", item["mode"]),
            "Full POSIX mode inventory required",
        )
    _require(
        inventory
        and {"task.toml", "instruction.md", "solution/solve.sh", "tests/test.sh"}
        <= set(inventory),
        "Full native task/control inventory required",
    )
    digest = sha(
        json.dumps(
            inventory, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
    )
    return inventory, digest


def bind_result(record, rows_by_id):
    """Validate published result, task modes, reused gate, images and model tuple."""
    raw = record["summary"]
    _require(isinstance(raw, bytes), "Summary must retain its published raw bytes")
    summary = _document(raw)
    _require(isinstance(summary, dict), "Published summary must be an object")
    locator = _document(record["summary_locator"])
    _require(sha(raw) == locator.get("summary_sha256"), "Summary locator hash mismatch")
    _require(
        re.fullmatch(r"[0-9a-f]{40}", locator.get("summary_revision", "")),
        "Immutable summary revision required",
    )
    _require(
        isinstance(summary.get("protocol_id"), str)
        and summary["protocol_id"].startswith(PROTOCOL_PREFIX)
        and summary["protocol_id"] == locator.get("protocol_id"),
        "Different Qwen protocol",
    )
    row = rows_by_id[locator["task_id"]]
    config_raw = record["audit_config_bytes"]
    _require(
        isinstance(config_raw, bytes),
        "Audit config must retain its published raw bytes",
    )
    sums = _checksums(record["audit_sha256sums"])
    _require(sums["config.json"] == sha(config_raw), "Audit config checksum mismatch")
    config = _document(config_raw)
    _require(
        re.fullmatch(r"[0-9a-f]{40}", summary.get("revision", "")),
        "Immutable audit revision required",
    )
    _require(
        isinstance(summary.get("run_id"), str)
        and re.fullmatch(r"coding-[0-9a-f]{64}", summary["run_id"]),
        "Malformed audit run identity",
    )
    _require(
        isinstance(summary.get("measurement_key"), str)
        and re.fullmatch(r"[0-9a-f]{64}", summary["measurement_key"]),
        "Malformed measurement identity",
    )
    prefix = f"results/qwen-difficulty-auto-v1/{summary['measurement_key']}/{summary['run_id']}"
    old_path = f"{prefix}/collections/{sha(raw)}/summary.json"
    manifest_carrier = bool(
        re.fullmatch(
            re.escape(prefix) + r"/manifest-collections-v1/[0-9a-f]{64}/summary\.json",
            locator.get("summary_path", ""),
        )
    )
    _require(
        locator.get("summary_path") == old_path or manifest_carrier,
        "Summary path/run identity mismatch",
    )
    if manifest_carrier:
        _require(
            summary.get("evidence_layout") == "immutable-worker-manifest-native-v1"
            and summary.get("evidence_manifest_path")
            == str(
                Path(locator["summary_path"]).parent / "worker-artifact-manifest.json"
            ),
            "Manifest-carried summary layout/path mismatch",
        )
    target = config["target"]
    _require(
        all(target.get(key) == value for key, value in MODEL.items())
        and isinstance(target.get("provider"), str)
        and bool(target["provider"].strip()),
        "Different target model identity",
    )
    _require(
        target.get("enable_thinking") is False
        and type(target.get("max_steps")) is int
        and target["max_steps"] == 48
        and type(target.get("max_tokens")) is int
        and target["max_tokens"] == 65536
        and type(target.get("max_total_tokens")) is int
        and target["max_total_tokens"] == 2000000
        and type(target.get("temperature")) in {int, float}
        and target["temperature"] == 0.7,
        "Effective R3 target settings differ",
    )
    execution = config["execution"]
    inventory, inv_sha = _inventory(record["task_inventory"])
    _require(
        inv_sha
        == row["task_inventory_sha256"]
        == execution.get("expected_task_inventory_sha256"),
        "Full task mode inventory mismatch",
    )
    _require(
        execution.get("expected_task_digest") == row["task_source_sha256"],
        "Full task source mismatch",
    )
    dependency_lock = row.get("dependency_lock_sha256")
    if dependency_lock is not None:
        _require(
            re.fullmatch(r"[0-9a-f]{64}", dependency_lock)
            and execution.get("dependency_lock_sha256") == dependency_lock,
            "Python dependency lock identity mismatch",
        )
    source = summary["source"]
    _require(
        source.get("kind") == "hf"
        and source.get("repo_id") == "harness-hub/agentic-coding-envs"
        and source.get("task_path") == row["task_path"],
        "Summary task source locator mismatch",
    )
    _require(
        re.fullmatch(r"[0-9a-f]{40}", source.get("revision", "")),
        "Immutable task source revision required",
    )
    _require(
        source.get("task_file_hashes")
        == {name: item["sha256"] for name, item in inventory.items()},
        "Summary full source file map mismatch",
    )
    gate_raw = record["source_gate_report_bytes"]
    _require(
        isinstance(gate_raw, bytes), "Source gate must retain its immutable raw bytes"
    )
    gate = _document(gate_raw)
    controls_metadata_absent = "source_controls" not in summary
    reference = summary.get("source_controls")
    if controls_metadata_absent:
        _require(
            summary.get("status") == "incomplete"
            and all(
                name in summary and summary[name] is None
                for name in (
                    "solve_count",
                    "solve_rate",
                    "solve_rate_wilson95",
                    "difficulty",
                    "difficulty_wilson95",
                )
            ),
            "Only an unmeasured incomplete summary may omit duplicate control metadata",
        )
    else:
        _require(
            isinstance(reference, dict),
            "Source-control summary metadata must be an object",
        )
    declared = config["source_gate"]
    _require(
        gate_raw == declared["report_json"].encode()
        and sha(gate_raw) == declared.get("report_sha256"),
        "Immutable source-control report hash mismatch",
    )
    _require(
        declared.get("report_path") == row["gate_report_path"]
        and declared.get("repo_id") == source["repo_id"],
        "Source-control locator mismatch",
    )
    if reference is not None:
        _require(
            sha(gate_raw) == reference.get("immutable_report_sha256")
            and declared.get("report_path") == reference.get("immutable_report_path")
            and declared.get("revision") == reference.get("immutable_report_revision"),
            "Summary source-control identity mismatch",
        )
    _require(
        re.fullmatch(r"[0-9a-f]{40}", declared.get("revision", "")),
        "Immutable source-control revision required",
    )
    _require(
        gate.get("task_digest") == row["task_source_sha256"]
        and gate.get("task_inventory_sha256") == inv_sha
        and gate.get("task_files") == inventory,
        "Source gate task/control inventory mismatch",
    )
    image = gate.get("image_ref")
    _require(
        isinstance(image, str)
        and re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", image)
        and execution.get("agent_image") == image == execution.get("verifier_image"),
        "Agent/verifier image identity mismatch",
    )
    checks = {item["check_id"]: item["status"] for item in gate["results"]}
    _require(
        len(checks) == len(gate["results"])
        and _REQUIRED_GATE <= set(checks)
        and all(checks[name] == "pass" for name in _REQUIRED_GATE)
        and not any(status in {"fail", "error"} for status in checks.values())
        and gate.get("admitted") is True,
        "Source semantic gate is not accepted",
    )
    carrier_proof = None
    if manifest_carrier:
        carrier_proof = bind_worker_manifest(
            record, summary, locator, inventory, config_raw, sums
        )
    witness = {
        "task_id": row["task_id"],
        "task_source_sha256": row["task_source_sha256"],
        "task_inventory_sha256": inv_sha,
        "agent_image": image,
        "verifier_image": image,
        "source_gate_sha256": sha(gate_raw),
        "controls_metadata_absent": controls_metadata_absent,
        "summary_sha256": sha(raw),
        "summary_revision": locator["summary_revision"],
        "summary_path": locator["summary_path"],
        "audit_revision": summary["revision"],
        "audit_config_sha256": sha(config_raw),
        "audit_checksums_sha256": sha(record["audit_sha256sums"]),
        "model": {key: target[key] for key in (*MODEL, "provider")},
        "protocol": summary["protocol_id"],
        "dependency_lock_sha256": dependency_lock,
        "run_id": summary["run_id"],
        "worker_manifest": carrier_proof,
    }
    return row, summary, config, witness


def complete_metrics(summary, config):
    """Copy one complete four/eight-valid run; qualification flags are separate."""
    _require(summary.get("status") == "complete", "Result is not complete")
    for name in (
        "artifacts_verified",
        "cleanup_verified",
        "full_task_inventory_verified",
        "protocol_effective_verified",
        "thinking_disabled_verified",
    ):
        _require(summary.get(name) is True, "Result verification is incomplete")
    count = summary.get("planned_attempts")
    _require(
        type(count) is int
        and count in {4, 8}
        and type(summary.get("valid_attempts")) is int
        and summary["valid_attempts"] == count,
        "A complete planned four- or eight-attempt run is required",
    )
    stats = summary["target_statistics"]
    replay = summary["replay"]
    _require(
        replay.get("accepted") is True
        and replay.get("verdict") == "pass"
        and replay["checks"]["fresh_target_reliability"]["status"] == "pass"
        and replay["checks"]["target_difficulty"] == stats,
        "Target evidence replay is incomplete",
    )
    _require(
        stats.get("status") == "pass"
        and all(
            type(stats.get(key)) is int and stats[key] == value
            for key, value in {
                "attempted": count,
                "completed": count,
                "failed": 0,
                "missing": 0,
                "infrastructure_errors": 0,
            }.items()
        ),
        "Target snapshot is partial or contains errors",
    )
    seeds = config["seeds"]
    _require(
        isinstance(seeds, list)
        and len(seeds) == count
        and all(type(seed) is int for seed in seeds)
        and len(set(seeds)) == count
        and type(config["validation"]["target_attempts"]) is int
        and config["validation"]["target_attempts"] == count,
        "Target attempt declaration is incomplete",
    )
    solved = summary["solve_count"]
    _require(
        type(solved) is int
        and 0 <= solved <= count
        and type(stats.get("solve_count")) is int
        and stats["solve_count"] == solved,
        "Malformed solve count",
    )
    rate = solved / count
    _require(
        type(summary.get("solve_rate")) in {int, float}
        and type(stats.get("solve_rate")) in {int, float}
        and summary["solve_rate"] == rate == stats.get("solve_rate")
        and type(summary.get("difficulty")) in {int, float}
        and summary["difficulty"] == 1 - rate,
        "Inconsistent solve rate or difficulty",
    )
    interval = summary["solve_rate_wilson95"]
    _require(
        isinstance(interval, list)
        and len(interval) == 2
        and all(type(v) in {int, float} and math.isfinite(v) for v in interval)
        and 0 <= interval[0] <= rate <= interval[1] <= 1
        and stats.get("solve_rate_wilson95") == interval,
        "Malformed confidence interval",
    )
    z = 1.959963984540054
    center = (rate + z * z / (2 * count)) / (1 + z * z / count)
    half = (
        z
        * math.sqrt(rate * (1 - rate) / count + z * z / (4 * count * count))
        / (1 + z * z / count)
    )
    _require(
        all(
            math.isclose(a, b, rel_tol=0, abs_tol=1e-12)
            for a, b in zip(interval, (max(0, center - half), min(1, center + half)))
        ),
        "Confidence interval differs from the complete attempt snapshot",
    )
    return {
        "qwen_solved": solved,
        "qwen_valid_attempts": count,
        "qwen_solve_rate": rate,
        "qwen_wilson95_low": interval[0],
        "qwen_wilson95_high": interval[1],
        "qwen_difficulty": 1 - rate,
    }


def _published(raw, locator):
    _require(isinstance(raw, bytes), "Published object bytes are required")
    locator = _document(locator)
    _require(
        locator.get("repo_id") == "harness-hub/agentic-coding-envs"
        and re.fullmatch(r"[0-9a-f]{40}", locator.get("revision", ""))
        and locator.get("sha256") == sha(raw)
        and isinstance(locator.get("path"), str)
        and locator["path"]
        and not Path(locator["path"]).is_absolute()
        and ".." not in Path(locator["path"]).parts
        and "\\" not in locator["path"],
        "Published object locator/hash mismatch",
    )
    document = _document(raw)
    _require(isinstance(document, dict), "Published object must be a JSON object")
    return document, locator


def bind_worker_manifest(record, summary, summary_locator, inventory, config_raw, sums):
    """Bind a manifest carrier to exact worker audit bytes and source modes."""
    manifest, locator = _published(
        record["worker_manifest_bytes"], record["worker_manifest_locator"]
    )
    _require(
        locator["revision"] == summary_locator["summary_revision"]
        and locator["path"] == summary["evidence_manifest_path"]
        and manifest.get("schema") == "qwen-immutable-worker-evidence-manifest-v1"
        and manifest.get("layout") == summary["evidence_layout"]
        and manifest.get("repo_id") == locator["repo_id"]
        and manifest.get("measurement_key") == summary["measurement_key"]
        and manifest.get("run_id") == summary["run_id"]
        and manifest.get("bundle_sha256") == summary["run_id"].removeprefix("coding-")
        and manifest.get("worker_revision")
        == summary["revision"]
        == summary.get("worker_artifact_revision")
        and manifest.get("private_worker_artifacts") is True,
        "Worker manifest immutable identity mismatch",
    )
    files = manifest["files"]
    _require(
        isinstance(files, dict)
        and {"audit/SHA256SUMS", *("audit/" + name for name in sums)} <= set(files)
        and set(files) - {"audit/SHA256SUMS", *("audit/" + name for name in sums)}
        <= {"claim.json", "cloud-report.json", "submission.json"},
        "Worker manifest audit inventory mismatch",
    )
    for name, item in files.items():
        _require(
            not Path(name).is_absolute()
            and ".." not in Path(name).parts
            and "\\" not in name
            and item.get("path") == f"runs/{summary['run_id']}/{name}"
            and type(item.get("bytes")) is int
            and item["bytes"] >= 0
            and re.fullmatch(r"[0-9a-f]{64}", item.get("sha256", "")),
            "Malformed worker manifest artifact identity",
        )
        if name.startswith("audit/") and name != "audit/SHA256SUMS":
            _require(
                item["sha256"] == sums[name.removeprefix("audit/")],
                "Worker artifact checksum differs from audit inventory",
            )
    for name, raw in [
        ("audit/config.json", config_raw),
        ("audit/SHA256SUMS", record["audit_sha256sums"]),
    ]:
        _require(
            files[name]["sha256"] == sha(raw) and files[name]["bytes"] == len(raw),
            "Worker manifest captured audit bytes differ",
        )
    expected_source = {
        name: {
            "sha256": item["sha256"],
            "bytes": item["size"],
            "mode": int(item["mode"], 8),
        }
        for name, item in inventory.items()
    }
    _require(
        manifest.get("source_files") == expected_source,
        "Worker manifest full task source/modes differ",
    )
    return {
        "locator": locator,
        "worker_revision": manifest["worker_revision"],
        "layout": manifest["layout"],
        "audit_files": len(files),
        "source_files": len(expected_source),
    }


def bind_claim(record, rows_by_id, *, allow_legacy=False):
    """Bind persisted claim content; scoring does not imply an active paid Job."""
    claim, locator = _published(record["claim_bytes"], record["claim_locator"])
    _require(
        claim.get("schema") == "openenv-qwen-logical-claim-v1",
        "Unsupported logical claim",
    )
    identity = claim["identity"]
    row = rows_by_id[identity["task_id"]]
    protocol = claim.get("protocol_id")
    key = claim.get("measurement_key")
    _require(
        isinstance(protocol, str)
        and protocol.startswith(PROTOCOL_PREFIX)
        and protocol == identity.get("protocol_id")
        and re.fullmatch(r"[0-9a-f]{64}", key or "")
        and key == identity.get("measurement_key")
        and locator["path"].startswith("evaluations/qwen38/claims/")
        and key in locator["path"],
        "Logical claim protocol/measurement locator differs",
    )
    attempts = claim["planned_attempt_ids"]
    _require(
        isinstance(attempts, list)
        and len(attempts) in {4, 8}
        and all(type(attempt) is int for attempt in attempts)
        and len(set(attempts)) == len(attempts),
        "Logical claim attempt declaration differs",
    )
    native = {}
    for name, item in identity["files"].items():
        _require(
            type(item.get("bytes")) is int
            and type(item.get("mode")) is int
            and 0 <= item["mode"] <= 0o777,
            "Malformed logical claim inventory",
        )
        native[name] = {
            "sha256": item["sha256"],
            "size": item["bytes"],
            "mode": oct(item["mode"]),
        }
    inventory, inventory_sha = _inventory(native)
    metadata = identity.get("source_metadata")
    profile = claim.get("control_profile")
    python_queued = (
        row["language"] == "python"
        and isinstance(profile, str)
        and profile.startswith(
            (
                "harbor-python-semantic-gate-targets",
                "harbor-python-native-suite-targets",
            )
        )
        and identity.get("control_profile") == profile
        and not {
            "source_metadata",
            "candidate_optional_gate_identity",
            "registration",
            "starter_source_receipt",
        }.intersection(identity)
    )
    _require(
        (
            isinstance(metadata, dict)
            or (allow_legacy or python_queued)
            and metadata is None
        )
        and (
            metadata is None
            or (
                all(metadata.get(name) == row.get(name) for name in metadata)
                and metadata.get("task_id") == row["task_id"]
                and metadata.get("target_model") == TARGET_MODEL
                and metadata.get("task_source_sha256") == row["task_source_sha256"]
            )
        )
        and inventory_sha
        == row["task_inventory_sha256"]
        == identity.get("full_task_inventory_sha256"),
        "Logical claim accepted source/mode identity differs",
    )
    source = identity["source"]
    _require(
        source.get("kind") == "hf"
        and source.get("repo_id") == "harness-hub/agentic-coding-envs"
        and re.fullmatch(r"[0-9a-f]{40}", source.get("revision", ""))
        and source.get("task_path") == row["task_path"]
        and source.get("task_file_hashes")
        == {name: item["sha256"] for name, item in inventory.items()},
        "Logical claim full task source differs",
    )
    if python_queued:
        # A frozen queued intent is not an assertion of an executed image or gate.
        gate = None
    elif "candidate_optional_gate_identity" in identity:
        gate = identity["candidate_optional_gate_identity"]
        _require(
            gate.get("repo_id") == source["repo_id"]
            and gate.get("report_path") == row["gate_report_path"]
            and re.fullmatch(r"[0-9a-f]{40}", gate.get("revision", ""))
            and re.fullmatch(r"[0-9a-f]{64}", gate.get("report_sha256", "")),
            "Logical claim source-control identity differs",
        )
        registration = identity["registration"]
        _require(
            registration.get("config") in CONFIGS
            and CONFIGS[registration["config"]] == row["language"]
            and registration.get("split") == "accepted",
            "Logical claim source registration differs",
        )
    else:
        _require(
            allow_legacy
            and identity.get("gate_seven_pass") is True
            and re.fullmatch(r"[0-9a-f]{64}", identity.get("gate_report_sha256", "")),
            "Legacy phase claim requires its actual declared semantic gate",
        )
        gate = {
            "report_sha256": identity["gate_report_sha256"],
            "gate_seven_pass": True,
            "legacy_locator_unavailable": True,
        }
    image = None
    if not python_queued:
        image = identity["starter_source_receipt"]["image"]
        _require(
            isinstance(image, str)
            and re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", image)
            and identity["starter_source_receipt"].get("registry_digest")
            == image.rsplit("@", 1)[1],
            "Logical claim immutable image identity differs",
        )
    _require(
        re.fullmatch(r"[0-9a-f]{64}", identity.get("effective_config_sha256", "")),
        "Logical claim effective configuration identity differs",
    )
    _require(
        re.fullmatch(r"[0-9a-f]{64}", identity.get("bundle_sha256", ""))
        and identity.get("run_id") == "coding-" + identity["bundle_sha256"],
        "Logical claim bundle/run identity differs",
    )
    return row, {
        "task_id": row["task_id"],
        "task_source_sha256": row["task_source_sha256"],
        "task_inventory_sha256": inventory_sha,
        "protocol": protocol,
        "measurement_key": key,
        "run_id": identity["run_id"],
        "claim_locator": locator,
        "image_ref": image,
        "effective_config_sha256": identity["effective_config_sha256"],
        "source_gate_identity": gate,
        "planned_attempts": len(attempts),
        "status_basis": "logical_claim_persisted; execution_state_unobserved",
        "execution_state_observed": False,
        "python_queued_intent_without_image_evidence": python_queued,
    }


def bind_phase_catalog(envelope, rows_by_id):
    """Join owner-observed terminal errors without inventing model outcomes."""
    if envelope is None:
        return {}, {"status": "unavailable"}
    catalog, locator = _published(
        envelope["catalog_bytes"], envelope["catalog_locator"]
    )
    _require(
        catalog.get("schema") == "qwen-terminal-phase-catalog-v1"
        and catalog.get("repo_id") == locator["repo_id"]
        and catalog.get("not_source") is True
        and re.fullmatch(r"[0-9a-f]{40}", catalog.get("claim_read_revision", ""))
        and re.fullmatch(
            r"results/qwen-difficulty-auto-v1/phase-catalog-v1/[0-9a-f]{64}/catalog\.json",
            locator["path"],
        ),
        "Unsupported owner phase catalog",
    )

    def indexed(records, raw_key, locator_key):
        result = {}
        for record in records:
            document, reference = _published(record[raw_key], record[locator_key])
            address = (reference["repo_id"], reference["revision"], reference["path"])
            _require(
                address not in result or result[address][0] == record[raw_key],
                "Conflicting captured phase artifact",
            )
            result[address] = (record[raw_key], reference, document, record)
        return result

    claims = indexed(envelope["claim_records"], "claim_bytes", "claim_locator")
    summaries = indexed(
        envelope.get("summary_records", []), "summary_bytes", "summary_locator"
    )

    def exact(reference, records):
        address = (reference["repo_id"], reference["revision"], reference["path"])
        _require(address in records, "Declared phase artifact was not captured")
        result = records[address]
        _require(reference == result[1], "Phase artifact locator/hash mismatch")
        return result

    result, seen = {}, set()
    for phase in catalog["rows"]:
        claim_raw, claim_locator, claim, claim_record = exact(phase["claim"], claims)
        row, witness = bind_claim(claim_record, rows_by_id, allow_legacy=True)
        key = witness["measurement_key"]
        _require(
            key not in seen
            and phase.get("raw_claim") == claim
            and phase.get("task_id") == row["task_id"]
            and phase.get("measurement_key") == key
            and phase.get("run_id") == witness["run_id"]
            and phase.get("protocol_id") == witness["protocol"]
            and claim_locator["revision"] == catalog["claim_read_revision"]
            and phase.get("status") == "incomplete"
            and phase.get("phase") == "controller_terminal_ERROR"
            and phase.get("difficulty") is None
            and phase.get("model_outcome_inferred") is False
            and phase.get("missing_artifacts_never_zero") is True,
            "Owner phase/claim identity mismatch",
        )
        seen.add(key)
        controller = phase["controller"]
        _require(
            re.fullmatch(r"[0-9a-f]{24}", controller.get("id", ""))
            and controller.get("identity_verified") is True
            and controller.get("status") == "ERROR"
            and controller.get("owner") == "burtenshaw"
            and controller.get("image")
            == "docker.io/library/python@sha256:48d884813cf44e927cf64c5529dd630dd3b18338c6dc727991eef9b71e934a20"
            and controller.get("labels", {}).get("openenv_bundle")
            == witness["run_id"].removeprefix("coding-"),
            "Owner terminal controller identity mismatch",
        )
        summary_proof = None
        if phase.get("summary") is not None:
            _, summary_proof, summary, _ = exact(phase["summary"], summaries)
            _require(
                summary.get("status") == phase["status"]
                and summary.get("measurement_key") == key
                and summary.get("run_id") == witness["run_id"]
                and summary.get("protocol_id") == witness["protocol"]
                and summary.get("difficulty") is None,
                "Published incomplete summary identity/status mismatch",
            )
            _require(
                summary_proof["path"]
                == f"results/qwen-difficulty-auto-v1/{key}/{witness['run_id']}/collections/{summary_proof['sha256']}/summary.json",
                "Published incomplete summary path mismatch",
            )
        witness.update(
            status_basis="owner_terminal_phase_catalog; model_outcome_unmeasured",
            execution_state_observed=True,
            controller=copy.deepcopy(controller),
            catalog_locator=copy.deepcopy(locator),
            incomplete_summary_locator=summary_proof,
            incomplete_summary_explicitly_absent=phase.get("summary") is None,
            cleanup_qualification_upgraded=False,
        )
        result.setdefault(row["task_id"], []).append(witness)
    return result, {
        "status": "verified",
        "locator": locator,
        "bound_rows": len(seen),
        "numeric_outcomes_inferred": False,
        "cleanup_qualification_upgraded": False,
    }


def bind_sample(sample, rows_by_id):
    """Use the owner's published SRS roster and seed, never infer membership."""
    if sample is None:
        return None, {"status": "unavailable"}
    document, locator = _published(sample["sample_bytes"], sample["sample_locator"])
    seed, seed_locator = _published(sample["seed_bytes"], sample["seed_locator"])
    _require(
        document.get("schema") == "repository-srs6-v1"
        and seed.get("schema") == "public-srs-seed-v1"
        and document.get("outcomes_used_for_selection") is False
        and seed.get("outcome_lookup_performed") is False
        and seed.get("seed_is_public_not_credential") is True
        and re.fullmatch(r"[0-9a-f]{64}", seed.get("seed_hex", ""))
        and re.fullmatch(r"[0-9a-f]{40}", seed.get("source_revision", ""))
        and document.get("revision") == seed["source_revision"]
        and type(document.get("population_count")) is int
        and document["population_count"] > 0
        and document["population_count"] == seed["expected_population"]["total"]
        and document["seed_receipt"]["sha256"] == sha(sample["seed_bytes"])
        and str(Path(locator["path"]).parent / document["seed_receipt"]["path"])
        == seed_locator["path"],
        "Published sample population/seed binding mismatch",
    )
    units = document["units"]
    _require(
        isinstance(units, list)
        and type(document.get("sample_count")) is int
        and len(units) == document["sample_count"],
        "Published sample count mismatch",
    )
    ids = set()
    for unit in units:
        identity = unit["task_id"]
        _require(
            isinstance(identity, str) and identity and identity not in ids,
            "Published sample IDs must be unique",
        )
        ids.add(identity)
        digest = unit["native_inventory"]["full_inventory_canonical_sha256"]
        _require(
            re.fullmatch(r"[0-9a-f]{64}", digest)
            and type(unit["native_inventory"].get("files")) is int
            and unit["native_inventory"]["files"] > 0
            and unit["row"]["task_id"] == identity
            and unit["identity"]["task_inventory_sha256"]
            == unit["row"]["task_inventory_sha256"]
            == unit["native_inventory"]["full_inventory_canonical_sha256"]
            == digest
            and unit["identity"]["task_source_sha256"]
            == unit["row"]["task_source_sha256"]
            and re.fullmatch(r"[0-9a-f]{64}", unit["unit_identity_sha256"]),
            "Published sample task source/mode identity mismatch",
        )
        rank = sha(
            b"openenv-qwen-srs6-v1\0"
            + bytes.fromhex(seed["seed_hex"])
            + bytes.fromhex(unit["unit_identity_sha256"])
        )
        _require(rank == unit["rank_sha256"], "Published sample rank/seed mismatch")
        if identity in rows_by_id:
            row = rows_by_id[identity]
            _require(
                all(row.get(key) == value for key, value in unit["row"].items()),
                "Sampled task changed since the frozen population",
            )
    selected_proof = None
    if "selected_task_ids_bytes" in sample:
        selected, selected_proof = _published(
            sample["selected_task_ids_bytes"], sample["selected_task_ids_locator"]
        )
        selected_ids = [
            identity for values in selected["by_repo"].values() for identity in values
        ]
        _require(
            selected.get("revision") == document["revision"]
            and selected.get("sample_sha256") == sha(sample["sample_bytes"])
            and len(selected_ids) == len(ids)
            and set(selected_ids) == ids,
            "Published selected-ID roster mismatch",
        )
    return ids, {
        "status": "verified",
        "population_revision": document["revision"],
        "population_count": document["population_count"],
        "sample_count": len(ids),
        "seed_hex": seed["seed_hex"],
        "seed_recorded_at": seed.get("recorded_at"),
        "drawn_at": document.get("drawn_at"),
        "sample_locator": locator,
        "seed_locator": seed_locator,
        "selected_task_ids_locator": selected_proof,
        "membership_scope": "Selected IDs in the owner's frozen population; later nonselected IDs are false. No outcome or attempt-count inference.",
    }


def derive(
    accepted_capture, result_records=(), claims=(), sample=None, phase_catalog=None
):
    """Build views without remote access, qualification upgrades or attempt pooling."""
    accepted_capture = copy.deepcopy(accepted_capture)
    result_records = copy.deepcopy(tuple(result_records))
    claims = copy.deepcopy(tuple(claims))
    sample = copy.deepcopy(sample)
    phase_catalog = copy.deepcopy(phase_catalog)
    source_rows, duplicates = unify(accepted_capture)
    by_id = {row["task_id"]: row for row in source_rows}
    sample_ids, sample_proof = bind_sample(sample, by_id)
    phase_candidates, phase_proof = bind_phase_catalog(phase_catalog, by_id)
    candidates = {}
    rejected = []
    for record in result_records:
        try:
            row, summary, config, witness = bind_result(record, by_id)
        except (ValueError, KeyError, TypeError, UnicodeError, OverflowError):
            rejected.append(
                {
                    "reason": "result_identity_or_artifact_binding_rejected",
                    "summary_sha256": sha(record["summary"])
                    if isinstance(record.get("summary"), bytes)
                    else None,
                }
            )
            continue
        try:
            metrics = complete_metrics(summary, config)
            status = "scored"
        except (ValueError, KeyError, TypeError, OverflowError):
            metrics = {key: None for key in _NUMERIC}
            status = "incomplete"
        candidates.setdefault(row["task_id"], []).append(
            {"status": status, "metrics": metrics, "witness": witness}
        )
    claim_candidates = {}
    claim_hashes = {}
    for record in claims:
        try:
            claimed_row, witness = bind_claim(record, by_id)
        except (ValueError, KeyError, TypeError, UnicodeError, OverflowError):
            rejected.append(
                {
                    "reason": "logical_claim_identity_or_artifact_binding_rejected",
                    "claim_sha256": sha(record["claim_bytes"])
                    if isinstance(record.get("claim_bytes"), bytes)
                    else None,
                }
            )
            continue
        key = witness["measurement_key"]
        digest = witness["claim_locator"]["sha256"]
        _require(
            key not in claim_hashes or claim_hashes[key] == digest,
            "Conflicting persisted logical claims share one measurement key",
        )
        claim_hashes[key] = digest
        claim_candidates.setdefault(claimed_row["task_id"], []).append(witness)
    main, selections = [], []
    for original in source_rows:
        row_id = original["task_id"]
        row = {
            **original,
            **{key: None for key in _NUMERIC},
            "qwen_protocol": None,
            "qwen_status": "not_started",
            "generated_alternatives_run": False,
            "leak_audit_run": False,
            "in_stratified_sample": (
                row_id in sample_ids if sample_ids is not None else None
            ),
        }
        available = candidates.get(row["task_id"], [])
        if available:
            # Choose one independent run, never the best score and never combined attempts.
            chosen = min(
                available,
                key=lambda item: (
                    item["status"] != "scored",
                    item["witness"]["run_id"],
                    item["witness"]["summary_sha256"],
                ),
            )
            row.update(
                chosen["metrics"],
                qwen_status=chosen["status"],
                qwen_protocol=chosen["witness"]["protocol"],
            )
            selections.append(chosen["witness"])
        elif phase_candidates.get(row["task_id"]):
            phase = min(
                phase_candidates[row["task_id"]],
                key=lambda item: item["measurement_key"],
            )
            row.update(qwen_status="incomplete", qwen_protocol=phase["protocol"])
            selections.append(phase)
        elif claim_candidates.get(row["task_id"]):
            claimed = min(
                claim_candidates[row["task_id"]],
                key=lambda item: (
                    item["measurement_key"],
                    item["claim_locator"]["sha256"],
                ),
            )
            row.update(qwen_status="scoring", qwen_protocol=claimed["protocol"])
            selections.append(claimed)
        main.append(row)
    best = [
        row
        for row in main
        if row["qwen_status"] == "scored"
        and type(row["qwen_solved"]) is int
        and row["qwen_valid_attempts"] in {4, 8}
        and 0 < row["qwen_solved"] < row["qwen_valid_attempts"]
    ]
    counts = {
        name: sum(row["qwen_status"] == name for row in main)
        for name in ("scored", "scoring", "incomplete", "not_started")
    }
    summary = {
        "tasks": len(main),
        "best_tasks": len(best),
        "duplicates_collapsed": duplicates,
        "qwen_protocol_prefix": PROTOCOL_PREFIX,
        "qwen_status_counts": counts,
        "per_language": {
            name: sum(row["language"] == name for row in main)
            for name in sorted(CONFIGS.values())
        },
        "generated_alternatives_run": False,
        "leak_audit_run": False,
        "qualification_upgraded": False,
    }
    proof = {
        "accepted_capture_canonical_sha256": sha(encode(accepted_capture)),
        "accepted_revision": accepted_capture.get("revision"),
        "source_indexes": copy.deepcopy(accepted_capture.get("index_sha256", {})),
        "stratified_sample": sample_proof,
        "phase_catalog": phase_proof,
        "bound_claims": [
            item
            for key in sorted(claim_candidates)
            for item in sorted(
                claim_candidates[key],
                key=lambda value: value["claim_locator"]["sha256"],
            )
        ],
        "scoring_status_semantics": "Persisted content-bound logical claim: claimed, queued, running, or awaiting authoritative reconciliation. Not a claim that paid Jobs are currently running.",
        "selected_results": selections,
        "rejected_results": sorted(rejected, key=lambda item: encode(item)),
        "selection_policy": "Prefer one complete matching run; tie-break by run_id then summary_sha256, independent of score. Never pool attempts.",
    }
    return {
        "rows": {MAIN: main, BEST: best},
        "files": render(main, best),
        "features": features(main),
        "summary": summary,
        "proof": proof,
    }


def write_local(output, result):
    """Write only owned view indexes and local proof/summary, never source splits."""
    output = Path(output)
    for name, raw in result["files"].items():
        _require(name in VIEW_PATHS.values(), "Unexpected derived output path")
        path = output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    output.mkdir(parents=True, exist_ok=True)
    (output / "capture-proof.json").write_bytes(encode(result["proof"]))
    (output / "summary.json").write_bytes(encode(result["summary"]))


def _local_bytes(directory, name):
    local = Path(name)
    _require(
        not local.is_absolute() and ".." not in local.parts,
        "Result paths must stay in the captured input directory",
    )
    source = directory / local
    _require(
        not source.is_symlink()
        and not any(parent.is_symlink() for parent in source.parents),
        "Captured result links are unsupported",
    )
    return source.read_bytes()


def read_result_manifest(path):
    """Read a local captured-byte manifest; no URL or network fetching occurs."""
    path = Path(path)
    manifest = parsed(path.read_bytes())
    records = []
    for item in manifest.get("records", []):
        record = {}
        for key in (
            "summary",
            "summary_locator",
            "audit_config_bytes",
            "audit_sha256sums",
            "source_gate_report_bytes",
            "task_inventory",
        ):
            raw = _local_bytes(path.parent, item[key])
            record[key] = (
                parsed(raw) if key in {"summary_locator", "task_inventory"} else raw
            )
        for key in ("worker_manifest_bytes", "worker_manifest_locator"):
            if key in item:
                raw = _local_bytes(path.parent, item[key])
                record[key] = parsed(raw) if key.endswith("_locator") else raw
        records.append(record)
    claims = [
        {
            "claim_bytes": _local_bytes(path.parent, item["claim_bytes"]),
            "claim_locator": parsed(_local_bytes(path.parent, item["claim_locator"])),
        }
        for item in manifest.get("claims", [])
    ]
    return records, claims


def read_sample_manifest(path):
    """Read the optional captured published roster and seed from local files."""
    path = Path(path)
    manifest = parsed(path.read_bytes())
    result = {}
    for key in (
        "sample_bytes",
        "sample_locator",
        "seed_bytes",
        "seed_locator",
        "selected_task_ids_bytes",
        "selected_task_ids_locator",
    ):
        if key in manifest:
            raw = _local_bytes(path.parent, manifest[key])
            result[key] = parsed(raw) if key.endswith("_locator") else raw
    return result


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--accepted-capture", type=Path, required=True)
    parser.add_argument("--results-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sample-manifest", type=Path)
    args = parser.parse_args()
    records, claims = read_result_manifest(args.results_manifest)
    sample = (
        read_sample_manifest(args.sample_manifest) if args.sample_manifest else None
    )
    result = derive(parsed(args.accepted_capture.read_bytes()), records, claims, sample)
    write_local(args.output, result)
    print(json.dumps(result["summary"], sort_keys=True))
