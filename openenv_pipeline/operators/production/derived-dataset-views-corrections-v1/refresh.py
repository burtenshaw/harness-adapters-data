"""Immutable scoped capture and owner-reviewed derived dataset refresh."""

import hashlib
import json
import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path, PurePosixPath

import yaml
from huggingface_hub import HfApi, hf_hub_download
from huggingface_hub.errors import EntryNotFoundError

HERE = Path(__file__).resolve().parent
REPO = "harness-hub/agentic-coding-envs"
ACCEPTED_CONFIGS = ("scale800_gate_v1", "scale800_py_gate_v1")
LANGUAGES = dict(zip(ACCEPTED_CONFIGS, ("go", "python")))
RESULT_PREFIX = "results/qwen-difficulty-auto-v1"
CLAIM_PREFIX = "evaluations/qwen38/claims"
PROTOCOL_PREFIX = "qwen38-auto48-64k-2m-nothink"
MAX_CATALOG_ENTRIES = 20000
MAX_FILE_BYTES = 16 * 1024**2
SECTION_BEGIN = b"<!-- BEGIN OPENENV DERIVED VIEWS -->"
SECTION_END = b"<!-- END OPENENV DERIVED VIEWS -->"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return (
        json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n"
    ).encode()


def parsed(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "Duplicate JSON key")
            result[key] = value
        return result

    return json.loads(raw, object_pairs_hook=unique)


class UniqueYaml(yaml.SafeLoader):
    pass


def _yaml_mapping(loader, node, deep=False):
    result = {}
    for key, value in node.value:
        name = loader.construct_object(key, deep=deep)
        require(name not in result, "Duplicate card YAML key")
        result[name] = loader.construct_object(value, deep=deep)
    return result


UniqueYaml.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _yaml_mapping
)


def metadata(raw):
    head, body = raw.decode().split("\n---\n", 1)
    require(head.startswith("---\n"), "Dataset YAML card required")
    result = yaml.load(head[4:], Loader=UniqueYaml)
    require(isinstance(result, dict), "Dataset metadata object required")
    return result, body.encode()


def safe_path(name):
    require(isinstance(name, str) and bool(name), "Nonempty repository path required")
    path = PurePosixPath(name)
    require(
        not path.is_absolute()
        and path.as_posix() == name
        and not any(part in {".", "..", ".git"} for part in path.parts)
        and "\\" not in name
        and not any(ord(c) < 32 for c in name),
        "Unsafe repository path",
    )
    return name


def accepted_paths(card):
    meta, _ = metadata(card)
    configs = meta.get("configs", [])
    require(isinstance(configs, list), "Dataset configs list required")
    require(
        len({c["config_name"] for c in configs}) == len(configs),
        "Duplicate dataset config",
    )
    result = {}
    for name in ACCEPTED_CONFIGS:
        matches = [c for c in configs if c["config_name"] == name]
        require(len(matches) == 1, "Both exact accepted configs are required")
        splits = [
            item for item in matches[0]["data_files"] if item["split"] == "accepted"
        ]
        require(len(splits) == 1, "One exact accepted split entry required")
        paths = splits[0]["path"]
        paths = [paths] if isinstance(paths, str) else paths
        require(
            isinstance(paths, list) and bool(paths) and len(set(paths)) == len(paths),
            "Exact distinct accepted paths required",
        )
        for path in paths:
            safe_path(path)
            require(
                path.startswith("splits/")
                and path.endswith(".jsonl")
                and not any(c in path for c in "*?[]"),
                "Accepted source paths must be exact JSONL indexes",
            )
        result[name] = paths
    return result


def owned_documentation(body, *, sample_proof):
    require(
        body.count(SECTION_BEGIN) == body.count(SECTION_END)
        and body.count(SECTION_BEGIN) <= 1,
        "Malformed owned section marker",
    )
    sample = "Sample authority is unavailable; `in_stratified_sample` is null."
    if sample_proof.get("status") == "verified":
        sample = (
            "`in_stratified_sample` is bound only to the owner's published roster and seed receipts: `"
            + json.dumps(sample_proof, sort_keys=True, separators=(",", ":"))
            + "`."
        )
    section = (
        SECTION_BEGIN.decode() + "\n## Current accepted task views\n\n"
        "This private dataset's default `scale800_v1/train` contains every accepted Go and Python task. `scale800_best_v1/train` keeps complete target-model measurements with `0 < qwen_solved < qwen_valid_attempts`.\n\n"
        "The former config named `default` is available as `legacy_default_v1`, with its original files, features and splits preserved.\n\n"
        "```python\nimport os\nfrom datasets import load_dataset\nrepo = 'harness-hub/agentic-coding-envs'\ntoken = os.environ['HF_TOKEN']\ntasks = load_dataset(repo, split='train', token=token)\nbest = load_dataset(repo, name='scale800_best_v1', split='train', token=token, streaming=True)\n```\n\n"
        "Qwen3.8-27B scores use current `qwen38-auto48-64k-2m-nothink*` protocols: thinking off, a 2,000,000-token attempt budget, and either four-of-four or eight-of-eight valid attempts. Partial attempts have null numerical scores; protocols and attempts are never pooled. Generated alternative solutions and leakage audits were **NOT RUN** by this reused-gate scoring profile. Source flags such as `target_model_calibrated=false`, `difficulty_status=unmeasured` and `usage=quarantine_only` are retained; new `qwen_status` and `qwen_*` fields describe the joined current measurement. A train split name or mixed score does not establish trainability or semantic holdout nonoverlap.\n\n"
        + sample
        + "\n"
        + SECTION_END.decode()
    ).encode()
    if SECTION_BEGIN in body:
        start = body.index(SECTION_BEGIN)
        end = body.index(SECTION_END) + len(SECTION_END)
        require(start < body.index(SECTION_END), "Malformed owned section marker order")
        return body[:start] + section + body[end:]
    return body + (b"\n" if body.endswith(b"\n") else b"\n\n") + section + b"\n"


def _read_sdk(path, revision, token):
    source = Path(
        hf_hub_download(
            REPO, safe_path(path), repo_type="dataset", revision=revision, token=token
        )
    )
    require(
        source.stat().st_size <= MAX_FILE_BYTES, "Captured metadata exceeds byte bound"
    )
    return source.read_bytes()


def _listing(api, prefix, revision, token):
    entries = []
    try:
        iterator = api.list_repo_tree(
            REPO,
            repo_type="dataset",
            path_in_repo=prefix,
            recursive=True,
            revision=revision,
            token=token,
        )
        for entry in iterator:
            require(
                len(entries) < MAX_CATALOG_ENTRIES,
                "Scoped catalog exceeds bounded entry limit",
            )
            name = safe_path(entry.path)
            require(
                name.startswith(prefix + "/"), "Catalog entry escaped its exact scope"
            )
            entries.append(entry)
    except EntryNotFoundError:
        if entries:
            raise
        return []
    return entries


def collect(
    *, api, token, read=None, revision=None, sample=None, corrections_index=None
):
    """Read exact accepted sources and bounded owned result/claim scopes, no writes."""
    info = api.dataset_info(REPO, token=token, timeout=120)
    require(info.private is True, "Dataset must remain private")
    revision = revision or info.sha
    require(
        re.fullmatch(r"[0-9a-f]{40}", revision or ""),
        "Immutable capture revision required",
    )
    read = read or (lambda path, rev: _read_sdk(path, rev, token))
    raw_files = {}

    def get(path, rev=revision):
        safe_path(path)
        require(
            re.fullmatch(r"[0-9a-f]{40}", rev or ""),
            "Immutable artifact revision required",
        )
        raw = read(path, rev)
        require(
            isinstance(raw, bytes) and len(raw) <= MAX_FILE_BYTES,
            "Bounded raw metadata bytes required",
        )
        raw_files[(rev, path)] = raw
        return raw

    def many(locators):
        with ThreadPoolExecutor(max_workers=16) as pool:
            return dict(
                pool.map(
                    lambda pair: (pair, get(pair[1], pair[0])), sorted(set(locators))
                )
            )

    card = get("README.md")
    paths = accepted_paths(card)
    indexes = many((revision, name) for names in paths.values() for name in names)
    rows = []
    for config, names in paths.items():
        for name in names:
            for line in indexes[(revision, name)].splitlines():
                row = parsed(line)
                require(
                    row.get("language") == LANGUAGES[config],
                    "Accepted source language/config mismatch",
                )
                rows.append(row)
    by_path = {}
    for row in rows:
        require(
            row["task_path"] not in by_path or by_path[row["task_path"]] == row,
            "Conflicting accepted source task paths",
        )
        by_path[row["task_path"]] = row
    accepted = {
        "repo_id": REPO,
        "revision": revision,
        "configs": list(ACCEPTED_CONFIGS),
        "rows": rows,
        "index_sha256": {name: sha(raw) for (_, name), raw in indexes.items()},
    }
    corrections = (
        correction_authority(corrections_index, read=get)
        if corrections_index is not None
        else None
    )
    results = _listing(api, RESULT_PREFIX, revision, token)
    claim_entries = _listing(api, CLAIM_PREFIX, revision, token)
    pattern = re.compile(
        re.escape(RESULT_PREFIX)
        + r"/[0-9a-f]{64}/coding-[0-9a-f]{64}/(collections|manifest-collections-v1)/([0-9a-f]{64})/summary\.json"
    )
    summary_paths = [entry.path for entry in results if pattern.fullmatch(entry.path)]
    summary_addresses = {(revision, path) for path in summary_paths}
    if corrections is not None:
        summary_addresses.update(
            (row["summary"]["revision"], row["summary"]["path"])
            for row in corrections["rows"]
        )
    claim_paths = [
        entry.path
        for entry in claim_entries
        if entry.path.endswith(".json") and hasattr(entry, "size")
    ]
    captured = many(summary_addresses | {(revision, path) for path in claim_paths})
    claims, records, rejected = [], [], []
    for path in claim_paths:
        raw = captured[(revision, path)]
        value = parsed(raw)
        if value.get("schema") == "openenv-qwen-logical-claim-v1":
            claims.append(
                {
                    "claim_bytes": raw,
                    "claim_locator": {
                        "repo_id": REPO,
                        "revision": revision,
                        "path": path,
                        "sha256": sha(raw),
                    },
                }
            )
    for summary_revision, path in sorted(summary_addresses):
        raw = captured[(summary_revision, path)]
        summary = parsed(raw)
        if not str(summary.get("protocol_id", "")).startswith(PROTOCOL_PREFIX):
            continue
        source = summary.get("source", {})
        row = by_path.get(source.get("task_path"))
        if row is None:
            continue
        locator = {
            "task_id": row["task_id"],
            "summary_path": path,
            "summary_revision": summary_revision,
            "summary_sha256": sha(raw),
            "protocol_id": summary["protocol_id"],
        }
        record = {
            "summary": raw,
            "summary_locator": locator,
            "audit_config_bytes": b"",
            "audit_sha256sums": b"",
            "source_gate_report_bytes": b"",
            "task_inventory": {},
        }
        try:
            carrier_kind = pattern.fullmatch(path).group(1)
            if carrier_kind == "collections":
                require(
                    pattern.fullmatch(path).group(2) == sha(raw),
                    "Published summary content-address mismatch",
                )
            else:
                manifest_path = summary["evidence_manifest_path"]
                require(
                    manifest_path
                    == str(
                        PurePosixPath(path).parent / "worker-artifact-manifest.json"
                    ),
                    "Worker manifest must be the summary's exact sibling",
                )
                record["worker_manifest_bytes"] = get(manifest_path, summary_revision)
                record["worker_manifest_locator"] = {
                    "repo_id": REPO,
                    "revision": summary_revision,
                    "path": manifest_path,
                    "sha256": sha(record["worker_manifest_bytes"]),
                }
            run_id, audit_rev = summary["run_id"], summary["revision"]
            if carrier_kind == "manifest-collections-v1":
                manifest = parsed(record["worker_manifest_bytes"])
                require(
                    manifest.get("repo_id") == REPO
                    and manifest.get("run_id") == run_id,
                    "Worker manifest repository/run mismatch",
                )
                audit_rev = manifest["worker_revision"]
                require(
                    audit_rev == summary["revision"],
                    "Worker and audit revisions differ",
                )
            require(
                re.fullmatch(r"coding-[0-9a-f]{64}", run_id or ""),
                "Malformed audit run identity",
            )
            record["audit_config_bytes"] = get(
                f"runs/{run_id}/audit/config.json", audit_rev
            )
            record["audit_sha256sums"] = get(
                f"runs/{run_id}/audit/SHA256SUMS", audit_rev
            )
            config = parsed(record["audit_config_bytes"])
            gate = config["source_gate"]
            require(
                gate["repo_id"] == REPO
                and gate["report_path"] == row["gate_report_path"],
                "Source gate locator differs",
            )
            record["source_gate_report_bytes"] = get(
                gate["report_path"], gate["revision"]
            )
            record["task_inventory"] = get(
                row["task_file_inventory_path"], source["revision"]
            )
        except (EntryNotFoundError, ValueError, KeyError, TypeError) as exc:
            rejected.append(
                {
                    "summary_path": path,
                    "summary_sha256": sha(raw),
                    "reason": type(exc).__name__,
                }
            )
        records.append(record)
    return {
        "accepted": accepted,
        "records": records,
        "claims": claims,
        "sample": sample,
        "readme_bytes": card,
        "readset": {
            "accepted_revision": revision,
            "config_paths": paths,
            "accepted_index_sha256": accepted["index_sha256"],
            "scoped_prefixes": [RESULT_PREFIX, CLAIM_PREFIX],
            **({"corrections_index_locator": corrections_index} if corrections else {}),
        },
        "raw_files": raw_files,
        "rejected_inputs": rejected,
    }


def save_capture(destination, capture):
    """Persist exact inputs locally for pure replay; never mutate the Hub."""
    destination = Path(destination)
    if destination.exists():
        raise FileExistsError("Fresh immutable local capture directory required")
    destination.mkdir(parents=True, mode=0o700)

    def put(name, raw):
        path = destination / safe_path(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        path.chmod(0o600)
        return name

    put("accepted.json", encode(capture["accepted"]))
    put("readme.md", capture["readme_bytes"])
    put("readset.json", encode(capture["readset"]))
    records = []
    for number, record in enumerate(capture["records"]):
        item = {}
        for key, value in record.items():
            item[key] = put(
                f"records/{number:04d}/{key}",
                value if isinstance(value, bytes) else encode(value),
            )
        records.append(item)
    claims = []
    for number, claim in enumerate(capture["claims"]):
        claims.append(
            {
                key: put(
                    f"claims/{number:04d}/{key}",
                    value if isinstance(value, bytes) else encode(value),
                )
                for key, value in claim.items()
            }
        )
    raw_inventory = []
    for (revision, path), raw in sorted(capture["raw_files"].items()):
        name = put("raw/" + revision + "/" + path, raw)
        raw_inventory.append(
            {
                "revision": revision,
                "path": path,
                "local": name,
                "sha256": sha(raw),
                "bytes": len(raw),
            }
        )
    manifest = {
        "records": records,
        "claims": claims,
        "raw_inventory": raw_inventory,
        "rejected_inputs": capture["rejected_inputs"],
        "remote_mutations": 0,
    }
    put("results.json", encode(manifest))
    put(
        "capture-status.json",
        encode(
            {
                "status": "immutable_scoped_capture_complete",
                "revision": capture["accepted"]["revision"],
                "accepted_rows": len(capture["accepted"]["rows"]),
                "records": len(records),
                "logical_claims": len(claims),
                "raw_files": len(raw_inventory),
                "remote_mutations": 0,
            }
        ),
    )
    return manifest


def load_builder(expected_sha256):
    import types

    path = HERE / "build.py"
    require(
        path.is_file() and not path.is_symlink(),
        "Reviewed regular builder source required",
    )
    raw = path.read_bytes()
    require(sha(raw) == expected_sha256, "Builder differs from approved source hash")
    module = types.ModuleType("captured_derived_view_builder")
    module.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


def load_capture(destination, builder):
    destination = Path(destination)
    accepted = parsed((destination / "accepted.json").read_bytes())
    readset = parsed((destination / "readset.json").read_bytes())
    manifest = parsed((destination / "results.json").read_bytes())
    raw_map = {}
    for item in manifest["raw_inventory"]:
        path = destination / safe_path(item["local"])
        require(
            path.is_file() and not path.is_symlink(), "Regular captured input required"
        )
        raw = path.read_bytes()
        require(
            sha(raw) == item["sha256"] and len(raw) == item["bytes"],
            "Captured raw input changed",
        )
        raw_map[(item["revision"], item["path"])] = raw
    rows = []
    for config in ACCEPTED_CONFIGS:
        for path in readset["config_paths"][config]:
            raw = raw_map[(accepted["revision"], path)]
            require(
                sha(raw) == readset["accepted_index_sha256"][path],
                "Captured accepted index changed",
            )
            for line in raw.splitlines():
                row = parsed(line)
                require(
                    row["language"] == LANGUAGES[config],
                    "Captured source language mismatch",
                )
                rows.append(row)
    require(
        rows == accepted["rows"],
        "Captured accepted rows differ from original source indexes",
    )
    records, claims = builder.read_result_manifest(destination / "results.json")
    card = (destination / "readme.md").read_bytes()
    require(
        card == raw_map[(accepted["revision"], "README.md")],
        "Captured README differs from source bytes",
    )
    return {
        "accepted": accepted,
        "records": records,
        "claims": claims,
        "sample": None,
        "readme_bytes": card,
        "readset": readset,
        "raw_files": raw_map,
        "rejected_inputs": manifest["rejected_inputs"],
    }


def fetch_sample(locators, *, token, read=None):
    """Fetch authority only from exact published immutable owner locators."""
    read = read or (lambda path, rev: _read_sdk(path, rev, token))
    result = {}
    for stem in ("sample", "seed", "selected_task_ids"):
        key = stem + "_locator"
        if key not in locators:
            require(
                stem == "selected_task_ids",
                "Published sample and seed locators required",
            )
            continue
        locator = locators[key]
        require(
            locator.get("repo_id") == REPO
            and re.fullmatch(r"[0-9a-f]{40}", locator.get("revision", "")),
            "Immutable owner sample locator required",
        )
        raw = read(safe_path(locator["path"]), locator["revision"])
        require(
            isinstance(raw, bytes) and sha(raw) == locator["sha256"],
            "Published sample authority hash differs",
        )
        result[key] = locator
        result[stem + "_bytes"] = raw
    return result


def fetch_phase_catalog(locator, *, token, read=None):
    """Capture the owner's exact published terminal catalog and its raw witnesses."""
    read = read or (lambda path, rev: _read_sdk(path, rev, token))

    def get(reference):
        require(
            reference.get("repo_id") == REPO
            and re.fullmatch(r"[0-9a-f]{40}", reference.get("revision", "")),
            "Immutable phase-catalog locator required",
        )
        raw = read(safe_path(reference["path"]), reference["revision"])
        require(
            isinstance(raw, bytes)
            and len(raw) <= MAX_FILE_BYTES
            and sha(raw) == reference["sha256"],
            "Phase-catalog witness hash differs",
        )
        return raw

    catalog_raw = get(locator)
    catalog = parsed(catalog_raw)
    require(
        catalog.get("schema") == "qwen-terminal-phase-catalog-v1"
        and isinstance(catalog.get("rows"), list)
        and len(catalog["rows"]) <= MAX_CATALOG_ENTRIES,
        "Bounded owner phase catalog required",
    )
    references = {}
    for row in catalog["rows"]:
        for key in ("claim", "summary"):
            reference = row[key]
            if reference is None:
                require(key == "summary", "Phase catalog claim locator is required")
                continue
            identity = (reference["revision"], reference["path"])
            require(
                identity not in references or references[identity] == reference,
                "Conflicting phase witness locator",
            )
            references[identity] = reference
    with ThreadPoolExecutor(max_workers=16) as pool:
        captured = dict(
            pool.map(lambda item: (item[0], get(item[1])), sorted(references.items()))
        )
    claims, summaries = {}, {}
    for row in catalog["rows"]:
        for key, target, bytes_key, locator_key in (
            ("claim", claims, "claim_bytes", "claim_locator"),
            ("summary", summaries, "summary_bytes", "summary_locator"),
        ):
            reference = row[key]
            if reference is None:
                require(key == "summary", "Phase catalog claim locator is required")
                continue
            identity = (reference["revision"], reference["path"])
            target[identity] = {bytes_key: captured[identity], locator_key: reference}
    return {
        "catalog_bytes": catalog_raw,
        "catalog_locator": locator,
        "claim_records": list(claims.values()),
        "summary_records": list(summaries.values()),
    }


def correction_authority(locator, *, read):
    """Bind a sealed correction roster to its exact original-attempt witnesses."""

    def get(reference):
        require(
            reference.get("repo_id", REPO) == REPO
            and re.fullmatch(r"[0-9a-f]{40}", reference.get("revision", ""))
            and re.fullmatch(r"[0-9a-f]{64}", reference.get("sha256", "")),
            "Immutable correction locator required",
        )
        raw = read(safe_path(reference["path"]), reference["revision"])
        require(
            isinstance(raw, bytes)
            and len(raw) <= MAX_FILE_BYTES
            and sha(raw) == reference["sha256"],
            "Correction witness hash differs",
        )
        return parsed(raw)

    require(locator.get("repo_id") == REPO, "Correction index repository differs")
    index = get(locator)
    require(
        locator["path"]
        == f"{RESULT_PREFIX}/collection-corrections-v1/{locator['sha256']}/index.json"
        and index.get("schema") == "qwen-immutable-collection-correction-index-v1"
        and isinstance(index.get("rows"), list)
        and 0 < len(index["rows"]) <= MAX_CATALOG_ENTRIES
        and type(index.get("published_complete_count")) is int
        and index["published_complete_count"] == len(index["rows"])
        and index.get("no_new_inference_or_jobs") is True
        and index.get("old_error_receipts_and_unknown_billing_held") is True,
        "Bounded sealed correction index required",
    )
    keys, preparations, superseded = set(), {}, []
    held = {item["measurement_key"] for item in index.get("publication_unknown", [])}
    for item in index["rows"]:
        key, run = item["measurement_key"], item["run_id"]
        require(
            re.fullmatch(r"[0-9a-f]{64}", key)
            and re.fullmatch(r"coding-[0-9a-f]{64}", run)
            and key not in keys | held
            and item.get("status") == "complete"
            and type(item.get("planned_attempts")) is int
            and item["planned_attempts"] == 8
            and type(item.get("valid_attempts")) is int
            and item["valid_attempts"] == 8
            and item.get("model_remeasurement") is False
            and item.get("original_model_attempts_retained") is True,
            "Distinct complete original eight-attempt corrections required",
        )
        keys.add(key)
        summary, preparation = get(item["summary"]), get(item["preparation"])
        require(
            item["preparation"]["revision"] == item["summary"]["revision"]
            and item["preparation"]["path"]
            == str(PurePosixPath(item["summary"]["path"]).parent / "preparation.json")
            and all(
                summary.get(name) == item[name]
                for name in (
                    "measurement_key",
                    "run_id",
                    "protocol_id",
                    "control_profile",
                    "status",
                    "planned_attempts",
                    "valid_attempts",
                    "solve_count",
                    "solve_rate",
                    "difficulty",
                )
            )
            and summary["protocol_id"].startswith(PROTOCOL_PREFIX)
            and all(
                preparation.get(name) == item[name]
                for name in (
                    "task_id",
                    "measurement_key",
                    "run_id",
                    "protocol_id",
                    "control_profile",
                )
            )
            and preparation.get("source") == summary["source"]
            and summary.get("model_remeasurement") is False
            and all(
                summary.get("collection_replay", {}).get(name) is True
                for name in (
                    "unchanged_model_attempts",
                    "unchanged_original_pure_scorer",
                    "original_failed_receipts_retained",
                )
            ),
            "Correction summary/preparation identity differs",
        )
        if "assessment_supersedes" in summary:
            prior_locator = summary["assessment_supersedes"]
            prior = get(prior_locator)
        else:
            retained = summary["prior_failed_assessment"]
            require(
                retained.get("original_publication_status") == "unknown_held",
                "Retained unknown original assessment required",
            )
            prior_locator = {
                "repo_id": REPO,
                "revision": item["summary"]["revision"],
                "path": retained["path"],
                "sha256": retained["sha256"],
            }
            require(
                prior_locator["path"]
                == f"{RESULT_PREFIX}/{key}/{run}/collection-replay-proofs-v1/{prior_locator['sha256']}/original-failure.json",
                "Retained original failure path differs",
            )
            failure = get(prior_locator)
            require(
                failure.get("schema") == "qwen-retained-original-collection-failure-v1"
                and failure.get("no_paid_retry") is True
                and failure.get("original_unknown_holds_retained") is True,
                "Original failure and unknown holds must remain retained",
            )
            prior = failure["summary"]
            require(
                sha(
                    (
                        json.dumps(
                            prior,
                            sort_keys=True,
                            separators=(",", ":"),
                            allow_nan=False,
                        )
                        + "\n"
                    ).encode()
                )
                == failure.get("summary_sha256"),
                "Retained original summary hash differs",
            )
        require(
            prior.get("status") == "incomplete"
            and all(
                prior.get(name) == summary[name]
                for name in (
                    "measurement_key",
                    "run_id",
                    "protocol_id",
                    "source",
                    "revision",
                    "planned_attempts",
                )
            ),
            "Correction must reassess the same original worker attempts",
        )
        preparations[key] = preparation
        superseded.append(prior_locator)
    return {
        "rows": index["rows"],
        "preparations": preparations,
        "held": held,
        "proof": {
            "index_locator": locator,
            "summary_locators": [item["summary"] for item in index["rows"]],
            "preparation_locators": [item["preparation"] for item in index["rows"]],
            "superseded_locators": superseded,
            "publication_unknown": index.get("publication_unknown", []),
            "attempts_pooled": False,
        },
    }


def corrected_records(capture, builder):
    locator = capture["readset"].get("corrections_index_locator")
    if locator is None:
        return capture["records"], None
    authority = correction_authority(
        locator, read=lambda path, revision: capture["raw_files"][(revision, path)]
    )
    by_id = {row["task_id"]: row for row in capture["accepted"]["rows"]}
    selected = {}
    for item in authority["rows"]:
        reference = item["summary"]
        matches = [
            record
            for record in capture["records"]
            if all(
                record["summary_locator"].get("summary_" + name) == reference[name]
                for name in ("revision", "path", "sha256")
            )
        ]
        require(len(matches) == 1, "Exact indexed correction record is required")
        record = matches[0]
        row, summary, config, _ = builder.bind_result(record, by_id)
        builder.complete_metrics(summary, config)
        preparation = authority["preparations"][item["measurement_key"]]
        inventory, digest = builder._inventory(record["task_inventory"])
        require(
            row["task_id"] == item["task_id"]
            and preparation.get("full_task_inventory_sha256") == digest
            and preparation.get("bundle_sha256")
            == summary["run_id"].removeprefix("coding-")
            and preparation.get("effective_config_sha256")
            == sha(record["audit_config_bytes"])
            and preparation.get("files")
            == {
                name: {
                    "sha256": member["sha256"],
                    "bytes": member["size"],
                    "mode": int(member["mode"], 8),
                }
                for name, member in inventory.items()
            },
            "Correction preparation differs from bound source/config/modes",
        )
        selected[item["measurement_key"]] = record
    retained = []
    for record in capture["records"]:
        summary = parsed(record["summary"])
        key = summary.get("measurement_key")
        if key in selected:
            if record is not selected[key]:
                continue
        elif key in authority["held"] and summary.get("status") == "complete":
            continue
        retained.append(record)
    return retained, authority["proof"]


def view_card_bytes(old_card, features, sample_proof, builder):
    card = builder.card_bytes(old_card, features)
    head, body = card.split(b"\n---\n", 1)
    return head + b"\n---\n" + owned_documentation(body, sample_proof=sample_proof)


def prepare(destination, capture, builder_sha256):
    """Derive and freeze two views locally; no credentials or Hub mutation."""
    destination = Path(destination)
    if destination.exists():
        raise FileExistsError("Fresh derived publication stage required")
    builder = load_builder(builder_sha256)
    options = {"claims": capture["claims"], "sample": capture.get("sample")}
    if capture.get("phase_catalog") is not None:
        options["phase_catalog"] = capture["phase_catalog"]
    records, correction_proof = corrected_records(capture, builder)
    result = builder.derive(capture["accepted"], records, **options)
    if correction_proof is not None:
        result["proof"]["corrections_index"] = correction_proof
    require(
        set(result["files"])
        == {"views/scale800_v1/train.jsonl", "views/scale800_best_v1/train.jsonl"},
        "Only two owned view files may be staged",
    )
    accepted_ids = sorted({row["task_id"] for row in capture["accepted"]["rows"]})
    require(
        accepted_ids == sorted(row["task_id"] for row in result["rows"][builder.MAIN]),
        "Derived view omitted accepted source identities",
    )
    destination.mkdir(parents=True, mode=0o700)
    builder.write_local(destination, result)
    plan = {
        "schema": "derived-dataset-views-publication-v1",
        "repo_id": REPO,
        "source_revision": capture["accepted"]["revision"],
        "builder_sha256": builder_sha256,
        "refresh_sha256": sha(Path(__file__).read_bytes()),
        "files": {path: sha(raw) for path, raw in result["files"].items()},
        "features": result["features"],
        "accepted_ids": accepted_ids,
        "accepted_readset": capture["readset"],
        "summary": result["summary"],
        "sample_proof": result["proof"]["stratified_sample"],
        "correction_index_inputs": correction_proof,
        "phase_catalog_inputs": {
            "catalog_locator": capture["phase_catalog"]["catalog_locator"],
            "catalog_sha256": sha(capture["phase_catalog"]["catalog_bytes"]),
            "claim_locators": [
                item["claim_locator"]
                for item in capture["phase_catalog"]["claim_records"]
            ],
            "summary_locators": [
                item["summary_locator"]
                for item in capture["phase_catalog"]["summary_records"]
            ],
        }
        if capture.get("phase_catalog") is not None
        else None,
        "requires_owner_GO_before_live_write": True,
    }
    (destination / "plan.json").write_bytes(encode(plan))
    for path in destination.rglob("*"):
        if path.is_file():
            path.chmod(0o600)
    return plan


def main():
    import argparse
    from dotenv import dotenv_values

    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    capture_args = sub.add_parser(
        "capture", help="Read-only immutable source/result/claim capture"
    )
    capture_args.add_argument("--output", required=True, type=Path)
    prepare_args = sub.add_parser(
        "prepare", help="Pure local preparation; never publishes"
    )
    prepare_args.add_argument("--capture", required=True, type=Path)
    prepare_args.add_argument("--output", required=True, type=Path)
    prepare_args.add_argument("--builder-sha256", required=True)
    prepare_args.add_argument("--sample-locators", type=Path)
    prepare_args.add_argument("--phase-catalog-locator", type=Path)
    args = parser.parse_args()
    if args.command == "capture":
        root = HERE.parents[4]
        token = dotenv_values(root / ".env")["HF_TOKEN"]
        captured = collect(api=HfApi(token=False), token=token)
        save_capture(args.output, captured)
        print(
            json.dumps(
                {
                    "status": "captured_readonly",
                    "revision": captured["accepted"]["revision"],
                    "accepted": len(captured["accepted"]["rows"]),
                    "results": len(captured["records"]),
                    "claims": len(captured["claims"]),
                    "remote_mutations": 0,
                }
            )
        )
    else:
        builder = load_builder(args.builder_sha256)
        captured = load_capture(args.capture, builder)
        if args.sample_locators:
            token = dotenv_values(HERE.parents[4] / ".env")["HF_TOKEN"]
            captured["sample"] = fetch_sample(
                parsed(args.sample_locators.read_bytes()), token=token
            )
        if args.phase_catalog_locator:
            token = dotenv_values(HERE.parents[4] / ".env")["HF_TOKEN"]
            captured["phase_catalog"] = fetch_phase_catalog(
                parsed(args.phase_catalog_locator.read_bytes()), token=token
            )
        plan = prepare(args.output, captured, args.builder_sha256)
        print(
            json.dumps(
                {
                    "status": "prepared_only",
                    "plan_sha256": sha((args.output / "plan.json").read_bytes()),
                    "summary": plan["summary"],
                    "remote_mutations": 0,
                }
            )
        )


if __name__ == "__main__":
    main()
