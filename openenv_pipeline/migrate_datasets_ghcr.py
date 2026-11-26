"""Atomic, idempotent migration of Harbor Hub datasets and local pins from registry.hf.space to GHCR.

Rewrites pinned ``registry.hf.space/...`` references to verified, anonymously publicly
pullable ``linux/amd64`` GHCR digest pins across:

- Hugging Face Hub Harbor datasets (``tasks/*/task.toml``, ``splits/*.jsonl``,
  ``README.md``, and ``SHA256SUMS``) in a single atomic commit with ``parent_commit``
  and post-commit readback verification.
- Local repository receipts and Python image pins (``knowledge/image/receipts/*.json``,
  ``knowledge/automation_{grade,canary}_job.py``, and
  ``knowledge/broad_eval/benchmarks/{gdpval,jobbench,spreadsheetbench}.py``).
- Read-only Hub dataset auditing (``audit``) reporting which datasets still reference
  ``registry.hf.space/...``.

Hard safety gate: before ANY write (Hub or local), every target GHCR image is verified
anonymously as ``linux/amd64`` via ``openenv.harbor.images.OCIRegistryClient(anonymous=True)``.
"""

from __future__ import annotations

import argparse
import ast
import copy
import difflib
import hashlib
import importlib.util
import json
import os
import re
import sys
import tempfile
import tomllib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent

DEFAULT_GHCR_RECEIPTS_REL = Path("knowledge/image/receipts/ghcr")
DEFAULT_MAPPING_REL = DEFAULT_GHCR_RECEIPTS_REL / "manifest.json"

LOCAL_RECEIPT_TARGETS: tuple[tuple[str, str], ...] = (
    ("apex-office-tools", "knowledge/image/receipts/apex-office-tools.json"),
    (
        "spreadsheetbench-verified",
        "knowledge/image/receipts/spreadsheetbench-verified.json",
    ),
)

LOCAL_PYTHON_TARGETS: tuple[dict[str, Any], ...] = (
    {
        "path": "knowledge/automation_grade_job.py",
        "receipt_names": ("apex-office-tools",),
        "metadata_var": None,
    },
    {
        "path": "knowledge/automation_canary_job.py",
        "receipt_names": ("apex-office-tools",),
        "metadata_var": None,
    },
    {
        "path": "knowledge/broad_eval/benchmarks/gdpval.py",
        "receipt_names": ("gdpval", "gdpval-env"),
        "metadata_var": "IMAGE_RECEIPT",
    },
    {
        "path": "knowledge/broad_eval/benchmarks/jobbench.py",
        "receipt_names": ("jobbench", "jobbench-env"),
        "metadata_var": "IMAGE_RECEIPT",
    },
    {
        "path": "knowledge/broad_eval/benchmarks/spreadsheetbench.py",
        "receipt_names": ("spreadsheetbench-verified", "spreadsheetbench"),
        "metadata_var": "IMAGE_PROVENANCE",
    },
)

IMMUTABLE_BASELINE_REPOS = frozenset(
    {
        "harness-hub/harness-adapters",
        "harness-hub/agentic-coding-envs",
    }
)

DEFAULT_AUDIT_DATASETS: tuple[str, ...] = (
    "harness-hub/automation-adapter-envs",
    "harness-hub/harness-adapters",
    "harness-hub/scale800-harbor",
    "harness-hub/traj2envs-rl",
    "harness-hub/termgrade-train-harbor",
    "burtenshaw/automation-eval-bundle",
    "burtenshaw/apex-automation-arm-bundle",
    "burtenshaw/apex-automation-screen-bundle",
    "burtenshaw/apex-knowledge-rl-bundle",
    "burtenshaw/apex-knowledge-rl-fit-bundle",
    "burtenshaw/apex-knowledge-rl-next-bundle",
    "burtenshaw/apex-transfer75-qualified-bundle",
    "burtenshaw/apex-transfer75-control-bundle",
)

_DIGEST_PIN_RE = re.compile(r"^[^@\s]+@sha256:[0-9a-f]{64}$")
_TASK_TOML_RE = re.compile(r"^(?:.+/)?tasks/[^/]+/task\.toml$")
_SPLIT_JSONL_RE = re.compile(r"^splits/[^/]+\.jsonl$")
_SHA256SUM_LINE_RE = re.compile(r"^([0-9a-f]{64})([ \t]+)(.+)$")
_TOML_SECTION_RE = re.compile(r"^\s*\[(\[)?\s*([^\]]+?)\s*(\])?\]\s*(?:#.*)?$")
_TOML_DOCKER_IMAGE_RE = re.compile(
    r"^(\s*docker_image\s*=\s*)(?:\"((?:\\.|[^\"\\])*)\"|'([^']*)')(\s*(?:#.*)?)$"
)
_README_HF_SPACE_PREFIX_RE = re.compile(r"registry\.hf\.space/harness-hub-(?:…|\.\.\.)")


class PublicImageVerificationError(RuntimeError):
    """Raised when a target GHCR image is not anonymously pullable as linux/amd64."""


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_openenv_images(openenv_src: Path | None = None):
    """Load ``openenv.harbor.images`` via ``openenv_pipeline/containerize.py`` without sys.path pollution."""
    mod_name = "openenv_pipeline_containerize_loader"
    containerize = sys.modules.get("openenv_pipeline.containerize") or sys.modules.get(
        mod_name
    )
    if containerize is None:
        spec = importlib.util.spec_from_file_location(
            mod_name, HERE / "containerize.py"
        )
        if spec is None or spec.loader is None:
            raise RuntimeError(f"Unable to load containerize.py from {HERE}")
        containerize = importlib.util.module_from_spec(spec)
        sys.modules[mod_name] = containerize
        spec.loader.exec_module(containerize)
    return containerize.load_openenv_images(openenv_src)


def load_mappings(
    mapping_path: Path | None = None,
    cli_maps: list[str] | None = None,
) -> dict[str, str]:
    """Load and validate ``old_ref -> new_ghcr_ref`` image mappings."""
    mappings: dict[str, str] = {}
    if mapping_path is not None:
        raw = json.loads(mapping_path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError(f"Mapping file must contain a JSON object: {mapping_path}")
        if "mappings" in raw:
            entries = raw["mappings"]
            if not isinstance(entries, dict):
                raise ValueError(
                    f"'mappings' in {mapping_path} must be a JSON object"
                )
        else:
            entries = raw
        for old_ref, new_ref in entries.items():
            if not isinstance(old_ref, str) or not isinstance(new_ref, str):
                raise ValueError(
                    f"Mapping entries must be string -> string in {mapping_path}"
                )
            mappings[old_ref.strip()] = new_ref.strip()

    for item in cli_maps or []:
        if "=" not in item:
            raise ValueError(f"--map must have form OLD=NEW, got: {item!r}")
        old_ref, new_ref = item.split("=", 1)
        old_ref, new_ref = old_ref.strip(), new_ref.strip()
        if not old_ref or not new_ref:
            raise ValueError(f"--map OLD and NEW must be non-empty, got: {item!r}")
        mappings[old_ref] = new_ref

    if not mappings:
        raise ValueError(
            "No image mappings supplied; pass --mapping PATH and/or --map OLD=NEW"
        )

    for old_ref, new_ref in mappings.items():
        if not old_ref or not new_ref:
            raise ValueError(f"Empty mapping entry: {old_ref!r} -> {new_ref!r}")
        if old_ref == new_ref:
            raise ValueError(f"Mapping is a no-op (old == new): {old_ref!r}")
        if new_ref.startswith("registry.hf.space/"):
            raise ValueError(
                f"Target image must not remain on registry.hf.space: {new_ref!r}"
            )
        if not _DIGEST_PIN_RE.match(new_ref):
            raise ValueError(
                f"Target image must be digest-pinned (<repo>@sha256:<64-hex>): {new_ref!r}"
            )

    return mappings


def verify_public_targets(
    targets: list[str] | set[str],
    *,
    openenv_src: Path | None = None,
    skip_public_check: bool = False,
    images_module: Any = None,
) -> dict[str, Any]:
    """Hard safety gate: verify EVERY target image is anonymously pullable as linux/amd64."""
    unique_targets = sorted(set(targets))
    if skip_public_check:
        return {
            "skipped": True,
            "verified": False,
            "targets": {t: {"skipped": True} for t in unique_targets},
        }

    images = images_module if images_module is not None else load_openenv_images(openenv_src)
    verified: dict[str, Any] = {}
    failures: dict[str, str] = {}

    with images.OCIRegistryClient(anonymous=True) as client:
        for ref in unique_targets:
            try:
                resolved, _, _ = client.resolve_linux_amd64(ref)
                cfg = getattr(resolved, "config", None) or {}
                if not getattr(resolved, "public_pull_verified", False):
                    raise PublicImageVerificationError(
                        "resolved image was not verified via anonymous public pull"
                    )
                if cfg.get("os") != "linux" or cfg.get("architecture") != "amd64":
                    raise PublicImageVerificationError(
                        f"expected linux/amd64, got {cfg.get('os')}/{cfg.get('architecture')}"
                    )
                if "@" in ref:
                    expected_digest = ref.split("@", 1)[1]
                    observed = {
                        getattr(resolved, "registry_digest", None),
                        getattr(resolved, "index_digest", None),
                    }
                    if expected_digest not in observed:
                        raise PublicImageVerificationError(
                            f"digest mismatch: expected {expected_digest}, got {sorted(d for d in observed if d)}"
                        )
                verified[ref] = {
                    "ok": True,
                    "image": resolved.image,
                    "registry_digest": resolved.registry_digest,
                    "index_digest": resolved.index_digest,
                    "config": cfg,
                    "public_pull_verified": True,
                }
            except Exception as exc:  # noqa: BLE001
                failures[ref] = f"{type(exc).__name__}: {exc}"

    if failures:
        details = "; ".join(f"{k}: {v}" for k, v in sorted(failures.items()))
        raise PublicImageVerificationError(
            f"Refusing to migrate: {len(failures)}/{len(unique_targets)} target image(s) "
            f"failed anonymous linux/amd64 public pull verification: {details}"
        )

    return {
        "skipped": False,
        "verified": True,
        "targets": verified,
    }


def compute_tree_sha256(file_digests: dict[str, str]) -> str:
    """Compute Harbor task ``tree_sha256`` matching ``knowledge/common.py:sha256_tree``."""
    h = hashlib.sha256()
    for rel in sorted(file_digests, key=Path):
        h.update(rel.encode("utf-8") + b"\0")
        h.update(bytes.fromhex(file_digests[rel]))
    return h.hexdigest()


def parse_sha256sums(text: str) -> dict[str, str]:
    """Parse ``SHA256SUMS`` into ``{path: hex_digest}``."""
    out: dict[str, str] = {}
    for idx, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        m = _SHA256SUM_LINE_RE.match(line)
        if not m:
            raise ValueError(f"Malformed SHA256SUMS line {idx}: {line!r}")
        out[m.group(3)] = m.group(1)
    return out


def update_sha256sums(text: str, new_digests: dict[str, str]) -> tuple[str, int]:
    """Update only modified paths in ``SHA256SUMS``, preserving exact order and format."""
    if not new_digests:
        return text, 0
    ends_nl = text.endswith("\n")
    lines = text.splitlines()
    out_lines: list[str] = []
    updated = 0
    for idx, line in enumerate(lines, 1):
        if not line.strip():
            out_lines.append(line)
            continue
        m = _SHA256SUM_LINE_RE.match(line)
        if not m:
            raise ValueError(f"Malformed SHA256SUMS line {idx}: {line!r}")
        old_hex, sep, rel_path = m.group(1), m.group(2), m.group(3)
        target_hex = new_digests.get(rel_path)
        if target_hex is not None and target_hex != old_hex:
            out_lines.append(f"{target_hex}{sep}{rel_path}")
            updated += 1
        else:
            out_lines.append(line)
    result = "\n".join(out_lines) + ("\n" if ends_nl else "")
    return result, updated


def _toml_section_name(line: str) -> str | None:
    m = _TOML_SECTION_RE.match(line)
    if not m:
        return None
    parts = [p.strip().strip("\"'") for p in m.group(2).split(".")]
    return ".".join(parts)


def _strip_docker_image_fields(doc: dict[str, Any], sections: set[str]) -> dict[str, Any]:
    copied = copy.deepcopy(doc)
    for sec in sections:
        cursor = copied
        keys = sec.split(".")
        for k in keys[:-1]:
            if not isinstance(cursor, dict) or k not in cursor:
                cursor = None
                break
            cursor = cursor[k]
        if isinstance(cursor, dict) and keys[-1] in cursor and isinstance(cursor[keys[-1]], dict):
            cursor[keys[-1]].pop("docker_image", None)
    return copied


def rewrite_task_toml(
    raw_text: str, mappings: dict[str, str]
) -> tuple[str, list[tuple[str, str, str]]]:
    """Surgically rewrite ``docker_image`` in ``task.toml`` and validate with ``tomllib``.

    Returns ``(new_text, changes)`` where each change is ``(section, old_ref, new_ref)``.
    """
    before = tomllib.loads(raw_text)
    target_sections: dict[str, tuple[str, str]] = {}

    env_tbl = before.get("environment")
    if isinstance(env_tbl, dict):
        cur = env_tbl.get("docker_image")
        if isinstance(cur, str) and cur in mappings:
            target_sections["environment"] = (cur, mappings[cur])

    ver_tbl = before.get("verifier")
    if isinstance(ver_tbl, dict) and isinstance(ver_tbl.get("environment"), dict):
        cur = ver_tbl["environment"].get("docker_image")
        if isinstance(cur, str) and cur in mappings:
            target_sections["verifier.environment"] = (cur, mappings[cur])

    if not target_sections:
        return raw_text, []

    out_chunks: list[str] = []
    current_section = ""
    applied: list[tuple[str, str, str]] = []
    seen_sections: set[str] = set()

    for line in raw_text.splitlines(keepends=True):
        newline = ""
        body = line
        if body.endswith("\r\n"):
            body, newline = body[:-2], "\r\n"
        elif body.endswith("\n"):
            body, newline = body[:-1], "\n"

        sec = _toml_section_name(body)
        if sec is not None:
            current_section = sec
            out_chunks.append(line)
            continue

        if current_section in target_sections and current_section not in seen_sections:
            m = _TOML_DOCKER_IMAGE_RE.match(body)
            if m:
                prefix, dq_val, sq_val, suffix = m.groups()
                parsed_val = (
                    tomllib.loads(f'v = "{dq_val}"')["v"]
                    if dq_val is not None
                    else sq_val
                )
                old_ref, new_ref = target_sections[current_section]
                if parsed_val == old_ref:
                    out_chunks.append(
                        f"{prefix}{json.dumps(new_ref)}{suffix}{newline}"
                    )
                    applied.append((current_section, old_ref, new_ref))
                    seen_sections.add(current_section)
                    continue

        out_chunks.append(line)

    if seen_sections != set(target_sections):
        missing = sorted(set(target_sections) - seen_sections)
        raise ValueError(
            f"Failed to locate docker_image assignment in TOML section(s): {missing}"
        )

    new_text = "".join(out_chunks)
    after = tomllib.loads(new_text)

    for sec, (_, new_ref) in target_sections.items():
        cursor: Any = after
        for key in sec.split("."):
            cursor = cursor[key]
        if cursor.get("docker_image") != new_ref:
            raise ValueError(
                f"TOML validation mismatch in [{sec}]: expected {new_ref!r}, got {cursor.get('docker_image')!r}"
            )

    if _strip_docker_image_fields(before, set(target_sections)) != _strip_docker_image_fields(
        after, set(target_sections)
    ):
        raise ValueError("TOML rewrite altered unrelated fields")

    return new_text, applied


def rewrite_readme(
    readme_text: str,
    mappings: dict[str, str],
    *,
    applied_mappings: dict[str, str] | None = None,
    remaining_hf_space_tasks: int = 0,
) -> tuple[str, list[dict[str, str]]]:
    """Update ``registry.hf.space/...`` references in ``README.md`` cleanly and idempotently."""
    updated = readme_text
    replacements: list[dict[str, str]] = []

    # 1. Exact digest-pinned old_ref -> new_ref
    for old_ref, new_ref in sorted(mappings.items(), key=lambda kv: -len(kv[0])):
        if old_ref in updated:
            updated = updated.replace(old_ref, new_ref)
            replacements.append({"from": old_ref, "to": new_ref, "kind": "exact_ref"})

    # 2. Exact repository prefix (without @sha256:...) for registry.hf.space refs
    repo_pairs: dict[str, set[str]] = {}
    for old_ref, new_ref in mappings.items():
        old_repo = old_ref.split("@", 1)[0]
        new_repo = new_ref.split("@", 1)[0]
        if old_repo.startswith("registry.hf.space/"):
            repo_pairs.setdefault(old_repo, set()).add(new_repo)

    for old_repo, new_repos in sorted(repo_pairs.items(), key=lambda kv: -len(kv[0])):
        if len(new_repos) == 1 and old_repo in updated:
            target_repo = next(iter(new_repos))
            updated = updated.replace(old_repo, target_repo)
            replacements.append(
                {"from": old_repo, "to": target_repo, "kind": "repo_prefix"}
            )

    # 3. Generic prose wildcard like `registry.hf.space/harness-hub-…` when all tasks migrated
    active = applied_mappings if applied_mappings is not None else mappings
    if (
        remaining_hf_space_tasks == 0
        and active
        and any(k.startswith("registry.hf.space/harness-hub-") for k in active)
        and _README_HF_SPACE_PREFIX_RE.search(updated)
    ):
        new_repos = sorted({v.split("@", 1)[0] for v in active.values()})
        if len(new_repos) == 1:
            target_prose = new_repos[0]
        else:
            owners = sorted(
                {"/".join(r.split("/")[:2]) for r in new_repos if "/" in r}
            )
            target_prose = (
                f"{owners[0]}/…" if len(owners) == 1 else "ghcr.io/…"
            )
        new_updated = _README_HF_SPACE_PREFIX_RE.sub(target_prose, updated)
        if new_updated != updated:
            updated = new_updated
            replacements.append(
                {
                    "from": "registry.hf.space/harness-hub-…",
                    "to": target_prose,
                    "kind": "prose_prefix",
                }
            )

    return updated, replacements


def _read_repo_bytes(api: Any, repo_id: str, filename: str, revision: str) -> bytes:
    if hasattr(api, "hf_hub_download"):
        res = api.hf_hub_download(
            repo_id=repo_id,
            filename=filename,
            repo_type="dataset",
            revision=revision,
        )
    else:
        from huggingface_hub import hf_hub_download

        res = hf_hub_download(
            repo_id=repo_id,
            filename=filename,
            repo_type="dataset",
            revision=revision,
        )
    if isinstance(res, (bytes, bytearray)):
        return bytes(res)
    return Path(res).read_bytes()


def _task_dir_from_toml(toml_path: str) -> str:
    return toml_path.rsplit("/", 1)[0]


def _task_id_from_task_dir(task_dir: str) -> str:
    return task_dir.rsplit("/", 1)[-1]


def migrate_hub_dataset(
    repo_id: str,
    mappings: dict[str, str],
    *,
    apply: bool = False,
    revision: str | None = None,
    allow_immutable_baseline: bool = False,
    skip_public_check: bool = False,
    openenv_src: Path | None = None,
    concurrency: int = 16,
    commit_message: str | None = None,
    readback_all: bool = False,
    list_all_files: bool = False,
    api: Any = None,
    images_module: Any = None,
) -> dict[str, Any]:
    """Plan (dry-run) or atomically apply GHCR migration to a Hub Harbor dataset."""
    warnings: list[str] = []

    if repo_id.casefold() in IMMUTABLE_BASELINE_REPOS:
        msg = (
            f"{repo_id} is a pinned immutable baseline repository; mutating main "
            "breaks historical replay / inventory invariants"
        )
        if apply and not allow_immutable_baseline:
            raise ValueError(
                f"Refusing to apply migration to {msg}. "
                "Pass --allow-immutable-baseline only if you intend to advance main."
            )
        warnings.append(msg)

    if apply and revision is not None and revision != "main":
        raise ValueError(
            f"Cannot --apply to a non-main revision ({revision!r}); omit --revision to target HEAD"
        )

    # Hard safety gate BEFORE any Hub read/write mutation
    public_verification = verify_public_targets(
        list(mappings.values()),
        openenv_src=openenv_src,
        skip_public_check=skip_public_check,
        images_module=images_module,
    )

    if api is None:
        from huggingface_hub import HfApi

        api = HfApi()

    info = api.dataset_info(repo_id, revision=revision)
    head_sha = info.sha
    if not head_sha:
        raise RuntimeError(f"Could not determine commit SHA for {repo_id}")

    repo_files = sorted(
        api.list_repo_files(repo_id, repo_type="dataset", revision=head_sha)
    )
    repo_file_set = set(repo_files)

    # Detect bundle/historical checksum invariants that live outside SHA256SUMS/splits
    bundle_markers = [
        p
        for p in repo_files
        if p == "holdout-run.json"
        or (p.startswith("manifest/") and (p.endswith(".jsonl") or p.endswith(".json")))
    ]
    if bundle_markers:
        warnings.append(
            f"Repository contains {len(bundle_markers)} bundle manifest/plan file(s) "
            "(e.g. manifest/*.jsonl, plan-*.json, holdout-run.json) with chained "
            "tree_sha256/plan_sha256 hashes not rewritten by this command."
        )
    inventory_markers = [
        p for p in repo_files if "/inventories/" in p and p.endswith(".json")
    ]
    if inventory_markers:
        warnings.append(
            f"Repository contains {len(inventory_markers)} task file inventory JSON(s) "
            "hashing task.toml; updating task.toml without regenerating inventories/views "
            "will create inventory hash mismatches."
        )

    task_tomls = [p for p in repo_files if _TASK_TOML_RE.match(p)]
    split_files = [p for p in repo_files if _SPLIT_JSONL_RE.match(p)]
    has_sha256sums = "SHA256SUMS" in repo_file_set
    has_readme = "README.md" in repo_file_set

    # Read all task.toml files at pinned head_sha
    def _fetch(path: str) -> tuple[str, bytes]:
        return path, _read_repo_bytes(api, repo_id, path, head_sha)

    toml_bytes_map: dict[str, bytes] = {}
    if task_tomls:
        workers = max(1, min(concurrency, len(task_tomls)))
        if workers == 1:
            for p in task_tomls:
                toml_bytes_map[p] = _read_repo_bytes(api, repo_id, p, head_sha)
        else:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                for p, data in pool.map(_fetch, task_tomls):
                    toml_bytes_map[p] = data

    updated_files: dict[str, bytes] = {}
    modified_file_hashes: dict[str, str] = {}
    applied_mappings: dict[str, str] = {}
    modified_task_dirs: set[str] = set()
    remaining_hf_space_tasks = 0
    unmapped_hf_space_images: set[str] = set()

    for toml_path in task_tomls:
        raw_text = toml_bytes_map[toml_path].decode("utf-8")
        new_text, changes = rewrite_task_toml(raw_text, mappings)
        if changes:
            new_bytes = new_text.encode("utf-8")
            updated_files[toml_path] = new_bytes
            modified_file_hashes[toml_path] = _sha256_bytes(new_bytes)
            modified_task_dirs.add(_task_dir_from_toml(toml_path))
            for _, old_ref, new_ref in changes:
                applied_mappings[old_ref] = new_ref

        # Inspect resulting docker_image(s) to see if any registry.hf.space refs remain
        final_doc = tomllib.loads(new_text)
        env_img = (final_doc.get("environment") or {}).get("docker_image")
        ver_img = ((final_doc.get("verifier") or {}).get("environment") or {}).get(
            "docker_image"
        )
        for img in (env_img, ver_img):
            if isinstance(img, str) and img.startswith("registry.hf.space/"):
                remaining_hf_space_tasks += 1
                unmapped_hf_space_images.add(img)

    if unmapped_hf_space_images:
        warnings.append(
            f"{remaining_hf_space_tasks} task.toml reference(s) remain on registry.hf.space "
            f"(unmapped): {sorted(unmapped_hf_space_images)[:5]}"
        )

    # Load SHA256SUMS early so we can recompute tree_sha256 without downloading sibling files
    original_sha256sums_text: str | None = None
    sha256sums_map: dict[str, str] = {}
    if has_sha256sums:
        original_sha256sums_text = _read_repo_bytes(
            api, repo_id, "SHA256SUMS", head_sha
        ).decode("utf-8")
        sha256sums_map = parse_sha256sums(original_sha256sums_text)

    # Recompute tree_sha256 for modified task directories when splits exist
    recomputed_trees_by_dir: dict[str, str] = {}
    recomputed_trees_by_id: dict[str, str] = {}
    if split_files and modified_task_dirs:
        # O(N) indexing of SHA256SUMS entries belonging to any modified task dir
        sums_by_task_dir: dict[str, dict[str, str]] = {}
        if sha256sums_map:
            parent_prefixes = {
                f"{tdir.rsplit('/', 1)[0]}/" if "/" in tdir else ""
                for tdir in modified_task_dirs
            }
            for rel_path, digest in sha256sums_map.items():
                for parent in parent_prefixes:
                    if not rel_path.startswith(parent):
                        continue
                    rest = rel_path[len(parent) :]
                    if "/" not in rest:
                        continue
                    tid, subrel = rest.split("/", 1)
                    tdir = f"{parent}{tid}"
                    if tdir in modified_task_dirs:
                        sums_by_task_dir.setdefault(tdir, {})[subrel] = digest
                        break

        for tdir in sorted(modified_task_dirs):
            prefix = tdir + "/"
            toml_path = f"{tdir}/task.toml"
            entries = dict(sums_by_task_dir.get(tdir) or {})
            if not entries:
                # Fallback when SHA256SUMS is absent: hash sibling files from repo
                siblings = [p for p in repo_files if p.startswith(prefix)]
                for sp in siblings:
                    rel = sp[len(prefix) :]
                    if sp in modified_file_hashes:
                        entries[rel] = modified_file_hashes[sp]
                    else:
                        entries[rel] = _sha256_bytes(
                            _read_repo_bytes(api, repo_id, sp, head_sha)
                        )
            entries["task.toml"] = modified_file_hashes[toml_path]
            new_tree = compute_tree_sha256(entries)
            recomputed_trees_by_dir[tdir] = new_tree
            recomputed_trees_by_id[_task_id_from_task_dir(tdir)] = new_tree

    # Update splits/*.jsonl (docker_image and/or tree_sha256)
    updated_splits: list[str] = []
    split_rows_updated = 0
    for split_path in split_files:
        raw_bytes = _read_repo_bytes(api, repo_id, split_path, head_sha)
        raw_text = raw_bytes.decode("utf-8")
        ends_nl = raw_text.endswith("\n")
        out_lines: list[str] = []
        file_changed = False
        for line in raw_text.splitlines():
            if not line.strip():
                out_lines.append(line)
                continue
            row = json.loads(line)
            row_changed = False

            old_img = row.get("docker_image")
            if isinstance(old_img, str) and old_img in mappings:
                row["docker_image"] = mappings[old_img]
                applied_mappings[old_img] = mappings[old_img]
                row_changed = True

            if "tree_sha256" in row:
                new_tree = None
                tpath = row.get("task_path")
                tid = row.get("task_id")
                if isinstance(tpath, str) and tpath in recomputed_trees_by_dir:
                    new_tree = recomputed_trees_by_dir[tpath]
                elif isinstance(tid, str) and tid in recomputed_trees_by_id:
                    new_tree = recomputed_trees_by_id[tid]
                if new_tree is not None and row["tree_sha256"] != new_tree:
                    row["tree_sha256"] = new_tree
                    row_changed = True

            if row_changed:
                out_lines.append(json.dumps(row, ensure_ascii=False))
                file_changed = True
                split_rows_updated += 1
            else:
                out_lines.append(line)

        if file_changed:
            new_split_bytes = (
                "\n".join(out_lines) + ("\n" if ends_nl else "")
            ).encode("utf-8")
            updated_files[split_path] = new_split_bytes
            modified_file_hashes[split_path] = _sha256_bytes(new_split_bytes)
            updated_splits.append(split_path)

    # Update README.md if it mentions any mapped old image or prose prefix
    readme_updated = False
    readme_replacements: list[dict[str, str]] = []
    if has_readme:
        readme_text = _read_repo_bytes(api, repo_id, "README.md", head_sha).decode(
            "utf-8"
        )
        new_readme, readme_replacements = rewrite_readme(
            readme_text,
            mappings,
            applied_mappings=applied_mappings or mappings,
            remaining_hf_space_tasks=remaining_hf_space_tasks,
        )
        if new_readme != readme_text:
            new_readme_bytes = new_readme.encode("utf-8")
            updated_files["README.md"] = new_readme_bytes
            modified_file_hashes["README.md"] = _sha256_bytes(new_readme_bytes)
            readme_updated = True

    # Recompute SHA256SUMS entries for all modified files listed in SHA256SUMS
    sha256sums_updated = False
    sha256sums_entries_updated = 0
    if original_sha256sums_text is not None and modified_file_hashes:
        new_sums_text, sha256sums_entries_updated = update_sha256sums(
            original_sha256sums_text, modified_file_hashes
        )
        if sha256sums_entries_updated > 0 and new_sums_text != original_sha256sums_text:
            updated_files["SHA256SUMS"] = new_sums_text.encode("utf-8")
            sha256sums_updated = True

    updated_task_tomls = sorted(
        p for p in updated_files if _TASK_TOML_RE.match(p)
    )

    plan: dict[str, Any] = {
        "mode": "apply" if apply else "dry-run",
        "repo_id": repo_id,
        "head_sha": head_sha,
        "public_verification": public_verification,
        "mappings_requested": mappings,
        "mappings_applied": applied_mappings,
        "counts": {
            "task_tomls_scanned": len(task_tomls),
            "task_tomls_updated": len(updated_task_tomls),
            "splits_scanned": len(split_files),
            "splits_updated": len(updated_splits),
            "split_rows_updated": split_rows_updated,
            "readme_updated": readme_updated,
            "sha256sums_updated": sha256sums_updated,
            "sha256sums_entries_updated": sha256sums_entries_updated,
            "total_files_to_commit": len(updated_files),
        },
        "updates": {
            "readme": readme_updated,
            "readme_replacements": readme_replacements,
            "sha256sums": sha256sums_updated,
            "splits": updated_splits,
            "task_tomls_count": len(updated_task_tomls),
            "task_tomls_sample": updated_task_tomls[:10],
        },
        "warnings": warnings,
    }
    if list_all_files or len(updated_files) <= 50:
        plan["files_to_update"] = sorted(updated_files)

    if not apply:
        return plan

    if not updated_files:
        plan["status"] = "up_to_date"
        plan["commit_oid"] = head_sha
        plan["committed_files"] = 0
        return plan

    from huggingface_hub import CommitOperationAdd

    operations = [
        CommitOperationAdd(path_in_repo=path, path_or_fileobj=data)
        for path, data in sorted(updated_files.items())
    ]
    msg = commit_message or (
        f"Migrate {len(updated_task_tomls)} Harbor task image pin(s) from "
        "registry.hf.space to verified public GHCR digest(s)"
    )
    commit_info = api.create_commit(
        repo_id=repo_id,
        repo_type="dataset",
        operations=operations,
        commit_message=msg,
        parent_commit=head_sha,
    )
    new_sha = getattr(commit_info, "oid", None) or api.dataset_info(repo_id).sha
    if not new_sha:
        raise RuntimeError("Hub create_commit did not return a commit OID")

    # Post-commit readback verification at new_sha
    readback_paths: list[str] = []
    for special in ("SHA256SUMS", "README.md"):
        if special in updated_files:
            readback_paths.append(special)
    readback_paths.extend(updated_splits)
    if readback_all or len(updated_task_tomls) <= 25:
        readback_paths.extend(updated_task_tomls)
    else:
        # Deterministic stratified sample covering first, evenly spaced middle, and last
        n = len(updated_task_tomls)
        indices = sorted({int(round(i * (n - 1) / 24)) for i in range(25)})
        readback_paths.extend(updated_task_tomls[i] for i in indices)

    verified_count = 0
    for path in readback_paths:
        observed_bytes = _read_repo_bytes(api, repo_id, path, new_sha)
        expected_bytes = updated_files[path]
        if observed_bytes != expected_bytes:
            raise RuntimeError(
                f"Readback verification failed for {path} at {new_sha}: "
                f"sha256 {_sha256_bytes(observed_bytes)} != {_sha256_bytes(expected_bytes)}"
            )
        if _TASK_TOML_RE.match(path):
            parsed = tomllib.loads(observed_bytes.decode("utf-8"))
            img = (parsed.get("environment") or {}).get("docker_image", "")
            if isinstance(img, str) and img.startswith("registry.hf.space/"):
                raise RuntimeError(
                    f"Readback task.toml still references registry.hf.space: {path}"
                )
        verified_count += 1

    plan["status"] = "committed"
    plan["commit_oid"] = new_sha
    plan["committed_files"] = len(operations)
    plan["readback"] = {
        "revision": new_sha,
        "files_verified": verified_count,
        "ok": True,
    }
    return plan


# --------------------------------------------------------------------------- local repo migration


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _load_ghcr_receipts(ghcr_dir: Path) -> dict[str, dict[str, Any]]:
    receipts: dict[str, dict[str, Any]] = {}
    if not ghcr_dir.is_dir():
        return receipts
    for p in sorted(ghcr_dir.glob("*.json")):
        if p.name == "manifest.json":
            continue
        data = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(data, dict) and data.get("image"):
            receipts[p.stem] = data
            if isinstance(data.get("task_id"), str):
                receipts[data["task_id"]] = data
    return receipts


def _build_receipt_payload(
    existing: dict[str, Any],
    *,
    new_ref: str,
    ghcr_receipt: dict[str, Any] | None,
    verified_info: dict[str, Any] | None,
) -> dict[str, Any]:
    if ghcr_receipt is not None:
        out = dict(ghcr_receipt)
        if existing.get("task_id") and not out.get("task_id"):
            out["task_id"] = existing["task_id"]
        if existing.get("context_files") and not out.get("context_files"):
            out["context_files"] = existing["context_files"]
        return out

    digest = (
        (verified_info or {}).get("registry_digest")
        or (new_ref.split("@", 1)[1] if "@" in new_ref else None)
    )
    cfg = (verified_info or {}).get("config") or existing.get("config")
    out = {
        "task_id": existing.get("task_id"),
        "status": "resolved",
        "image": new_ref,
        "registry": new_ref.split("@", 1)[0],
        "registry_digest": digest,
        "index_digest": (verified_info or {}).get("index_digest"),
        "config": cfg,
        "public_pull_verified": bool(
            (verified_info or {}).get("public_pull_verified", False)
        ),
        "context_files": existing.get("context_files", {}),
        "contents": "environment/Dockerfile only (OCI registry, no Space)",
    }
    return {k: v for k, v in out.items() if v is not None}


def _find_top_level_assign(tree: ast.Module, name: str) -> ast.Assign | None:
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == name:
                    return node
    return None


def _format_python_dict_assign(var_name: str, data: dict[str, Any]) -> list[str]:
    lines = [f"{var_name} = {{\n"]
    for k, v in data.items():
        val_repr = json.dumps(v) if isinstance(v, str) else repr(v)
        lines.append(f"    {json.dumps(k)}: {val_repr},\n")
    lines.append("}\n")
    return lines


def _build_python_metadata_dict(
    existing: dict[str, Any],
    *,
    new_ref: str,
    ghcr_receipt: dict[str, Any] | None,
    verified_info: dict[str, Any] | None,
) -> dict[str, Any]:
    """Construct updated ``IMAGE_RECEIPT`` / ``IMAGE_PROVENANCE`` preserving ``dockerfile_sha256``."""
    registry = (
        (ghcr_receipt or {}).get("registry")
        or new_ref.split("@", 1)[0]
    )
    registry_digest = (
        (ghcr_receipt or {}).get("registry_digest")
        or (verified_info or {}).get("registry_digest")
        or (new_ref.split("@", 1)[1] if "@" in new_ref else None)
    )
    dockerfile_sha256 = (
        (ghcr_receipt or {}).get("dockerfile_sha256")
        or existing.get("dockerfile_sha256")
    )
    cfg = (ghcr_receipt or {}).get("config") or (verified_info or {}).get("config") or {}
    config_digest = cfg.get("digest") or existing.get("config_digest")

    out: dict[str, Any] = {
        "registry": registry,
        "registry_digest": registry_digest,
    }
    if ghcr_receipt and ghcr_receipt.get("tag"):
        out["tag"] = ghcr_receipt["tag"]
    if ghcr_receipt and ghcr_receipt.get("builder"):
        out["builder"] = ghcr_receipt["builder"]
    if dockerfile_sha256:
        out["dockerfile_sha256"] = dockerfile_sha256
    if config_digest:
        out["config_digest"] = config_digest
    out["platform"] = "linux/amd64"
    out["public_pull_verified"] = bool(
        (ghcr_receipt or {}).get("public_pull_verified")
        or (verified_info or {}).get("public_pull_verified", False)
    )
    return out


def rewrite_local_python_file(
    source_text: str,
    mappings: dict[str, str],
    *,
    metadata_var: str | None = None,
    ghcr_receipt: dict[str, Any] | None = None,
    verified_targets: dict[str, Any] | None = None,
) -> tuple[str, dict[str, Any] | None]:
    """Rewrite top-level ``IMAGE`` (and optional ``IMAGE_RECEIPT`` / ``IMAGE_PROVENANCE``) via AST."""
    tree = ast.parse(source_text)
    img_node = _find_top_level_assign(tree, "IMAGE")
    if img_node is None:
        return source_text, None

    try:
        current_image = ast.literal_eval(img_node.value)
    except (ValueError, SyntaxError):
        return source_text, None

    if not isinstance(current_image, str):
        return source_text, None

    new_image = mappings.get(current_image)
    if new_image is None:
        return source_text, None

    lines = source_text.splitlines(keepends=True)
    # Collect replacements as (start_idx, end_idx_exclusive, replacement_lines)
    edits: list[tuple[int, int, list[str]]] = [
        (
            img_node.lineno - 1,
            img_node.end_lineno,
            [f"IMAGE = {json.dumps(new_image)}\n"],
        )
    ]

    metadata_updated = False
    if metadata_var:
        meta_node = _find_top_level_assign(tree, metadata_var)
        if meta_node is not None:
            try:
                existing_meta = ast.literal_eval(meta_node.value)
            except (ValueError, SyntaxError):
                existing_meta = None
            if isinstance(existing_meta, dict):
                v_info = (verified_targets or {}).get(new_image)
                new_meta = _build_python_metadata_dict(
                    existing_meta,
                    new_ref=new_image,
                    ghcr_receipt=ghcr_receipt,
                    verified_info=v_info if isinstance(v_info, dict) else None,
                )
                edits.append(
                    (
                        meta_node.lineno - 1,
                        meta_node.end_lineno,
                        _format_python_dict_assign(metadata_var, new_meta),
                    )
                )
                metadata_updated = True

    # Apply edits bottom-to-top so line numbers remain valid
    for start, end, repl in sorted(edits, key=lambda e: e[0], reverse=True):
        lines[start:end] = repl

    updated_text = "".join(lines)
    # Validate syntax and resulting AST values
    reparsed = ast.parse(updated_text)
    new_img_node = _find_top_level_assign(reparsed, "IMAGE")
    if new_img_node is None or ast.literal_eval(new_img_node.value) != new_image:
        raise RuntimeError("AST readback check failed for IMAGE assignment")

    return updated_text, {
        "old_image": current_image,
        "new_image": new_image,
        "metadata_var_updated": metadata_var if metadata_updated else None,
    }


def migrate_local_repo(
    mappings: dict[str, str],
    *,
    repo_root: Path = ROOT,
    ghcr_receipts_dir: Path | None = None,
    apply: bool = False,
    skip_public_check: bool = False,
    openenv_src: Path | None = None,
    images_module: Any = None,
) -> dict[str, Any]:
    """Plan (dry-run) or atomically apply GHCR pin updates to local repository files."""
    repo_root = repo_root.resolve()
    ghcr_dir = (
        ghcr_receipts_dir.resolve()
        if ghcr_receipts_dir is not None
        else repo_root / DEFAULT_GHCR_RECEIPTS_REL
    )
    ghcr_receipts = _load_ghcr_receipts(ghcr_dir)

    # Collect EVERY target image (mapping targets + any matching GHCR receipt images)
    all_targets = set(mappings.values())
    for target_name, rel_path in LOCAL_RECEIPT_TARGETS:
        if (repo_root / rel_path).is_file() and target_name in ghcr_receipts:
            img = ghcr_receipts[target_name].get("image")
            if isinstance(img, str):
                if not _DIGEST_PIN_RE.match(img) or img.startswith("registry.hf.space/"):
                    raise ValueError(
                        f"GHCR receipt {target_name!r} has invalid image pin: {img!r}"
                    )
                all_targets.add(img)

    # Hard safety gate BEFORE any local file write
    public_verification = verify_public_targets(
        all_targets,
        openenv_src=openenv_src,
        skip_public_check=skip_public_check,
        images_module=images_module,
    )
    verified_targets = public_verification.get("targets", {})

    pending_writes: dict[str, str] = {}
    diffs: dict[str, str] = {}
    file_changes: list[dict[str, Any]] = []
    unchanged_files: list[str] = []
    warnings: list[str] = []

    # 1. JSON image receipts
    for target_name, rel_path in LOCAL_RECEIPT_TARGETS:
        path = repo_root / rel_path
        if not path.is_file():
            warnings.append(f"Missing local receipt target (skipped): {rel_path}")
            continue
        old_text = path.read_text(encoding="utf-8")
        existing = json.loads(old_text)
        old_image = existing.get("image", "")
        ghcr_rec = ghcr_receipts.get(target_name)

        new_image: str | None = None
        if ghcr_rec is not None:
            new_image = ghcr_rec["image"]
            if old_image in mappings and mappings[old_image] != new_image:
                raise ValueError(
                    f"Conflict for {rel_path}: GHCR receipt image {new_image!r} "
                    f"!= mapping target {mappings[old_image]!r}"
                )
        elif old_image in mappings:
            new_image = mappings[old_image]

        if new_image is None:
            unchanged_files.append(rel_path)
            continue

        new_payload = _build_receipt_payload(
            existing,
            new_ref=new_image,
            ghcr_receipt=ghcr_rec,
            verified_info=verified_targets.get(new_image)
            if isinstance(verified_targets, dict)
            else None,
        )
        new_text = json.dumps(new_payload, indent=1) + "\n"
        if new_text == old_text:
            unchanged_files.append(rel_path)
            continue

        pending_writes[rel_path] = new_text
        diffs[rel_path] = "".join(
            difflib.unified_diff(
                old_text.splitlines(keepends=True),
                new_text.splitlines(keepends=True),
                fromfile=f"a/{rel_path}",
                tofile=f"b/{rel_path}",
            )
        )
        file_changes.append(
            {
                "path": rel_path,
                "kind": "receipt",
                "old_image": old_image,
                "new_image": new_image,
                "from_ghcr_receipt": ghcr_rec is not None,
            }
        )

    # 2. Python IMAGE / IMAGE_RECEIPT / IMAGE_PROVENANCE files
    for spec in LOCAL_PYTHON_TARGETS:
        rel_path = spec["path"]
        path = repo_root / rel_path
        if not path.is_file():
            warnings.append(f"Missing local Python target (skipped): {rel_path}")
            continue
        old_text = path.read_text(encoding="utf-8")
        ghcr_rec = next(
            (ghcr_receipts[n] for n in spec["receipt_names"] if n in ghcr_receipts),
            None,
        )
        new_text, detail = rewrite_local_python_file(
            old_text,
            mappings,
            metadata_var=spec["metadata_var"],
            ghcr_receipt=ghcr_rec,
            verified_targets=verified_targets
            if isinstance(verified_targets, dict)
            else None,
        )
        if detail is None or new_text == old_text:
            unchanged_files.append(rel_path)
            continue

        pending_writes[rel_path] = new_text
        diffs[rel_path] = "".join(
            difflib.unified_diff(
                old_text.splitlines(keepends=True),
                new_text.splitlines(keepends=True),
                fromfile=f"a/{rel_path}",
                tofile=f"b/{rel_path}",
            )
        )
        file_changes.append({"path": rel_path, "kind": "python", **detail})
        if rel_path.endswith("spreadsheetbench.py"):
            warnings.append(
                "knowledge/broad_eval/benchmarks/spreadsheetbench.py pins TASKS_SHA256 "
                "over converted task trees (which embed IMAGE); recompute TASKS_SHA256 "
                "after regenerating tasks with the new GHCR image."
            )

    if any(
        p.startswith("knowledge/broad_eval/benchmarks/") for p in pending_writes
    ) and (repo_root / "knowledge/broad_eval/test_image_builders.py").is_file():
        warnings.append(
            "knowledge/broad_eval/test_image_builders.py pins expected_image for "
            "gdpval/jobbench/spreadsheetbench; update SPECS expected_image after "
            "applying local benchmark image changes."
        )

    if apply:
        for rel_path, new_text in sorted(pending_writes.items()):
            dest = repo_root / rel_path
            _atomic_write_text(dest, new_text)
            # Readback verification
            readback = dest.read_text(encoding="utf-8")
            if readback != new_text:
                raise RuntimeError(f"Local readback mismatch for {rel_path}")
            if rel_path.endswith(".json"):
                json.loads(readback)
            elif rel_path.endswith(".py"):
                ast.parse(readback)

    return {
        "mode": "apply" if apply else "dry-run",
        "repo_root": str(repo_root),
        "ghcr_receipts_dir": str(ghcr_dir),
        "public_verification": public_verification,
        "changed_files": sorted(pending_writes),
        "unchanged_files": sorted(unchanged_files),
        "changes": file_changes,
        "diffs": diffs,
        "warnings": warnings,
        "applied": bool(apply and pending_writes),
    }


# --------------------------------------------------------------------------- audit subcommand


def _extract_registry_host(image_ref: str) -> str:
    if "/" not in image_ref:
        return "docker.io"
    first = image_ref.split("/", 1)[0]
    if "." in first or ":" in first or first == "localhost":
        return first
    return "docker.io"


def _list_top_level(api: Any, repo_id: str, revision: str) -> tuple[set[str], set[str]]:
    """Return ``(top_files, top_dirs)`` using fast non-recursive tree listing when available."""
    if hasattr(api, "list_repo_tree"):
        entries = list(
            api.list_repo_tree(
                repo_id, repo_type="dataset", revision=revision, recursive=False
            )
        )
        top_files = {e.path for e in entries if hasattr(e, "blob_id") or hasattr(e, "size")}
        top_dirs = {e.path for e in entries if e.path not in top_files}
        return top_files, top_dirs

    all_files = api.list_repo_files(repo_id, repo_type="dataset", revision=revision)
    top_files = {f for f in all_files if "/" not in f}
    top_dirs = {f.split("/", 1)[0] for f in all_files if "/" in f}
    return top_files, top_dirs


def _list_subdir_children(
    api: Any, repo_id: str, subdir: str, revision: str
) -> list[str]:
    if hasattr(api, "list_repo_tree"):
        return sorted(
            e.path
            for e in api.list_repo_tree(
                repo_id,
                path_in_repo=subdir,
                repo_type="dataset",
                revision=revision,
                recursive=False,
            )
        )
    prefix = subdir + "/"
    all_files = api.list_repo_files(repo_id, repo_type="dataset", revision=revision)
    children = {
        prefix + f[len(prefix) :].split("/", 1)[0]
        for f in all_files
        if f.startswith(prefix)
    }
    return sorted(children)


def audit_dataset(
    repo_id: str,
    *,
    api: Any = None,
    sample_tasks: int = 5,
) -> dict[str, Any]:
    """Read-only inspection of one Hub dataset for ``registry.hf.space/...`` references."""
    if api is None:
        from huggingface_hub import HfApi

        api = HfApi()

    try:
        info = api.dataset_info(repo_id)
        head_sha = info.sha
        top_files, top_dirs = _list_top_level(api, repo_id, head_sha)

        has_sha256sums = "SHA256SUMS" in top_files
        has_readme = "README.md" in top_files
        has_splits = "splits" in top_dirs
        has_views = "views" in top_dirs
        has_bundle_manifests = ("manifest" in top_dirs) or (
            "holdout-run.json" in top_files
        )
        immutable = repo_id.casefold() in IMMUTABLE_BASELINE_REPOS

        images_found: set[str] = set()
        readme_has_hf_space = False
        task_count = 0

        if has_readme:
            readme_text = _read_repo_bytes(api, repo_id, "README.md", head_sha).decode(
                "utf-8", errors="replace"
            )
            readme_has_hf_space = "registry.hf.space" in readme_text

        # Fast split inspection (full coverage of docker_image column when present)
        if has_splits:
            split_children = [
                p
                for p in _list_subdir_children(api, repo_id, "splits", head_sha)
                if p.endswith(".jsonl")
            ]
            split_task_ids: set[str] = set()
            for sp in split_children:
                txt = _read_repo_bytes(api, repo_id, sp, head_sha).decode("utf-8")
                for line in txt.splitlines():
                    if not line.strip():
                        continue
                    row = json.loads(line)
                    if row.get("task_id"):
                        split_task_ids.add(row["task_id"])
                    img = row.get("docker_image")
                    if isinstance(img, str) and img:
                        images_found.add(img)
            if split_task_ids:
                task_count = max(task_count, len(split_task_ids))

        # Fast views inspection (e.g. harness-hub/harness-adapters)
        if has_views:
            try:
                view_bytes = _read_repo_bytes(
                    api, repo_id, "views/final_v1/train.jsonl", head_sha
                )
                rows = [
                    json.loads(line)
                    for line in view_bytes.decode("utf-8").splitlines()
                    if line.strip()
                ]
                task_count = max(task_count, len(rows))
                seen_origins: dict[str, int] = {}
                for row in rows:
                    origin = row.get("task_origin", "unknown")
                    if seen_origins.get(origin, 0) >= max(1, sample_tasks // 2):
                        continue
                    seen_origins[origin] = seen_origins.get(origin, 0) + 1
                    tpath = row.get("task_path")
                    if tpath:
                        try:
                            toml_raw = _read_repo_bytes(
                                api, repo_id, f"{tpath}/task.toml", head_sha
                            ).decode("utf-8")
                            doc = tomllib.loads(toml_raw)
                            img = (doc.get("environment") or {}).get("docker_image")
                            if isinstance(img, str) and img:
                                images_found.add(img)
                        except Exception:  # noqa: BLE001
                            pass
                    rpath = row.get("image_receipt_path")
                    if rpath:
                        try:
                            rec = json.loads(
                                _read_repo_bytes(api, repo_id, rpath, head_sha).decode(
                                    "utf-8"
                                )
                            )
                            img = rec.get("image")
                            if isinstance(img, str) and img:
                                images_found.add(img)
                        except Exception:  # noqa: BLE001
                            pass
            except Exception:  # noqa: BLE001
                pass

        # Sample tasks/*/task.toml when tasks/ exists
        if "tasks" in top_dirs:
            tdirs = _list_subdir_children(api, repo_id, "tasks", head_sha)
            task_count = max(task_count, len(tdirs))
            for tdir in tdirs[:sample_tasks]:
                try:
                    toml_raw = _read_repo_bytes(
                        api, repo_id, f"{tdir}/task.toml", head_sha
                    ).decode("utf-8")
                    doc = tomllib.loads(toml_raw)
                    img = (doc.get("environment") or {}).get("docker_image")
                    if isinstance(img, str) and img:
                        images_found.add(img)
                except Exception:  # noqa: BLE001
                    pass

        hf_space_images = sorted(
            img for img in images_found if img.startswith("registry.hf.space/")
        )
        has_hf_space = bool(hf_space_images) or readme_has_hf_space
        registries = sorted({_extract_registry_host(img) for img in images_found})

        if not has_hf_space:
            status = "migrated"
        elif immutable:
            status = "immutable_historical"
        elif has_bundle_manifests:
            status = "needs_migration_bundle"
        else:
            status = "needs_migration"

        return {
            "repo_id": repo_id,
            "private": bool(getattr(info, "private", False)),
            "head_sha": head_sha,
            "immutable_baseline": immutable,
            "task_count": task_count,
            "has_registry_hf_space": has_hf_space,
            "readme_has_registry_hf_space": readme_has_hf_space,
            "has_sha256sums": has_sha256sums,
            "has_splits": has_splits,
            "has_bundle_manifests": has_bundle_manifests,
            "registries": registries,
            "sample_images": sorted(images_found)[:5],
            "status": status,
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "repo_id": repo_id,
            "status": "error",
            "error": f"{type(exc).__name__}: {exc}",
        }


def audit_datasets(
    repos: list[str] | None = None,
    *,
    api: Any = None,
    sample_tasks: int = 5,
) -> dict[str, Any]:
    """Audit project datasets and return a concise JSON status table."""
    target_repos = list(repos) if repos else list(DEFAULT_AUDIT_DATASETS)
    if api is None:
        from huggingface_hub import HfApi

        api = HfApi()

    results = [
        audit_dataset(repo_id, api=api, sample_tasks=sample_tasks)
        for repo_id in target_repos
    ]
    summary = {
        "total": len(results),
        "needs_migration": sum(r.get("status") == "needs_migration" for r in results),
        "needs_migration_bundle": sum(
            r.get("status") == "needs_migration_bundle" for r in results
        ),
        "immutable_historical": sum(
            r.get("status") == "immutable_historical" for r in results
        ),
        "migrated": sum(r.get("status") == "migrated" for r in results),
        "errors": sum(r.get("status") == "error" for r in results),
    }
    return {
        "summary": summary,
        "datasets": results,
    }


# --------------------------------------------------------------------------- CLI


def _add_mapping_and_safety_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--mapping",
        type=Path,
        help=(
            'JSON mapping file ({"mappings": {"<old_ref>": "<new_ghcr_ref>"}}), '
            f"e.g. {DEFAULT_MAPPING_REL}"
        ),
    )
    parser.add_argument(
        "--map",
        dest="maps",
        action="append",
        default=[],
        metavar="OLD=NEW",
        help="Explicit old=new image mapping (repeatable; overrides --mapping)",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--dry-run",
        action="store_true",
        help="Compute and print exact migration plan without writing (default)",
    )
    mode.add_argument(
        "--apply",
        action="store_true",
        help="Execute migration after verifying every target GHCR image is publicly pullable",
    )
    parser.add_argument(
        "--skip-public-check",
        action="store_true",
        help="FOR UNIT TESTS ONLY: skip anonymous public linux/amd64 verification gate",
    )
    parser.add_argument(
        "--openenv-src",
        type=Path,
        help="Path to OpenEnv src/ tree containing openenv/harbor/images.py",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_hub = sub.add_parser(
        "hub",
        help="Migrate a Hugging Face Hub Harbor dataset atomically to GHCR",
    )
    p_hub.add_argument("repo_id", help="HF dataset repo ID (e.g. harness-hub/automation-adapter-envs)")
    _add_mapping_and_safety_args(p_hub)
    p_hub.add_argument(
        "--revision",
        help="Optional revision to inspect during --dry-run (defaults to HEAD)",
    )
    p_hub.add_argument(
        "--allow-immutable-baseline",
        action="store_true",
        help="Override safety guard against mutating pinned historical baseline repos",
    )
    p_hub.add_argument(
        "--concurrency",
        type=int,
        default=16,
        help="Parallel read workers for task.toml downloads (default: 16)",
    )
    p_hub.add_argument("--commit-message", help="Custom Hub commit message on --apply")
    p_hub.add_argument(
        "--readback-all",
        action="store_true",
        help="Verify every modified task.toml on readback instead of sampling 25 when >25",
    )
    p_hub.add_argument(
        "--list-all-files",
        action="store_true",
        help="Include full files_to_update list in dry-run JSON even when >50 files",
    )

    p_local = sub.add_parser(
        "local",
        help="Update local repository receipts and Python IMAGE pins to GHCR",
    )
    _add_mapping_and_safety_args(p_local)
    p_local.add_argument(
        "--repo-root",
        type=Path,
        default=ROOT,
        help="Repository root directory (defaults to workspace root)",
    )
    p_local.add_argument(
        "--ghcr-receipts-dir",
        type=Path,
        help=f"Directory of GHCR receipt JSONs (default: <repo-root>/{DEFAULT_GHCR_RECEIPTS_REL})",
    )

    p_audit = sub.add_parser(
        "audit",
        help="Audit project Hub datasets for remaining registry.hf.space references",
    )
    p_audit.add_argument(
        "--repo",
        dest="repos",
        action="append",
        default=[],
        help="Dataset repo ID to audit (repeatable; defaults to all project datasets)",
    )
    p_audit.add_argument(
        "--sample-tasks",
        type=int,
        default=5,
        help="Number of tasks/*/task.toml files to sample per dataset (default: 5)",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "audit":
        result = audit_datasets(args.repos or None, sample_tasks=args.sample_tasks)
        print(json.dumps(result, indent=2))
        return 0

    mapping_path = args.mapping
    if mapping_path is None and not args.maps:
        base_root = getattr(args, "repo_root", ROOT)
        default_manifest = Path(base_root) / DEFAULT_MAPPING_REL
        if default_manifest.is_file():
            mapping_path = default_manifest

    mappings = load_mappings(mapping_path, args.maps)

    if args.command == "hub":
        result = migrate_hub_dataset(
            args.repo_id,
            mappings,
            apply=bool(args.apply),
            revision=args.revision,
            allow_immutable_baseline=bool(args.allow_immutable_baseline),
            skip_public_check=bool(args.skip_public_check),
            openenv_src=args.openenv_src,
            concurrency=args.concurrency,
            commit_message=args.commit_message,
            readback_all=bool(args.readback_all),
            list_all_files=bool(args.list_all_files),
        )
    elif args.command == "local":
        result = migrate_local_repo(
            mappings,
            repo_root=args.repo_root,
            ghcr_receipts_dir=args.ghcr_receipts_dir,
            apply=bool(args.apply),
            skip_public_check=bool(args.skip_public_check),
            openenv_src=args.openenv_src,
        )
    else:
        parser.error(f"Unknown command: {args.command}")

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, FileNotFoundError, PublicImageVerificationError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
