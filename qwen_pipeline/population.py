"""Assemble the outcome-blind sampling population from registered accepted source rows."""

import argparse
from collections import Counter
from functools import lru_cache
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from urllib.request import Request, urlopen

from draw import digest, encode

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL = "harness-hub/agentic-coding-envs"
ORIGINAL_REVISION = "3afa3ffb350eae408cdc4962952452726a680559"
IMAGE_FIELDS = (
    "image",
    "space_id",
    "space_commit",
    "source_image",
    "image_config_sha256",
    "context_inventory_sha256",
    "public_source_inventory_sha256",
)
GIT = r"[0-9a-f]{40}"
HASH = r"[0-9a-f]{64}"
REPO = r"[A-Za-z0-9][\w.-]*/[A-Za-z0-9][\w.-]*"
IMAGE = r"[^@\s]+@sha256:[0-9a-f]{64}"


def require(value, message):
    if not value:
        raise ValueError(message)


def parser_module():
    path = (
        ROOT
        / "openenv_pipeline/operators/production/derived-dataset-views-corrections-v1/refresh.py"
    )
    pins = json.loads((ROOT / "openenv_pipeline/pins.json").read_bytes())[
        "operator_files_sha256"
    ]
    name = str(path.relative_to(ROOT / "openenv_pipeline/operators"))
    require(digest(path.read_bytes()) == pins[name], "Historical input parser changed")
    spec = importlib.util.spec_from_file_location("accepted_indexes", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def historical_reader(folder):
    def document(name, expected):
        raw = (folder / name).read_bytes()
        require(digest(raw) == expected, f"Historical evidence changed: {name}")
        return json.loads(raw)

    proofs = document(
        "canonical-repository-proofs.json",
        "883258affd3efee151a0059c3fc6a0a00ff8947c92f9d3fd43f58a24a6bc9039",
    )["proofs"]
    index = document(
        "source-proof-file-index.json",
        "775e407e3a57651c0c13fbd4cff1ea59364ced4d7da043e5de315943e4a757da",
    )
    rows = document(
        "registered-rows-raw.json",
        "695608318838b1697f23b2876cfb352b5b16db665c8685d3104903be004c9671",
    )
    require(
        rows["revision"] == index["revision"] == ORIGINAL_REVISION,
        "Historical source revision changed",
    )
    hashes = {k: v["sha256"] for k, v in index["files"].items()}
    hashes["README.md"] = rows["README_sha256"]
    lines = {}
    for row in rows["rows"]:
        lines.setdefault(row["registration"]["path"], []).append(row["line_sha256"])

    def read(name):
        raw = (folder / "raw" / name).read_bytes()
        if name in lines:
            require(
                [digest(line) for line in raw.splitlines()] == lines[name],
                "Historical split membership changed",
            )
        else:
            require(digest(raw) == hashes[name], "Historical source proof changed")
        return raw

    def lookup(name):
        p = proofs[name.lower()]
        require(
            p["status"] == "verified" and p["private"] is False,
            "Historical public repo identity missing",
        )
        return {
            "canonical_name": p["canonical_name"],
            "repository_id": p["repository_id"],
        }

    return read, lookup


def provider_reader(repo, revision):
    from huggingface_hub import HfApi, hf_hub_download

    info = HfApi().dataset_info(repo, revision=revision)
    require(
        info.id.casefold() == repo.casefold()
        and info.sha == revision
        and info.private is True,
        "Expected the explicitly named private dataset at its immutable revision",
    )

    def read(name):
        return Path(
            hf_hub_download(repo, name, repo_type="dataset", revision=revision)
        ).read_bytes()

    use_gh = (
        shutil.which("gh")
        and subprocess.run(
            ["gh", "auth", "status", "--hostname", "github.com"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode
        == 0
    )

    def lookup(name):
        if use_gh:
            payload = subprocess.check_output(
                ["gh", "api", "--hostname", "github.com", f"repos/{name}"], timeout=45
            )
            return repo_proof(json.loads(payload))
        request = Request(
            f"https://api.github.com/repos/{name}",
            headers={"User-Agent": "openenv-srs6-source-intake"},
        )
        with urlopen(request, timeout=30) as response:
            return repo_proof(json.load(response))

    def repo_proof(record):
        require(record["private"] is False, "Canonical repository must be public")
        return {"canonical_name": record["full_name"], "repository_id": record["id"]}

    return read, lookup


def image_identity(receipt):
    image = {k: receipt[k] for k in IMAGE_FIELDS if receipt.get(k) is not None}
    image["omitted_fields"] = [k for k in IMAGE_FIELDS if k not in image]
    require(
        re.fullmatch(IMAGE, image["image"])
        and re.fullmatch(REPO, image["space_id"])
        and re.fullmatch(GIT, image["space_commit"]),
        "Missing immutable starter image identity",
    )
    if "source_image" in image:
        require(re.fullmatch(IMAGE, image["source_image"]), "Mutable upstream image")
    for k in (
        "image_config_sha256",
        "context_inventory_sha256",
        "public_source_inventory_sha256",
    ):
        if k in image:
            require(re.fullmatch(HASH, image[k]), "Invalid image fingerprint")
    return image


def inventory_hash(raw, source):
    data = source.parsed(raw)
    require(isinstance(data, dict) and data, "Empty native inventory")
    for name, item in data.items():
        source.safe_path(name)
        require(
            set(item) == {"sha256", "size", "mode"}
            and re.fullmatch(HASH, item["sha256"])
            and type(item["size"]) is int
            and item["size"] >= 0
            and re.fullmatch("0o[0-7]{1,3}", item["mode"])
            and oct(int(item["mode"], 8)) == item["mode"],
            "Invalid native inventory path, file size, mode or digest",
        )
    return len(data), digest(
        json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    )


def build(repo, revision, read, lookup):
    require(
        re.fullmatch(REPO, repo) and re.fullmatch(GIT, revision),
        "Expected a repo ID and immutable revision",
    )
    source = parser_module()
    card = read("README.md")
    metadata, _ = source.metadata(card)
    names = {cfg["config_name"] for cfg in metadata["configs"]}
    source.ACCEPTED_CONFIGS = tuple(c for c in source.ACCEPTED_CONFIGS if c in names)
    require(source.ACCEPTED_CONFIGS, "No registered Scale800 accepted config")
    canonical = lru_cache(maxsize=None)(lookup)
    units, known_tasks = {}, {}
    for config, splits in source.accepted_paths(card).items():
        for split in splits:
            raw = read(split)
            split_hash = digest(raw)
            for line_no, line in enumerate(raw.splitlines(), 1):
                row = source.parsed(line)
                require(
                    row["language"] == source.LANGUAGES[config]
                    and row["gate_passed"] is True
                    and re.fullmatch(REPO, row["source_dataset"])
                    and re.fullmatch(GIT, row["source_revision"])
                    and re.fullmatch(GIT, row["source_commit"])
                    and not any(
                        row.get(flag) is True
                        for flag in (
                            "exclude_from_qwen",
                            "evaluation_only",
                            "holdout",
                            "benchmark_holdout",
                        )
                    ),
                    "Invalid source in registered accepted split",
                )
                name = row["upstream_repo"]
                require(
                    re.fullmatch(REPO, name), "Invalid canonical repository locator"
                )
                repository = canonical(name.casefold())
                require(
                    repository["canonical_name"].lower() == name.lower()
                    and type(repository["repository_id"]) is int
                    and repository["repository_id"] > 0,
                    "Upstream repository identity differs beyond letter case",
                )

                def proof(key):
                    path = source.safe_path(row[key])
                    data = read(path)
                    return data, {
                        "path": path,
                        "repo_id": repo,
                        "revision": revision,
                        "sha256": digest(data),
                    }

                inventory, native = proof("task_file_inventory_path")
                count, fingerprint = inventory_hash(inventory, source)
                require(
                    fingerprint == row["task_inventory_sha256"]
                    and re.fullmatch(HASH, row["task_source_sha256"]),
                    "Registered inventory or task digest differs",
                )
                native.update(files=count, full_inventory_canonical_sha256=fingerprint)
                receipt, image_ref = proof("image_receipt_path")
                identity = {
                    "source_dataset": row["source_dataset"],
                    "canonical_repository": repository,
                    "task_source_sha256": row["task_source_sha256"],
                    "task_inventory_sha256": fingerprint,
                    "image_identity": image_identity(source.parsed(receipt)),
                }
                key = digest(encode(identity))
                task_id = row["task_id"]
                require(
                    isinstance(task_id, str)
                    and task_id
                    and known_tasks.setdefault(task_id, key) == key,
                    "Conflicting source identity for task ID",
                )
                member = {
                    "config": config,
                    "split": "accepted",
                    "path": split,
                    "repo_id": repo,
                    "revision": revision,
                    "split_sha256": split_hash,
                    "line_number": line_no,
                    "line_sha256": digest(line),
                    "line_hash_excludes_terminator": True,
                }
                if key not in units:
                    units[key] = dict(
                        task_id=task_id,
                        row=row,
                        canonical_repo=repository["canonical_name"],
                        identity=identity,
                        unit_identity_sha256=key,
                        native_inventory=native,
                        image_receipt=image_ref,
                        language=row["language"],
                        memberships=[],
                    )
                require(
                    units[key]["task_id"] == task_id and units[key]["row"] == row,
                    "Conflicting source rows share a sampling identity",
                )
                units[key]["memberships"].append(member)
    require(units, "Empty sampling population")
    return {
        "schema": "repository-srs6-v1",
        "source_repo": repo,
        "revision": revision,
        "README_sha256": digest(card),
        "outcomes_used_for_selection": False,
        "population_count": len(units),
        "repo_counts": dict(Counter(u["canonical_repo"] for u in units.values())),
        "units": sorted(units.values(), key=lambda u: u["unit_identity_sha256"]),
    }


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("output", type=Path)
    cli.add_argument("--source-repo", required=True)
    cli.add_argument("--revision", required=True)
    cli.add_argument(
        "--historical-archive",
        type=Path,
        help="Offline source proofs for the original immutable 825-task population",
    )
    args = cli.parse_args()
    if args.output.exists() or args.output.is_symlink():
        raise FileExistsError(args.output)
    if args.historical_archive:
        require(
            (args.source_repo, args.revision) == (ORIGINAL, ORIGINAL_REVISION),
            "Historical archive belongs to the original source revision",
        )
        readers = historical_reader(args.historical_archive)
    else:
        require(
            re.fullmatch(GIT, args.revision) and re.fullmatch(REPO, args.source_repo),
            "Invalid immutable source locator",
        )
        readers = provider_reader(args.source_repo, args.revision)
    result = build(args.source_repo, args.revision, *readers)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=args.output.parent) as tmp:
        path = Path(tmp) / "population.json"
        path.write_bytes(encode(result))
        path.chmod(0o600)
        args.output.hardlink_to(path)
    print(
        f"{result['population_count']} units across {len(result['repo_counts'])} repositories"
    )


if __name__ == "__main__":
    main()
