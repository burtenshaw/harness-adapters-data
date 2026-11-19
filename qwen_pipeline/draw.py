"""Freeze an outcome-independent six-per-repository sample and capture its immutable evidence."""

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sys
import tempfile

REV = r"[0-9a-f]{40}"
HASH = r"[0-9a-f]{64}"
REPO = r"[A-Za-z0-9][\w.-]*/[A-Za-z0-9][\w.-]*"
ASSETS = {
    "seed.json",
    "sample.json",
    "outside-sample.json",
    "population.json",
    "selected-task-ids.json",
}
HISTORICAL_IDS = {"harness-hub/agentic-coding-envs", "harness-hub/harness-adapters"}


def encode(value):
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    ).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def rank_units(population, seed):
    if (
        not re.fullmatch(REV, population["revision"])
        or population.get("outcomes_used_for_selection") is not False
        or not re.fullmatch(HASH, seed)
    ):
        raise ValueError(
            "Expected an outcome-blind population, source revision and 32-byte seed"
        )
    groups = defaultdict(list)
    ids, identities, sources = set(), set(), set()
    for unit in population["units"]:
        task, identity, row = unit["task_id"], unit["identity"], unit["row"]
        unit_hash = digest(encode(identity))
        repo = identity["canonical_repository"]["canonical_name"].casefold()
        native = unit["native_inventory"]
        if (
            unit_hash != unit["unit_identity_sha256"]
            or unit_hash in identities
            or task in ids
            or repo != unit["canonical_repo"].casefold()
            or not re.fullmatch(REPO, repo)
            or not re.fullmatch(HASH, identity["task_inventory_sha256"])
            or not re.fullmatch(HASH, identity["task_source_sha256"])
            or not re.fullmatch(
                r"[^@\s]+@sha256:[0-9a-f]{64}", identity["image_identity"]["image"]
            )
            or row["task_id"] != task
            or row["task_source_sha256"] != identity["task_source_sha256"]
            or row["task_inventory_sha256"] != identity["task_inventory_sha256"]
            or native["full_inventory_canonical_sha256"]
            != identity["task_inventory_sha256"]
            or type(native["files"]) is not int
            or native["files"] <= 0
            or not unit["memberships"]
        ):
            raise ValueError(f"Invalid or duplicate population identity for {task}")
        for proof in [*unit["memberships"], native, unit["image_receipt"]]:
            if proof["revision"] != population["revision"]:
                raise ValueError("Population source revision conflict")
            sources.add(proof["repo_id"])
        rank = digest(
            b"openenv-qwen-srs6-v1\0" + bytes.fromhex(seed) + bytes.fromhex(unit_hash)
        )
        groups[repo].append(dict(unit, rank_sha256=rank))
        ids.add(task)
        identities.add(unit_hash)
    if len(sources) != 1 or not ids or population.get("population_count") != len(ids):
        raise ValueError("Incomplete population")
    source = sources.pop()
    if (
        not re.fullmatch(REPO, source)
        or population.get("source_repo", source) != source
    ):
        raise ValueError("Population source dataset conflict")
    sample, outside = [], []
    for repo in sorted(groups):
        ordered = sorted(
            groups[repo], key=lambda u: (u["rank_sha256"], u["unit_identity_sha256"])
        )
        sample.extend(ordered[:6])
        outside.extend(ordered[6:])
    # The original roster listed sampled units by rank, other units by identity.
    # Both lists used the upstream repository's canonical display spelling.
    sample.sort(
        key=lambda u: (u["canonical_repo"], u["rank_sha256"], u["unit_identity_sha256"])
    )
    outside.sort(key=lambda u: (u["canonical_repo"], u["unit_identity_sha256"]))
    return source, sample, outside


def draw(path, dest, seed):
    raw = path.read_bytes()
    population = json.loads(raw)
    recorded = datetime.now(timezone.utc).isoformat()
    source, sample, outside = rank_units(population, seed)
    seed_bytes = encode(
        dict(
            schema="public-srs-seed-v1",
            algorithm="sha256-hash-rank-v1",
            recorded_at=recorded,
            seed_hex=seed,
            seed_is_public_not_credential=True,
            outcome_lookup_performed=False,
            source_revision=population["revision"],
            source_repo=source,
            expected_population=dict(
                total=len(population["units"]),
                canonical_repositories=len(
                    {u["canonical_repo"].casefold() for u in population["units"]}
                ),
                **Counter(u["language"] for u in population["units"]),
            ),
        )
    )
    info = dict(
        schema="repository-srs6-v1",
        revision=population["revision"],
        source_repo=source,
        algorithm="sha256-hash-rank-v1",
        outcomes_used_for_selection=False,
        drawn_at=datetime.now(timezone.utc).isoformat(),
        population_sha256=digest(raw),
        seed_hex=seed,
        seed_receipt=dict(path="seed.json", sha256=digest(seed_bytes)),
        population_count=len(population["units"]),
        sample_count=len(sample),
    )
    sample_raw = encode(dict(info, units=sample))
    selected = defaultdict(list)
    for unit in sample:
        selected[unit["canonical_repo"]].append(unit["task_id"])
    blobs = {
        "population.json": raw,
        "seed.json": seed_bytes,
        "sample.json": sample_raw,
        "outside-sample.json": encode(dict(info, units=outside)),
        "selected-task-ids.json": encode(
            dict(
                revision=info["revision"],
                sample_sha256=digest(sample_raw),
                by_repo=selected,
            )
        ),
    }
    blobs["draw-manifest.json"] = encode(
        dict(info, files={name: digest(data) for name, data in blobs.items()})
    )
    install(dest, blobs)
    return dict(info, draw_sha256=digest(blobs["draw-manifest.json"]))


def install(dest, blobs):
    if dest.exists() or dest.is_symlink():
        raise FileExistsError(dest)
    dest.parent.mkdir(exist_ok=True, parents=True)
    with tempfile.TemporaryDirectory(dir=dest.parent) as tmp:
        stage = Path(tmp) / "files"
        stage.mkdir(mode=0o700)
        for name, raw in blobs.items():
            (stage / name).write_bytes(raw)
        stage.rename(dest)


def published(
    draw_dir, dest, repo, draw_sha, action, revision, *, api=None, download=None
):
    from huggingface_hub import CommitOperationAdd, HfApi, hf_hub_download

    if (
        not re.fullmatch(REPO, repo)
        or repo.casefold() in HISTORICAL_IDS
        or not re.fullmatch(REV, revision)
        or not re.fullmatch(HASH, draw_sha)
    ):
        raise ValueError(
            "Expected a new private source repository, immutable commit and draw manifest digest"
        )
    if dest.exists() or dest.is_symlink():
        raise FileExistsError(dest)
    manifest = (draw_dir / "draw-manifest.json").read_bytes()
    record = json.loads(manifest)
    if (
        digest(manifest) != draw_sha
        or set(record["files"]) != ASSETS
        or record["source_repo"] != repo
    ):
        raise ValueError("Draw manifest or source identity changed")
    files = {"draw-manifest.json": manifest}
    for name, h in record["files"].items():
        raw = (draw_dir / name).read_bytes()
        if digest(raw) != h:
            raise ValueError(f"Draw file changed: {name}")
        files[name] = raw
    prefix = f"results/qwen-difficulty-auto-v1/stratified-samples/srs6-{record['revision'][:8]}-v1/{draw_sha}/"
    api = api if api is not None else HfApi()
    download = download if download is not None else hf_hub_download

    def snapshot(rev=None):
        info = api.dataset_info(repo, revision=rev)
        if (
            info.id.casefold() != repo.casefold()
            or info.private is not True
            or not re.fullmatch(REV, info.sha)
            or (rev and info.sha != rev)
        ):
            raise ValueError(
                "Expected the named private source dataset at the requested revision"
            )
        return info.sha

    snapshot(record["revision"])
    if action == "publish":
        if snapshot() != revision:
            raise ValueError("Private source head changed since --parent")
        existing = api.get_paths_info(
            repo, [prefix.rstrip("/")], repo_type="dataset", revision=revision
        )
        if existing:
            raise ValueError(
                "Content-addressed draw prefix is already present; capture its immutable commit"
            )
        # Exclusive durable attempt marker prevents uncertain API effects from being retried.
        with (draw_dir / "publication-attempt.json").open("xb") as receipt:
            receipt.write(
                encode(
                    dict(
                        repo=repo, parent=revision, prefix=prefix, draw_sha256=draw_sha
                    )
                )
            )
            receipt.flush()
            os.fsync(receipt.fileno())
        commit = api.create_commit(
            repo_id=repo,
            repo_type="dataset",
            parent_commit=revision,
            operations=[
                CommitOperationAdd(path_in_repo=prefix + n, path_or_fileobj=b)
                for n, b in files.items()
            ],
            commit_message="Append frozen repository-stratified sampling evidence",
        )
        revision = commit.oid
        with (draw_dir / "publication-commit.json").open("xb") as receipt:
            receipt.write(encode(dict(repo=repo, revision=revision, prefix=prefix)))
    snapshot(revision)
    blobs, manifest = {}, {}
    for name, expected in files.items():
        value = download(repo, prefix + name, repo_type="dataset", revision=revision)
        data = value if isinstance(value, bytes) else Path(value).read_bytes()
        if data != expected:
            raise ValueError(f"Immutable readback differs: {name}")
        if name in {"seed.json", "sample.json", "selected-task-ids.json"}:
            label = name.removesuffix(".json").replace("-", "_")
            blobs[name] = data
            key = label + "-locator.json"
            blobs[key] = encode(
                dict(
                    repo_id=repo,
                    revision=revision,
                    path=prefix + name,
                    sha256=digest(data),
                )
            )
            manifest[label + "_bytes"] = name
            manifest[label + "_locator"] = key
    blobs["sample-manifest.json"] = encode(manifest)
    install(dest, blobs)
    return dict(
        repo=repo,
        revision=revision,
        prefix=prefix,
        sample_manifest=str(dest / "sample-manifest.json"),
    )


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    if sys.argv[1:2] in (["publish"], ["capture"]):
        action = sys.argv[1]
        parser.prog += " " + action
        parser.add_argument("draw", type=Path)
        parser.add_argument("capture", type=Path)
        parser.add_argument("--source-repo", required=True)
        parser.add_argument("--draw-sha256", required=True)
        parser.add_argument(
            "--parent" if action == "publish" else "--revision",
            dest="revision",
            required=True,
        )
        args = parser.parse_args(sys.argv[2:])
        result = published(
            args.draw,
            args.capture,
            args.source_repo,
            args.draw_sha256,
            action,
            args.revision,
        )
    else:
        parser.add_argument("population", type=Path)
        parser.add_argument("output", type=Path)
        parser.add_argument(
            "--seed", help="64 hex digits. Default is a new public random seed."
        )
        args = parser.parse_args()
        result = draw(args.population, args.output, args.seed or secrets.token_hex(32))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
