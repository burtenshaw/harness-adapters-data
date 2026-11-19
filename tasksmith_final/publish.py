"""Append a staged expansion to an existing private dataset with two parent-bound commits."""

import argparse
import fcntl
import hashlib
import json
import os
import re
from pathlib import Path

from common import inside, jsonl, read, require, scan_credentials, sha, write


def file_manifest(root):
    files = {}
    for path in sorted(root.rglob("*")):
        require(not path.is_symlink(), "symlink in export")
        if path.is_file() and path != root / "publish-summary.json":
            files[path.relative_to(root).as_posix()] = sha(path)
    return files


def add_configs(card, views):
    import yaml

    require(
        card.startswith("---\n"),
        "expected an existing dataset card with YAML frontmatter",
    )
    header, rest = card[4:].split("\n---\n", 1)
    before = yaml.safe_load(header)
    names = {c["config_name"] for c in before["configs"]}
    require(not names.intersection(views), "config names already exist")
    lines = header.splitlines()
    stop = lines.index("configs:") + 1
    while stop < len(lines) and (
        lines[stop].startswith(" ") or lines[stop].startswith("- ")
    ):
        stop += 1
    configs = [
        {"config_name": name, "data_files": [{"split": "train", "path": path}]}
        for name, path in views.items()
    ]
    lines[stop:stop] = yaml.safe_dump(configs, sort_keys=False).splitlines()
    updated = "\n".join(lines)
    require(
        yaml.safe_load(updated) == {**before, "configs": before["configs"] + configs},
        "card merge changed existing content",
    )
    return f"---\n{updated}\n---\n{rest}"


def remote_entries(api, repo, revision, paths):
    paths = list(paths)
    for offset in range(0, len(paths), 50):
        yield from api.get_paths_info(
            repo, paths[offset : offset + 50], repo_type="dataset", revision=revision
        )


def matches(entry, data):
    if getattr(entry, "lfs", None):
        return entry.lfs.sha256 == hashlib.sha256(data).hexdigest()
    return (
        getattr(entry, "blob_id", None)
        == hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest()
    )


def publish(args, api, operation, download):
    run = args.run.resolve(strict=True)
    cfg, stage = read(run / "campaign.json"), read(run / "stage-manifest.json")
    if cfg.get("source_repo") is not None:
        require(
            args.repo == cfg["source_repo"],
            "destination differs from bound source repository",
        )
    root = Path(stage["out"])
    require(
        file_manifest(root) == stage["files"],
        "staged files changed, prepare a new stage",
    )
    paths = stage["files"]
    for name in paths:
        scan_credentials(inside(root, name).read_bytes())
    tag = cfg["tag"]
    views = {
        name: f"views/{name}/{file}"
        for name, file in [
            (f"final_{tag}", "train.jsonl"),
            (f"final_best_{tag}", "train.jsonl"),
            (f"tasksmith_final_rejected_{tag}", "train.parquet"),
        ]
        if f"views/{name}/{file}" in paths
    }
    # Empty views are present in the local export but cannot be loaded by datasets.
    views = {k: v for k, v in views.items() if (root / v).stat().st_size}
    payload = [p for p in paths if not p.startswith("views/")]
    require(
        re.fullmatch("[a-f0-9]{40}", args.parent), "full parent dataset SHA required"
    )
    snapshot = run / "publication.json"
    identity = {
        "repo": args.repo,
        "parent": args.parent,
        "base_view": args.base_view,
        "stage_sha256": sha(run / "stage-manifest.json"),
    }
    state = read(snapshot) if snapshot.exists() else {**identity}
    require(
        all(state.get(k) == v for k, v in identity.items()),
        "existing receipt binds another export",
    )
    require(
        "pending" not in state,
        "ambiguous prior commit: reconcile the recorded parent and remote revision",
    )
    head = state.get("views_commit", state.get("files_commit", args.parent))
    info = api.dataset_info(args.repo)
    require(
        info.id == args.repo and info.private is True and info.sha == head,
        "expected private destination at the recorded head",
    )
    if args.base_view:
        base = Path(
            download(
                args.repo, args.base_view, repo_type="dataset", revision=args.parent
            )
        )
        require(
            sha(base) == cfg["base_sha256"],
            "remote baseline does not match the retained rows",
        )
    else:
        require(
            Path(cfg["base"]).stat().st_size == 0,
            "--base-view required for a nonempty baseline",
        )

    staged_locators = set(payload)
    for name in payload:
        staged_locators.update(p.as_posix() for p in Path(name).parents)
    locators = {
        relative
        for name, view in views.items()
        if view.endswith(".jsonl")
        for row in jsonl(root / view)
        for key, relative in row.items()
        if key.endswith("_path") and isinstance(relative, str) and relative
    }
    existing_locators = locators - staged_locators
    found = {
        e.path
        for e in remote_entries(api, args.repo, args.parent, sorted(existing_locators))
    }
    require(
        found == existing_locators,
        f"destination lacks {len(existing_locators - found)} referenced paths",
    )

    def commit(phase, entries, parent):
        current = api.dataset_info(args.repo)
        require(
            current.id == args.repo
            and current.private is True
            and current.sha == parent,
            "destination visibility or head changed",
        )
        state["pending"] = {"phase": phase, "parent": parent}
        write(snapshot, state)
        result = api.create_commit(
            args.repo,
            repo_type="dataset",
            operations=entries,
            parent_commit=parent,
            commit_message=f"Add Tasksmith {tag} {phase}",
        )
        del state["pending"]
        state[phase + "_commit"] = result.oid
        write(snapshot, state)
        return result.oid

    if "files_commit" not in state:
        existing = list(
            remote_entries(api, args.repo, head, [*payload, *views.values()])
        )
        # Original bundles and provenance may already be in the private dataset.
        # Reuse those only if their bytes match. New outputs always require new paths.
        originals = [
            row[key].rstrip("/") + "/"
            for _, row in cfg["selected"].values()
            for key in ("task_path", "provenance_path")
        ]
        reusable = set()
        for entry in existing:
            p = entry.path
            require(
                p.startswith(tuple(originals))
                and matches(entry, inside(root, p).read_bytes()),
                f"destination collision: {p}",
            )
            reusable.add(p)
        card = Path(
            download(args.repo, "README.md", repo_type="dataset", revision=head)
        ).read_text()
        add_configs(card, views)  # Check collisions/malformed card before either write.
        entries = [
            operation(path_in_repo=p, path_or_fileobj=str(inside(root, p)))
            for p in payload
            if p not in reusable
        ]
        if entries:
            head = commit("files", entries, head)
        else:
            state["files_commit"] = head
            write(snapshot, state)
    if "views_commit" not in state:
        card = Path(
            download(args.repo, "README.md", repo_type="dataset", revision=head)
        ).read_text()
        updated = add_configs(card, views)
        entries = [
            operation(path_in_repo=p, path_or_fileobj=str(inside(root, p)))
            for p in views.values()
        ]
        entries.append(
            operation(path_in_repo="README.md", path_or_fileobj=updated.encode())
        )
        head = commit("views", entries, head)
    expected = set(payload) | set(views.values())
    seen = set()
    for entry in remote_entries(api, args.repo, head, expected):
        require(
            matches(entry, inside(root, entry.path).read_bytes()),
            f"remote evidence differs: {entry.path}",
        )
        seen.add(entry.path)
    require(seen == expected, "incomplete revision readback")
    initial = Path(
        download(args.repo, "README.md", repo_type="dataset", revision=args.parent)
    ).read_text()
    final = Path(
        download(args.repo, "README.md", repo_type="dataset", revision=head)
    ).read_text()
    require(final == add_configs(initial, views), "remote config readback differs")
    state["verified_files"] = len(seen)
    write(snapshot, state)
    return state


def main():
    from huggingface_hub import CommitOperationAdd, HfApi, hf_hub_download

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    parser.add_argument("--repo", required=True, help="existing private dataset")
    parser.add_argument("--parent", required=True, help="expected full dataset commit")
    parser.add_argument(
        "--base-view", help="path to the base view on the destination dataset"
    )
    parser.add_argument(
        "--lock",
        required=True,
        type=Path,
        help="publication lock shared with writers of this dataset",
    )
    args = parser.parse_args()
    token = os.environ["HF_TOKEN"]
    api = HfApi(endpoint="https://huggingface.co", token=token)
    from functools import partial

    with args.lock.open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = publish(
            args,
            api,
            CommitOperationAdd,
            partial(hf_hub_download, token=token, endpoint="https://huggingface.co"),
        )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
