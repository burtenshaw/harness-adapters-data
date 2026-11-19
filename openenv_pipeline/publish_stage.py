"""Register a local semantic-gate stage on an explicitly named private dataset."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import tempfile

HERE = Path(__file__).resolve().parent
CONFIGS = {
    "scale800_gate_v1": ("scale800-private-gate-publication-v1", "scale800_v1"),
    "scale800_py_gate_v1": (
        "scale800-python-private-gate-publication-v1",
        "scale800_py_v1",
    ),
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def publisher():
    name = "production/python-gate-publication-v5/publish.py"
    path = HERE / "operators" / name
    pins = json.loads((HERE / "pins.json").read_bytes())["operator_files_sha256"]
    if sha(path.read_bytes()) != pins[name]:
        raise ValueError("Historical card registration helper changed")
    spec = importlib.util.spec_from_file_location("gate_publication", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def frozen(stage, plan_digest):
    helper = publisher()
    plan = helper.parsed(helper.captured(stage / "plan.json", plan_digest))
    schema, prefix = CONFIGS[plan["config"]]
    batch = plan["batch_id"]
    split = f"splits/{plan['config']}-{batch}.jsonl"
    if (
        plan["schema"] != schema
        or not re.fullmatch("[a-z0-9][a-z0-9._-]{0,63}", batch)
        or plan["split_path"] != split
        or split not in plan["files"]
    ):
        raise ValueError("Malformed accepted split registration")
    if not 1 <= len(plan["files"]) <= 4999:
        raise ValueError("Unexpected staged file count")
    root = (stage / "files").resolve(strict=True)
    manifests = [
        name
        for name in plan["files"]
        if re.fullmatch(
            re.escape(prefix)
            + r"/[a-z0-9][a-z0-9._-]{0,63}/batches/"
            + re.escape(batch)
            + "/file-sha256.json",
            name,
        )
    ]
    if len(manifests) != 1:
        raise ValueError("Expected one campaign file manifest")
    campaign = manifests[0].split("/batches/")[0] + "/"
    files = {}
    for name, digest in plan["files"].items():
        rel = helper.safe(name)
        dest = stage / "files" / rel
        if (name != split and not name.startswith(campaign)) or dest.resolve(
            strict=True
        ) != root / rel:
            raise ValueError("Stage path outside the declared campaign")
        files[name] = helper.captured(dest, digest)
        if (
            "file_modes" in plan
            and oct(stat.S_IMODE(dest.stat().st_mode)) != plan["file_modes"][name]
        ):
            raise ValueError(f"Staged POSIX mode changed for {name}")
    manifest = helper.parsed(files[manifests[0]])
    if set(manifest) != set(files) - set(manifests) or any(
        item != {"sha256": plan["files"][name], "size": len(files[name])}
        for name, item in manifest.items()
    ):
        raise ValueError("Staged file manifest differs from its plan")
    rows = [helper.parsed(line) for line in files[split].splitlines()]
    if (
        len({r["task_id"] for r in rows}) != len(rows)
        or not rows
        or len(rows) != plan["summary"]["tasks"]
        or any(r["gate_passed"] is not True for r in rows)
    ):
        raise ValueError("Stage contains duplicate or unaccepted rows")
    # Use the historical accepted-split merger (global repo cap, config and body preservation).
    helper.CONFIG = plan["config"]
    return helper, plan, files


def save(path, record):
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        tmp = Path(stream.name)
        stream.write((json.dumps(record, indent=2, sort_keys=True) + "\n").encode())
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(tmp, path)


def publish(
    stage,
    plan_digest,
    repo,
    action,
    revision=None,
    *,
    api=None,
    download=None,
    token=None,
):
    from huggingface_hub import CommitOperationAdd, HfApi, get_token, hf_hub_download

    if not re.fullmatch(r"[\w.-]+/[\w.-]+", repo) or repo.casefold() in {
        "harness-hub/agentic-coding-envs",
        "harness-hub/harness-adapters",
    }:
        raise ValueError("Supply the new private destination by owner/name")
    helper, plan, files = frozen(stage, plan_digest)
    # The local check never reads credentials or constructs a Hub client.
    if action == "check":
        return dict(
            status="stage_verified",
            config=plan["config"],
            split_path=plan["split_path"],
            tasks=plan["summary"]["tasks"],
            files=len(files),
            plan_sha256=plan_digest,
        )
    token = token or get_token()
    if not token:
        raise ValueError("Hugging Face authentication required")
    api = api if api is not None else HfApi(token=token)
    download = hf_hub_download if download is None else download

    def snapshot(rev=None):
        info = api.dataset_info(repo, revision=rev, token=token, timeout=120)
        if (
            info.private is not True
            or info.id.casefold() != repo.casefold()
            or not re.fullmatch("[0-9a-f]{40}", info.sha)
            or (rev and info.sha != rev)
        ):
            raise ValueError(
                "Destination must be the named private dataset at the requested revision"
            )
        return info.sha

    def read(name, rev):
        result = download(repo, name, repo_type="dataset", revision=rev, token=token)
        return result if isinstance(result, bytes) else Path(result).read_bytes()

    journal = stage / "registration.json"
    with (stage / ".registration.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if action == "publish":
            if journal.exists():
                raise FileExistsError(
                    f"Prior registration attempt recorded in {journal}"
                )
            parent = snapshot()
            # Check every planned path at this exact immutable parent. The CAS prevents concurrent edits.
            wanted = [*files, "README.md"]
            existing = set()
            for start in range(0, len(wanted), 100):
                paths = api.get_paths_info(
                    repo,
                    wanted[start : start + 100],
                    repo_type="dataset",
                    revision=parent,
                    token=token,
                )
                existing.update(item.path for item in paths)
            for name in existing.intersection(files):
                if read(name, parent) != files[name]:
                    raise ValueError(
                        f"Existing private path has different bytes: {name}"
                    )
            card = read("README.md", parent) if "README.md" in existing else b""
            original = card if card.startswith(b"---\n") else b"---\n{}\n---\n" + card
            import yaml

            metadata = yaml.safe_load(original.decode().split("\n---\n", 1)[0][4:])
            prior_paths = helper.accepted_paths(metadata)
            with ThreadPoolExecutor(max_workers=8) as pool:
                indices = dict(
                    pool.map(lambda name: (name, read(name, parent)), prior_paths)
                )
            updated = helper.merge_card(original, plan, files, indices)
            values = [token] + [
                os.environ[k]
                for k in ("HF_SANDBOX_TOKEN", "HF_INFERENCE_TOKEN")
                if os.environ.get(k)
            ]
            helper.parent().scan({**files, "README.md": updated}, values)
            additions = [
                CommitOperationAdd(path_in_repo=name, path_or_fileobj=raw)
                for name, raw in files.items()
                if name not in existing
            ]
            additions.append(
                CommitOperationAdd(path_in_repo="README.md", path_or_fileobj=updated)
            )
            if snapshot() != parent:
                raise ValueError("Destination changed during preparation")
            record = dict(
                status="commit_uncertain",
                repository=repo,
                plan_sha256=plan_digest,
                parent=parent,
                config=plan["config"],
                split_path=plan["split_path"],
                card_before_sha256=sha(card),
                card_after_sha256=sha(updated),
                files=len(files),
            )
            save(journal, record)
            committed = api.create_commit(
                repo,
                repo_type="dataset",
                operations=additions,
                token=token,
                parent_commit=parent,
                commit_message="Register accepted coding tasks " + plan["batch_id"],
            )
            record.update(status="committed_readback_pending", revision=committed.oid)
            save(journal, record)
        else:
            record = json.loads(journal.read_bytes())
            if (
                record["repository"] != repo
                or record["plan_sha256"] != plan_digest
                or revision
                and record.get("revision", revision) != revision
            ):
                raise ValueError(
                    "Readback request differs from the recorded publication"
                )
        rev = record.get("revision") or revision
        if not rev or not re.fullmatch("[0-9a-f]{40}", rev):
            raise ValueError("Recovery needs the known immutable commit revision")
        snapshot(rev)
        expected = {**plan["files"], "README.md": record["card_after_sha256"]}

        def verify(item):
            name, digest = item
            if sha(read(name, rev)) != digest:
                raise ValueError(f"Immutable readback mismatch for {name}")

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(verify, expected.items()))
        record.update(
            status="immutable_readback_verified",
            revision=rev,
            readback_files=len(expected),
        )
        save(journal, record)
        return record


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "publish", "verify"))
    parser.add_argument("stage", type=Path)
    parser.add_argument("--plan-sha256", required=True)
    parser.add_argument("--repo", required=True)
    parser.add_argument(
        "--revision",
        help="Known immutable commit for read-only recovery after an ambiguous response",
    )
    args = parser.parse_args()
    os.umask(0o077)
    print(
        json.dumps(
            publish(
                args.stage.resolve(),
                args.plan_sha256,
                args.repo,
                args.action,
                args.revision,
            ),
            indent=2,
        )
    )
