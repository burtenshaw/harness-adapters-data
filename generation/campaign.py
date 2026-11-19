"""Prepare Repo2RLEnv batch inputs and collect native-verified Harbor tasks."""

import argparse
import base64
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import tomllib
from urllib.parse import quote

HERE = Path(__file__).resolve().parent
COMMIT = "61903fe0ed805ea5418811b0fcf399e4144e95e4"
OPTIONS_SHA256 = "b1786575e5d13abcdfbec39892e49667baa23591b8ef994b93035529f622a58a"
WHEEL_SHA256 = "49589871dc0acf0286bfa11a2c8a4a84eae2aedd775f13d05cc78ae23b6236c6"
RECORDED_PLANS = {
    "v2": "89c98532060cef20e9ed965c8d554e6cdb0b399f3db51a66c0a74c3e51065a38",
    "v2-phase2": "e4cb115730e7f76090e69d9fc9d67f6ccbe227e2a21139f06cdb0ffc94b27593",
    "v3-recovery": "8eda6fdf592b43801096cf1d0bd10e80f7dbe460bb74fca9d62bce3399f3e868",
    "v4-native": "868fbff16ee1734c6a69391628cd5da3d73c2b48e535a11ab8b25bcd1438c0f3",
    "v4-recovery": "17f96f3f0cc57394fe2460ee21cca35e04e6dffb3af17ed3935c3828973cd215",
}


def formatted(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read(path):
    return json.loads(path.read_bytes())


def check_runtime():
    import repo2rlenv

    src = Path(repo2rlenv.__file__).resolve().parent
    checkout = src.parents[1]
    git = ["git", "-C", str(checkout)]
    head = subprocess.check_output(git + ["rev-parse", "HEAD"], text=True).strip()
    dirty = subprocess.check_output(
        git + ["status", "--porcelain", "--", "src", "uv.lock", "pyproject.toml"]
    )
    if src != checkout / "src/repo2rlenv" or head != COMMIT or dirty:
        raise ValueError(f"Use the frozen editable Repo2RLEnv checkout at {COMMIT}")


@contextmanager
def new_output(out):
    out = out.resolve()
    if out.exists():
        raise FileExistsError(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=out.parent, prefix=".tasksmith-") as tmp:
        stage = Path(tmp) / "output"
        stage.mkdir(mode=0o700)
        yield stage
        stage.rename(out)


def freeze(args):
    """Resolve a new PR panel once and bind license bytes to the same Git head."""
    from repo2rlenv.tasksmith.source import resolve_pr, validate_source_records

    panel = read(args.panel)
    urls = [row["url"] for row in panel]
    if not urls or len({u.casefold().rstrip("/") for u in urls}) != len(urls):
        raise ValueError("Supply a nonempty panel of distinct PRs")
    archived = None
    if args.source_evidence:
        rows = read(args.source_evidence)
        archived = {row["source"]["url"]: row for row in rows}
        if len(archived) != len(rows):
            raise ValueError("Archived source evidence repeats a PR")
    sources, pinned_panel = [], []
    with new_output(args.output) as out:
        for candidate in panel:
            url = candidate["url"]
            lic = candidate["license"]
            path = Path(lic["path"])
            if (
                not path.name
                or path.is_absolute()
                or ".." in path.parts
                or not lic["spdx"]
            ):
                raise ValueError(
                    f"Supply the repo-relative path and reviewed SPDX expression for {url}"
                )
            if archived is None:
                source = resolve_pr(url)
                repo = source["repo"].removeprefix("https://github.com/")
                api = f"repos/{repo}/contents/{quote(path.as_posix())}?ref={source['head']}"
                document = json.loads(subprocess.check_output(["gh", "api", api]))
                if document["type"] != "file" or document["encoding"] != "base64":
                    raise ValueError(
                        f"GitHub did not return the license file for {url}"
                    )
                data = base64.b64decode(document["content"])
                blob = hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest()
                if blob != document["sha"]:
                    raise ValueError(f"GitHub license blob digest disagrees for {url}")
            else:
                row = archived[url]
                source = row["source"]
                doc = row["license"]
                locator = f"{source['repo']}/blob/{source['head']}/{path.as_posix()}"
                data = doc["text"].encode()
                if (
                    doc["path"] != path.as_posix()
                    or doc["url"] != locator
                    or sha(data) != doc["sha256"]
                ):
                    raise ValueError(
                        f"Archived license is not bound to the PR head for {url}"
                    )
            validate_source_records([source], [url])
            pins = {k: source[k] for k in ("id", "base", "head")}
            pins["full_diff_sha256"] = sha(source["full_diff"].encode())
            if any(
                pins.get(k) != v for k, v in candidate.get("expected", {}).items()
            ) or lic.get("sha256", sha(data)) != sha(data):
                raise ValueError(f"Reviewed source or license changed for {url}")
            pinned_panel.append(
                {**candidate, "expected": pins, "license": {**lic, "sha256": sha(data)}}
            )
            sources.append(source)
            licenses = out / "licenses" / source["id"] / path
            licenses.parent.mkdir(parents=True)
            licenses.write_bytes(data)
        (out / "panel.json").write_bytes(formatted(pinned_panel))
        (out / "frozen-records.json").write_bytes(formatted(sources))
    print(f"Froze {len(sources)} sources and licenses")


def prepare(args):
    from repo2rlenv.tasksmith.batch import BatchPlan
    from repo2rlenv.tasksmith.source import resolve_pr, validate_source_records

    spec = read(args.spec)
    candidates = spec["candidates"]
    urls = [row["url"] for row in candidates]
    excluded = {url.lower().rstrip("/") for url in spec.get("excluded_prs", [])}
    keys = [url.lower().rstrip("/") for url in urls]
    if not urls or len(set(keys)) != len(keys) or excluded.intersection(keys):
        raise ValueError("Empty, duplicate, or excluded PR selection")
    if not (1 <= spec["target_verified"] <= len(urls)) or not spec["benchmarks"]:
        raise ValueError(
            "Supply benchmark names and a verified target within the candidate count"
        )
    for candidate in candidates:
        lic = candidate["license"]
        path = Path(lic["path"])
        if (
            not candidate["capability_tags"]
            or not lic["spdx"]
            or path.is_absolute()
            or ".." in path.parts
            or not path.name
            or not re.fullmatch(r"[0-9a-f]{64}", lic["sha256"])
        ):
            raise ValueError(
                f"Missing capability or invalid pinned license for {candidate['url']}"
            )
    if args.frozen_records:
        records = read(args.frozen_records)
        by_url = {record["url"]: record for record in records}
        if len(by_url) != len(records) or not set(urls).issubset(by_url):
            raise ValueError(
                "Frozen source inventory contains duplicates or lacks a selected PR"
            )
        sources = [by_url[url] for url in urls]
    else:
        sources = [resolve_pr(url) for url in urls]
    validate_source_records(sources, urls)
    options_bytes = (HERE / "options.json").read_bytes()
    if sha(options_bytes) != OPTIONS_SHA256:
        raise ValueError("Expansion quality options differ from the recorded profile")
    options = json.loads(options_bytes)
    entries = []
    for candidate, source in zip(candidates, sources, strict=True):
        expected = candidate.get("expected", {})
        actual = {**source, "full_diff_sha256": sha(source["full_diff"].encode())}
        if any(actual[key] != value for key, value in expected.items()):
            raise ValueError(f"Frozen source changed for {source['url']}")
        entries.append(
            {"url": source["url"], "source_record": source, "options": options}
        )
    plan = BatchPlan(
        name=spec["name"],
        candidates=entries,
        target_verified=spec["target_verified"],
        max_spend_usd=spec["max_spend_usd"],
        max_parallel=2,
        max_gpu_parallel=1,
    )
    if args.recorded_plan:
        data = args.recorded_plan.read_bytes()
        if sha(data) not in RECORDED_PLANS.values():
            raise ValueError("Historical plan digest is unknown")
        plan = BatchPlan.model_validate_json(data)
        selected = {r["url"]: r for r in sources}
        if any(selected.get(c.url) != c.source_record for c in plan.candidates):
            raise ValueError("Historical plan does not match the frozen source intake")
    else:
        data = formatted(plan.model_dump(mode="json"))
    with new_output(args.output) as out:
        (out / "launch-plan.json").write_bytes(data)
        (out / "intake.json").write_bytes(formatted(spec))
        (out / "binding.json").write_bytes(
            formatted(
                {
                    "repo2rlenv_commit": COMMIT,
                    "launch_plan_sha256": sha(data),
                    "intake_sha256": sha(formatted(spec)),
                    "options_sha256": OPTIONS_SHA256,
                }
            )
        )
    print(f"{len(plan.candidates)} PRs, launch plan SHA256 {sha(data)}")


def inventory(root):
    """Hash ordinary files and retain their POSIX modes, including directory modes."""
    records = {}
    for path in [root, *sorted(root.rglob("*"))]:
        mode = path.lstat().st_mode
        record = {"mode": stat.S_IMODE(mode)}
        if stat.S_ISREG(mode):
            if path.name in {
                ".env",
                "auth.json",
                "tasksmith.env",
                "modal.toml",
                "credential-status.json",
            } or path.name.endswith(".env"):
                raise ValueError(f"Review credential-named native asset: {path}")
            with path.open("rb") as handle:
                record["sha256"] = hashlib.file_digest(handle, "sha256").hexdigest()
        elif not stat.S_ISDIR(mode):
            raise ValueError(f"Unsupported native file type at {path}")
        records[path.relative_to(root).as_posix()] = record
    return records


def checked_path(path, root):
    absolute = Path(path).resolve(strict=True)
    if absolute != Path(path) or not absolute.is_relative_to(root):
        raise ValueError(f"Evidence path outside frozen candidate: {path}")
    return absolute


def copy_verified(batch, candidate, source, saved, out):
    from repo2rlenv.quality.loop.artifacts import task_identity
    from repo2rlenv.tasksmith.batch import verified_result

    source_id = source["id"]
    task_id = f"tasksmith-{source_id}"
    url = source["url"]
    candidate_root = (
        batch / "candidates" / sha(url.encode())[:12] / "candidates" / source_id
    )
    quality = checked_path(saved["quality_result"], candidate_root)
    if (
        quality != candidate_root / "quality/result.json"
        or verified_result(quality) != saved
        or saved["url"] != url
    ):
        raise ValueError(f"Native quality proof changed for {url}")
    label_path = quality.with_name("labeled-task.json")
    label = read(label_path)
    task = checked_path(label["task_path"], quality.parent / "labeled")
    if (
        task.name != task_id
        or label["state"] != "completed"
        or label["status"] != "verified"
        or label["quality_result"] != str(quality)
        or label["quality_result_sha256"] != saved["quality_sha256"]
        or label["bundle_hash"] != saved["bundle_hash"]
    ):
        raise ValueError(f"Quality label disagrees with native proof for {url}")
    files = inventory(task)
    dest = out / "tasks" / task_id
    shutil.copytree(task, dest, symlinks=True)
    if files != inventory(dest) or task_identity(dest) != saved["bundle_hash"]:
        raise ValueError(f"Copied native task changed for {url}")
    meta = tomllib.loads((dest / "task.toml").read_text())["metadata"]["repo2env"]
    required = {
        "source_url": url,
        "source_head": source["head"],
        "source_base": source["base"],
        "source_diff_sha256": sha(source["source_diff"].encode()),
        "recipe": "tasksmith",
        "workspace_strategy": source["workspace_strategy"],
    }
    if any(meta.get(k) != v for k, v in required.items()):
        raise ValueError(f"Copied task metadata differs from its frozen PR for {url}")
    lic = candidate["license"]
    license_path = dest / "environment/source" / lic["path"]
    if not license_path.is_file() or sha(license_path.read_bytes()) != lic["sha256"]:
        raise ValueError(f"Bundled source license differs from intake for {url}")
    provenance = out / "provenance" / source_id
    provenance.mkdir(parents=True)
    for name, data in {
        "source.json": formatted(source),
        "candidate-intake.json": formatted(candidate),
        "quality-result.json": quality.read_bytes(),
        "quality-label.json": label_path.read_bytes(),
        "native-proof.json": formatted(saved),
        "files.json": formatted(files),
    }.items():
        (provenance / name).write_bytes(data)
    return {
        "task_id": task_id,
        "task_path": dest.relative_to(out).as_posix(),
        "provenance_path": provenance.relative_to(out).as_posix(),
        "source_repo": source["repo"],
        "source_head_commit": source["head"],
        "source_pr_url": url,
        "source_license_spdx": lic["spdx"],
        "split": "candidates",
        "tasksmith_verified": True,
        "tasksmith_bundle_hash": saved["bundle_hash"],
        "semantic_nonoverlap_established": False,
        "target_model_calibrated": False,
    }


def collect(args):
    from repo2rlenv.execution.artifacts import check_runtime_wheel

    prepared, batch = args.prepared.resolve(), args.batch.resolve()
    binding = read(prepared / "binding.json")
    spec_bytes = (prepared / "intake.json").read_bytes()
    plan_bytes = (prepared / "launch-plan.json").read_bytes()
    if (
        sha(spec_bytes) != binding["intake_sha256"]
        or sha(plan_bytes) != binding["launch_plan_sha256"]
        or binding["repo2rlenv_commit"] != COMMIT
        or binding["options_sha256"] != OPTIONS_SHA256
    ):
        raise ValueError("Prepared intake or launch plan changed")
    spec, plan = json.loads(spec_bytes), json.loads(plan_bytes)
    intake = {c["url"]: c for c in spec["candidates"]}
    sources = {c["url"]: c["source_record"] for c in plan["candidates"]}
    config = read(batch / "configuration.json")
    expected = (
        RECORDED_PLANS[args.recorded_phase] if args.recorded_phase else sha(plan_bytes)
    )
    if sha(formatted(config["plan"])) != expected:
        raise ValueError("Batch configuration differs from the requested plan")
    admitted = {c["url"]: c["source_record"] for c in config["plan"]["candidates"]}
    if any(
        sources.get(url) != source or url not in intake
        for url, source in admitted.items()
    ):
        raise ValueError("Batch used different frozen PR records")
    wheel = checked_path(config["wheel"], batch / "runtime")
    if (
        check_runtime_wheel(wheel) != config["runtime"]
        or config["runtime"] != WHEEL_SHA256
    ):
        raise ValueError("Batch wheel and controller disagree")
    report = read(batch / "report.json")
    if (
        not report.get("stop_reason")
        or not set(report["candidates"]).issubset(admitted)
        or any(
            row["status"] == "running"
            or row.get("cleanup_pending")
            or row.get("reason_code") == "interrupted_controller"
            for row in report["candidates"].values()
        )
    ):
        raise ValueError("Batch has no terminal report or has unresolved children")
    with new_output(args.output) as out:
        rows = []
        for url, row in report["candidates"].items():
            if row["status"] == "verified":
                rows.append(
                    copy_verified(
                        batch, intake[url], sources[url], row["verified"], out
                    )
                )
        if report["new_verified"] != len(rows) or len(
            {r["tasksmith_bundle_hash"] for r in rows}
        ) != len(rows):
            raise ValueError(
                "Native report count or distinct bundle count differs from accepted rows"
            )
        (out / "verified.jsonl").write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows)
        )
        (out / "generation-report.json").write_bytes(
            formatted(
                {
                    "benchmarks": spec["benchmarks"],
                    "batch_directory": str(batch),
                    "repo2rlenv_commit": COMMIT,
                    "wheel_sha256": config["runtime"],
                    "launch_plan_sha256": expected,
                    "report_sha256": sha((batch / "report.json").read_bytes()),
                    "stop_reason": report["stop_reason"],
                    "statuses": {
                        url: row["status"] for url, row in report["candidates"].items()
                    },
                    "pending": report.get("pending"),
                    "new_verified": len(rows),
                }
            )
        )
    print(f"{len(rows)} native-verified tasks exported")


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    actions = cli.add_subparsers(required=True)
    freeze_cmd = actions.add_parser(
        "freeze",
        help="Freeze merged PRs and source licenses using read-only GitHub intake",
    )
    freeze_cmd.add_argument("panel", type=Path)
    freeze_cmd.add_argument("output", type=Path)
    freeze_cmd.add_argument(
        "--source-evidence",
        type=Path,
        help="Read historical source/license pairs offline in place of GitHub",
    )
    freeze_cmd.set_defaults(run=freeze)
    prep = actions.add_parser("prepare")
    prep.add_argument("spec", type=Path)
    prep.add_argument("output", type=Path)
    prep.add_argument(
        "--recorded-plan",
        type=Path,
        help="Restore the exact phase-specific plan, including its historical evidence references",
    )
    intake = prep.add_mutually_exclusive_group(required=True)
    intake.add_argument(
        "--frozen-records",
        type=Path,
        help="Select from a local array of Repo2RLEnv PR records",
    )
    intake.add_argument(
        "--resolve",
        action="store_true",
        help="Fetch and freeze PR records with the pinned GitHub intake",
    )
    prep.set_defaults(run=prepare)
    export = actions.add_parser("collect")
    export.add_argument("prepared", type=Path)
    export.add_argument("batch", type=Path)
    export.add_argument("output", type=Path)
    export.add_argument(
        "--recorded-phase",
        choices=RECORDED_PLANS,
        help="Replay a named historical plan and its exact hash",
    )
    export.set_defaults(run=collect)
    args = cli.parse_args()
    check_runtime()
    args.run(args)


if __name__ == "__main__":
    main()
