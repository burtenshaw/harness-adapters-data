"""Rebuild the original Scale800 target-only operators in a fresh local campaign."""

import argparse
from decimal import Decimal
import hashlib
import importlib
import json
import os
import re
import shutil
import stat
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

HERE = Path(__file__).resolve().parent
SOURCE_LOCK = json.loads((HERE / "source-lock.json").read_bytes())
ORIGINAL_REPO = "harness-hub/agentic-coding-envs"
DEFAULT_CACHE = HERE.parent / ".sources/qwen"
SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}\Z")
REPO_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*\Z")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def source_bytes(source, name):
    data = (source / name).read_bytes()
    if sha(data) != SOURCE_LOCK[name]:
        raise ValueError(f"Source fingerprint changed: {name}")
    return data


PRIVATE_COST_FILES = {"bulk-v1/retest-cost.json", "bulk-v1/retest-cost-receipts.json"}


def shipped_sources():
    """The archive stores each unique byte string once, indexed by its SHA256."""
    with tarfile.open(HERE / "operator-sources.tar.xz", "r:xz") as packed:
        contents = {
            entry.name: packed.extractfile(entry).read()
            for entry in packed
            if entry.isfile()
        }
    expected = {v for k, v in SOURCE_LOCK.items() if k not in PRIVATE_COST_FILES}
    if set(contents) != expected or any(sha(data) != h for h, data in contents.items()):
        raise ValueError("Operator source pack differs from its lock")
    return contents


def install(source, dest, *, relocate=False):
    """Copy only the enumerated sources. The cache retains original bytes."""
    dest = dest.absolute()
    if dest.exists():
        raise FileExistsError(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=dest.parent) as temp:
        root = Path(temp) / "snapshot"
        bundled = {} if relocate else shipped_sources()
        for name, digest in SOURCE_LOCK.items():
            if not relocate and digest in bundled:
                data = bundled[digest]
            elif name in PRIVATE_COST_FILES and not (source / name).is_file():
                # The exact Go budget forecast consumes these two private, checksum-bound records.
                continue
            else:
                data = source_bytes(source, name)
            if relocate and name == "core.py":
                data = data.replace(
                    b"Path('/Users/ben/.local/share/openenv-qwen-difficulty')",
                    b"Path(__file__).resolve().parent",
                )
                data = data.replace(
                    b"'/Users/ben/.t3/worktrees/OpenEnv/ben-hub-validation-pipeline/src'",
                    b"str(ROOT / 'bulk-v1/operator/src')",
                )
            out = root / name
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(data)
        root.rename(dest)


def bind_source_repository(bulk, repo):
    """Recompile the original single-repository approvals for the chosen private mirror."""
    if not REPO_ID.fullmatch(repo):
        raise ValueError("Expected a source dataset in owner/name form")
    if repo == ORIGINAL_REPO:
        return

    def edit(name, before, after, count=1):
        path = bulk / name
        raw = source_bytes(bulk.parent, "bulk-v1/" + name)
        if raw.count(before) != count:
            raise ValueError(f"Unexpected repository binding in {name}")
        updated = raw.replace(before, after)
        compile(updated, str(path), "exec")
        path.write_bytes(updated)
        return sha(updated).encode()

    original, chosen = repr(ORIGINAL_REPO).encode(), repr(repo).encode()
    helper = "candidate_optional.py"
    helper_sha = edit(helper, original, chosen, count=2)
    edit("gate_target_only.py", SOURCE_LOCK["bulk-v1/" + helper].encode(), helper_sha)

    # Python's source factory checks the original parent before compiling rosters.
    # Rebind the one location check in its output; keep the parent pins intact.
    before = b"gate['repo_id'] != " + original
    after = b"gate['repo_id'] != " + chosen
    target = b"    output['examples/coding_audit/scoring.py']=_rosters(scoring,configs).encode()"
    replacement = (
        f"    scoring=change(scoring,{before.decode()!r},{after.decode()!r})\n".encode()
        + target
    )
    edit("python_operator_r3_v3.py", target, replacement)
    builder = "python_operator_r3_v4.py"
    builder_sha = edit(builder, target, replacement)
    edit("four_target_v3.py", SOURCE_LOCK["bulk-v1/" + builder].encode(), builder_sha)


def check_native(directory, row, repo):
    if (
        row.get("status") != "acquired"
        or row.get("readiness_accepted") is not True
        or not SAFE_ID.fullmatch(row["task_id"])
    ):
        raise ValueError("A reviewed, accepted source acquisition is required")
    source = row["source"]
    if source["repo_id"] != repo or not re.fullmatch(
        "[a-f0-9]{40}", source["revision"]
    ):
        raise ValueError("Expected an immutable published source revision")
    raw = (directory / "native.zip").read_bytes()
    if sha(raw) != row["native_zip_sha256"]:
        raise ValueError("Native archive hash differs")
    with zipfile.ZipFile(directory / "native.zip") as archive:
        members = archive.infolist()
        if len(members) != len(row["files"]) or {m.filename for m in members} != set(
            row["files"]
        ):
            raise ValueError("Native archive membership differs")
        for m in members:
            path = PurePosixPath(m.filename)
            if (
                path.is_absolute()
                or ".." in path.parts
                or path.as_posix() != m.filename
                or not stat.S_ISREG(m.external_attr >> 16)
            ):
                raise ValueError("Unexpected native archive member")
            record = row["files"][m.filename]
            if (
                m.file_size != record["bytes"]
                or stat.S_IMODE(m.external_attr >> 16) != record["mode"]
                or source["task_file_hashes"][m.filename] != record["sha256"]
                or sha(archive.read(m)) != record["sha256"]
            ):
                raise ValueError(f"Native member differs: {m.filename}")


def runtime_paths(run):
    bulk = run / "bulk-v1"
    sys.path[:0] = list(map(str, (bulk, run, bulk / "operator", bulk / "operator/src")))
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    sys.dont_write_bytecode = True
    return bulk


def read_acquisition(directory, core, repo):
    row = core.loads((directory / "acquisition.json").read_bytes())
    check_native(directory, row, repo)
    config_raw = (directory / "config.json").read_bytes()
    config = core.loads(config_raw)
    gate = row["candidate_optional_gate_identity"]
    if (
        gate["repo_id"] != repo
        or gate["revision"] != row["source"]["revision"]
        or gate["report_path"] != row["source_metadata"]["gate_report_path"]
    ):
        raise ValueError("Gate identity differs from the acquired source")
    target = core.loads(
        (
            Path(core.ROOT)
            / "cycles/20261112-maxlen-nothink-canary-v1/effective-config.json"
        ).read_bytes()
    )["target"]
    target.pop("provider_model_id", None)
    target["max_total_tokens"] = 2_000_000
    if (
        config["target"] != target
        or config["execution"]["timeout_seconds"] != 1800
        or config["seeds"] != list(range(8))
        or target["temperature"] != Decimal("0.7")
    ):
        raise ValueError(
            "The source does not match the recorded Qwen R3 model and attempt settings"
        )
    if row.get("config_sha256"):
        if sha(config_raw) != row["config_sha256"] or any(
            config["source_gate"][key] != value for key, value in gate.items()
        ):
            raise ValueError("Python source config changed")
    else:
        bound = dict(
            files=row["files"],
            config=config,
            protocol="qwen38-auto48-64k-2m-nothink-v1",
        )
        if sha(core.json_bytes(bound)) != row["source_config_identity_sha256"]:
            raise ValueError("Go source config changed")
    return row, config


def checked_draw(directory, repo, four):
    from draw import rank_units

    names = ("sample.json", "outside-sample.json")
    sample, outside = [(directory / name).read_bytes() for name in names]
    record = json.loads((directory / "draw-manifest.json").read_bytes())
    hashes = (sha(sample), sha(outside))
    if hashes != tuple(record["files"][name] for name in names):
        raise ValueError("Frozen sample bytes differ from the draw manifest")
    if "source_repo" not in record:
        if repo != ORIGINAL_REPO or hashes != (
            four.SRS_SAMPLE_SHA,
            four.SRS_OUTSIDE_SHA,
        ):
            raise ValueError(
                "Expected the archived original draw and source repository"
            )
    else:
        population = (directory / "population.json").read_bytes()
        seed = (directory / "seed.json").read_bytes()
        if (
            record["source_repo"] != repo
            or sha(population) != record["files"]["population.json"]
            or sha(seed) != record["files"]["seed.json"]
            or json.loads(seed)["seed_hex"] != record["seed_hex"]
        ):
            raise ValueError("Sampling population, seed or source repository changed")
        origin, chosen, remaining = rank_units(
            json.loads(population), record["seed_hex"]
        )
        if (
            origin != repo
            or json.loads(sample)["units"] != chosen
            or json.loads(outside)["units"] != remaining
        ):
            raise ValueError(
                "Sample membership differs from the frozen source population"
            )
    return sample, outside


def prepare(args):
    run = args.run.resolve()
    install(args.cache, run, relocate=True)
    bulk = runtime_paths(run)
    import core

    directory = args.acquisition.resolve()
    row, config = read_acquisition(directory, core, args.source_repo)
    bind_source_repository(bulk, args.source_repo)
    config["cloud"]["results_repo"] = args.results_repo
    operator = bulk / "operator-r3"
    cycle = run / "cycles/r3"
    if "adapter_version" in row:
        # Rebind persistence only, on a private copy. Preserve source bytes and modes.
        copy = run / "incoming/source"
        copy.mkdir(mode=0o700, parents=True)
        # Only the native archive and reviewed helper bytes enter the private copy.
        for name in (
            "native.zip",
            "platforms.json",
            "readiness.json",
            "gate-jobs.json",
            "gate-replay.json",
        ):
            shutil.copyfile(directory / name, copy / name)
        prefix = (
            Path("hub")
            / core.safe_path(row["source_metadata"]["adapter_implementation_path"])
            / "repo"
        )
        for name, digest in row["helper_hashes"].items():
            helper = prefix / core.safe_path(name)
            raw = (directory / helper).read_bytes()
            if sha(raw) != digest:
                raise ValueError(f"Adapter helper changed: {name}")
            (copy / helper).parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            (copy / helper).write_bytes(raw)
        core.atomic(copy / "config.json", config)
        row.update(
            config_sha256=sha((copy / "config.json").read_bytes()),
            task_directory=str(copy),
        )
        core.atomic(copy / "acquisition.json", row)
        builder = importlib.import_module(
            "python_operator_r3_v4"
            if int(row["adapter_version"]) == 3
            else "python_operator_r3_v3"
        )
        if config["profile"] != builder.PROFILE:
            raise ValueError(
                f"Expected a native-suite acquisition from the matching intake profile {builder.PROFILE}"
            )
        builder.build([copy], operator, helper_authorities=args.helper_authority)
        prepared = builder.prepare(operator, [copy], cycle, max_parallel=1)
    else:
        if any(not (run / name).is_file() for name in PRIVATE_COST_FILES):
            raise ValueError(
                "Go R3 preparation needs both historical cost receipt files. Restore them in the runtime cache."
            )
        import target_only_operator as builder
        from examples.coding_audit.runner import normalize_coding_config

        gate = dict(row["candidate_optional_gate_identity"])
        report = (directory / "hub" / core.safe_path(gate["report_path"])).read_bytes()
        if (
            sha(report) != gate["report_sha256"]
            or gate["revision"] != row["source"]["revision"]
        ):
            raise ValueError("Source gate bytes or revision changed")
        gate["report_json"] = report.decode()
        jobs = (directory / "gate-jobs.json").read_bytes()
        config.update(
            profile=builder.PROFILE,
            source_gate=gate,
            source_gate_jobs=dict(receipt_json=jobs.decode(), receipt_sha256=sha(jobs)),
            generation={"candidate_count": 0},
        )
        config["validation"]["reference_repeats"] = 2
        config = builder.freeze_config(config, normalize_coding_config)
        config["cloud"]["max_inference_calls"] = 1152
        readiness = core.loads((directory / "readiness.json").read_bytes())
        if (
            readiness["gate_source_sha256"]
            != "aff5529192d01dad7b987726cb932300e904bfa93e74aecedec7b6f34eee6cc3"
        ):
            raise ValueError("Unknown Go gate implementation")
        row["task_directory"] = str(directory)
        rows = [
            dict(
                acquisition=row,
                config=config,
                gate_scorer_sha256=readiness["gate_source_sha256"],
            )
        ]
        builder.build(
            rows,
            bulk / "operator",
            operator,
            bulk / "operator-2m-wave1-v5/examples/coding_audit/cost-projection.json",
            max_parallel=1,
        )
        prepared = builder.prepare(rows, operator, cycle, max_parallel=1)
    if len(prepared["tasks"]) != 1:
        raise ValueError("Acquisition could not produce a bound target plan")
    p = prepared["tasks"][0]
    manifest = cycle / "prepared/manifest.json"
    if args.draw:
        import four_target_v3 as four

        sample, outside = checked_draw(args.draw, args.source_repo, four)
        # Membership pins in the historical builder were specific to its first 825 rows.
        four.SRS_SAMPLE_SHA, four.SRS_OUTSIDE_SHA = sha(sample), sha(outside)
        frozen = run / "incoming/srs6-repo-3afa3ffb-v1"
        frozen.mkdir(parents=True)
        for name, raw in (("sample.json", sample), ("outside-sample.json", outside)):
            (frozen / name).write_bytes(raw)
        r3_plan = cycle / "prepared" / p["plan_path"]
        with zipfile.ZipFile(r3_plan.parent / "bundle.zip") as bundle:
            config = core.loads(bundle.read("coding-config.json"))
        additions = None
        if args.outside_additions:
            additions = args.outside_additions.read_bytes()
            original_additions = run / "incoming/outside-final22-051d-v3/authority.json"
            original_additions.parent.mkdir(parents=True)
            original_additions.write_bytes(additions)
        route = four.route(
            row["task_id"],
            config,
            sample_raw=sample,
            outside_raw=outside,
            additions_raw=additions,
        )
        if not route["is_stratified_sample"]:
            a4 = bulk / "operator-a4"
            four.build(operator, a4, [config], [route])
            dest = run / "cycles/a4"
            p = four.prepare_from_plan(a4, r3_plan, p, dest)
            manifest = dest / "prepared/manifest.json"
            operator = a4
        core.atomic(run / "sampling.json", route)
    build_receipt = next(
        operator / n
        for n in (
            "a4-build-receipt.json",
            "python-build-receipt.json",
            "build-receipt.json",
        )
        if (operator / n).is_file()
    )
    receipt = dict(
        preparations_sha256=sha(
            (manifest.parent.parent / "preparations.json").read_bytes()
        ),
        build_receipt=build_receipt.name,
        build_receipt_sha256=sha(build_receipt.read_bytes()),
        assessor_sha256=sha((operator / "gate_target_only_collector.py").read_bytes()),
        task_id=row["task_id"],
        protocol_id=p["protocol_id"],
        measurement_key=p["measurement_key"],
        operator=str(operator),
        prepared_manifest=str(manifest),
        manifest_sha256=sha(manifest.read_bytes()),
        plan_sha256=p["plan_sha256"],
        bundle_sha256=p["bundle_sha256"],
        results_repo=args.results_repo,
        source_repo=args.source_repo,
        source_revision=row["source"]["revision"],
    )
    core.atomic(run / "prepared.json", receipt)
    print(json.dumps(receipt, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    cmds = parser.add_subparsers(dest="command", required=True)
    cache = cmds.add_parser(
        "cache", help="Copy pinned historical worker sources, excluding all run state"
    )
    cache.add_argument(
        "--archive",
        type=Path,
        default=Path.home() / ".local/share/openenv-qwen-difficulty",
    )
    cache.add_argument("--output", type=Path, default=DEFAULT_CACHE)
    verify = cmds.add_parser(
        "verify-cache",
        help="Check the installed operator cache against its source lock",
    )
    verify.add_argument("--cache", type=Path, default=DEFAULT_CACHE)
    prep = cmds.add_parser(
        "prepare",
        help="Compile and read back one accepted acquisition as a new HF Jobs plan",
    )
    prep.add_argument("acquisition", type=Path)
    prep.add_argument("run", type=Path)
    prep.add_argument("--results-repo", required=True)
    prep.add_argument(
        "--source-repo",
        default=ORIGINAL_REPO,
        help="Dataset recorded in the accepted acquisition",
    )
    prep.add_argument("--cache", type=Path, default=DEFAULT_CACHE)
    prep.add_argument(
        "--draw", type=Path, help="Frozen SRS6 population draw for R3/A4 routing"
    )
    prep.add_argument(
        "--outside-additions",
        type=Path,
        help="Historical authority for the last 22 outside-sample tasks",
    )
    prep.add_argument(
        "--helper-authority",
        type=Path,
        action="append",
        default=[],
        help="Recorded Python V1/V2 helper catalog",
    )
    args = parser.parse_args()
    os.umask(0o077)
    if args.command == "cache":
        install(args.archive, args.output)
        print(f"Cached the pinned Qwen runtime in {args.output}")
    elif args.command == "verify-cache":
        for name in SOURCE_LOCK:
            if name not in PRIVATE_COST_FILES or (args.cache / name).exists():
                source_bytes(args.cache, name)
        print("Verified the installed Qwen operator sources")
    else:
        if not REPO_ID.fullmatch(args.results_repo):
            parser.error("--results-repo must be an owner/name private dataset")
        prepare(args)


if __name__ == "__main__":
    main()
