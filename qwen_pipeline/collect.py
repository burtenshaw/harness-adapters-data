"""Collect an existing R3/A4 run, stage its private result, and seal immutable readback."""

import argparse
import ast
import hashlib
import inspect
import json
import os
import re
import sys
import tempfile
import shutil
from pathlib import Path
from types import FunctionType, ModuleType, SimpleNamespace

from run import runtime_paths

PINS = {
    "bulk2m_collection.py": "1b48739e7b8ac4e0fe5d88e8687059532b0c90cdb662560315a9276b7ddd218b",
    "prefix_collection.py": "b73a61688116846ccb855cd1adab209eea841dae4bd609f96b25f23168f9f7d0",
    "native_contract_collection_v1.py": "323ce6357cefe1d53840a498f7a5b8d466efd6f64eecd61e7c59dda068cc22fd",
    "manifest_collection_v1.py": "3d0e9fe00a9affaa1dc3f870ac328bc4c06752cf275cb30fab7f184d913e733a",
    "target_only_run_v39.py": "2a55ec789d5c816a6a09624849d82ebf38c622846d046b3e5c13369f7d9230bb",
}
R3 = "qwen38-auto48-64k-2m-nothink-r3-v1"
A4 = "qwen38-auto48-64k-2m-nothink-r3-a4-v1"
ATTEMPTS = {R3: 8, A4: 4}
PYTHON = {
    "harbor-python-semantic-gate-targets-r3-v1",
    "harbor-python-native-suite-targets-r3-v2",
    "harbor-python-native-suite-v3-targets-r3-v1",
}
PREFIX = "results/qwen-difficulty-auto-v1/"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def require(ok, message):
    if not ok:
        raise ValueError(message)


def helper(raw, name):
    tree = ast.parse(raw)
    nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name]
    require(len(nodes) == 1, f"missing original collector function {name}")
    return ast.get_source_segment(raw, nodes[0])


def load(args):
    run = args.run.resolve(strict=True)
    receipt_raw = (run / "prepared.json").read_bytes()
    require(sha(receipt_raw) == args.prepared_sha256, "prepared receipt SHA differs")
    binding = json.loads(receipt_raw)
    protocol = binding["protocol_id"]
    suffix = "a4" if protocol == A4 else "r3"
    require(protocol in ATTEMPTS, "unsupported scoring protocol")
    cycle = run / "cycles" / suffix
    op = run / "bulk-v1" / f"operator-{suffix}"
    require(op == Path(binding["operator"]), "prepared operator differs")
    manifest = cycle / "prepared/manifest.json"
    require(
        manifest == Path(binding["prepared_manifest"])
        and sha(manifest.read_bytes()) == binding["manifest_sha256"],
        "prepared manifest differs",
    )
    (task,) = json.loads(manifest.read_bytes())["tasks"]
    prep_raw = (cycle / "preparations.json").read_bytes()
    (prep,) = json.loads(prep_raw)["tasks"]
    for k in (
        "protocol_id",
        "plan_sha256",
        "bundle_sha256",
        "task_id",
        "measurement_key",
    ):
        require(binding[k] == prep[k], "task preparation differs: " + k)
    require(
        all(v == prep[k] for k, v in task.items())
        and prep["prepared_root"] == str(manifest.parent)
        and prep["run_id"] == "coding-" + prep["bundle_sha256"]
        and prep["plan_path"] == prep["task_id"] + "/plan.json",
        "unbound task plan",
    )
    require(
        binding.get("preparations_sha256") == sha(prep_raw),
        "preparations digest differs",
    )
    require(
        sha((run / "core.py").read_bytes())
        == "5f24b1005945caf086ec3338376829ed53560943fcffb17b06cfe9505694ed15",
        "relocated runtime module changed",
    )
    bulk = runtime_paths(run)
    archive = (args.helpers or bulk).resolve()
    for name, pin in PINS.items():
        require(
            sha((archive / name).read_bytes()) == pin,
            f"collector source differs: {name}",
        )
    bname = (
        "a4-build-receipt.json"
        if suffix == "a4"
        else (
            "python-build-receipt.json"
            if prep["control_profile"] in PYTHON
            else "build-receipt.json"
        )
    )
    build_raw = (op / bname).read_bytes()
    build = json.loads(build_raw)
    require(
        binding.get("build_receipt") == bname
        and binding.get("build_receipt_sha256") == sha(build_raw),
        "operator build receipt changed",
    )
    for name, digest in build["files"].items():
        path = op / name
        require(
            path.resolve() == path
            and path.is_relative_to(op)
            and sha(path.read_bytes()) == digest,
            "operator source changed: " + name,
        )
    sys.path[:0] = [str(op), str(op / "src"), str(run), str(archive)]
    import core
    import bulk2m_collection as original
    import prefix_collection as bounded
    import manifest_collection_v1 as publisher
    import native_contract_collection_v1 as contracts
    from examples.hub_validation_pipeline import cloud

    plan_path = manifest.parent / prep["plan_path"]
    plan, config, _, bundle = cloud._read_plan(
        plan_path, expected_sha256=prep["plan_sha256"]
    )
    require(
        plan["results_repo"]
        == binding["results_repo"]
        == config["cloud"]["results_repo"]
        and plan["task_source"] == prep["source"]
        and plan["run_id"] == prep["run_id"],
        "plan source/results identity differs",
    )
    require(
        config["profile"] == prep["control_profile"]
        and config["validation"]["target_attempts"] == ATTEMPTS[protocol],
        "control profile or protocol attempt count differs",
    )
    collector = op / "gate_target_only_collector.py"
    source = collector.read_bytes()
    pin = build["files"][collector.name]
    require(pin == binding.get("assessor_sha256"), "prepared collector SHA differs")
    if config["profile"] in PYTHON - {"harbor-python-semantic-gate-targets-r3-v1"}:
        module, provenance = contracts.assessor(
            source, expected_sha256=pin, filename=collector
        )
    else:
        module = ModuleType("reviewed_target_assessor")
        exec(compile(source, str(collector), "exec"), module.__dict__)
        provenance = {}
    original_source = (archive / "target_only_run_v39.py").read_text()
    runtime_src = helper(original_source, "_target_runtime")
    before = "owner='burtenshaw'"
    require(runtime_src.count(before) == 1, "historical namespace seam changed")
    ns = {
        "inspect_one": original.inspect_one,
        "R3_PROTOCOL": R3,
        "A4_PROTOCOL": A4,
        "re": re,
        "PYTHON_PROFILES": PYTHON,
        "TARGET_PROFILES": {*PYTHON, "harbor-semantic-gate-targets-v1"},
        "PROFILE": "harbor-semantic-gate-targets-v1",
        "TERMINAL": {"COMPLETED", "ERROR", "CANCELED", "CANCELLED", "DELETED"},
        "_bounds": lambda protocol: {"children": ATTEMPTS[protocol] * 2},
        "ChildEnvelopeViolation": ValueError,
        "_manifest_helper": lambda: publisher,
        "inspect": inspect,
    }
    exec(
        compile(
            runtime_src.replace(before, "owner=_jobs_namespace"),
            "reviewed-runtime-inspection",
            "exec",
        ),
        ns,
    )
    exec(
        compile(
            helper(original_source, "_collector_function"),
            "reviewed-assessment",
            "exec",
        ),
        ns,
    )
    fn = ns["_collector_function"](
        original.collect,
        assessor=module.assess_local,
        profile=config["profile"],
        operator=op,
        protocol=protocol,
        provenance=provenance,
    )

    def no_append(*args, **kwargs):
        raise ValueError("collection must be read-only")

    fn = FunctionType(
        fn.__code__,
        {**fn.__globals__, "audit_files": bounded.audit_files, "cas_append": no_append},
        fn.__name__,
        fn.__defaults__,
        fn.__closure__,
    )
    return SimpleNamespace(
        prep=prep,
        plan=plan,
        config=config,
        path=plan_path,
        cloud=cloud,
        core=core,
        collect=fn,
        runtime_globals=ns,
        bounded=bounded,
        publisher=publisher,
        source_pin=pin,
        receipt_pin=sha(receipt_raw),
        module=module,
        operator=op,
        archive=archive,
    )


def client(repo):
    from huggingface_hub import HfApi

    require(re.fullmatch(r"[\w.-]+/[\w.-]+", repo), "invalid private dataset ID")
    return HfApi(endpoint="https://huggingface.co", token=os.environ["HF_TOKEN"])


def collect(st, dest):
    p = st.prep
    local = st.core.loads((st.path.parent / "submission.json").read_bytes())
    require(
        local["status"] == "submitted"
        and local["run_id"] == p["run_id"]
        and re.fullmatch("[a-f0-9]{40}", local["input_revision"])
        and local["launch_spec"]
        == st.cloud._launch_spec(
            st.config, p["bundle_sha256"], local["input_revision"]
        ),
        "missing or inconsistent final submission",
    )
    match = re.fullmatch(
        r"https://huggingface\.co/jobs/([\w.-]+)/([\w-]+)", local["job_url"]
    )
    require(
        match and match[2] == local["job_id"], "unexpected Jobs owner or identifier"
    )
    st.runtime_globals["_jobs_namespace"] = match[1]
    token = {name: os.environ[name] for name in ("HF_TOKEN", "HF_SANDBOX_TOKEN")}
    repo = st.plan["results_repo"]
    api = client(repo)
    info = api.dataset_info(repo)
    require(
        info.private is True and info.id == repo,
        "exact private worker results repository required",
    )
    hub = st.bounded.Reader(SimpleNamespace(repo=repo, api=api), token)
    try:
        worker_revision = hub.head()
        # Preserve one immutable anchor for all worker downloads.
        hub.head = lambda: worker_revision
        remote = st.core.loads(
            hub.read(f"runs/{p['run_id']}/submission.json", worker_revision)
        )
        require(
            remote == local,
            "private worker submission differs from local confirmed Job",
        )
        # Detect pending Jobs before doing an immutable collection. No cancellation or polling.
        controller = st.core.loads(
            hub.read(f"runs/{p['run_id']}/cloud-report.json", worker_revision)
        )
        require(controller.get("run_id") == p["run_id"], "missing final worker report")
        policy = {
            "protocol": {"id": p["protocol_id"]},
            "results": {"prefix": PREFIX},
            "identity": {"claim_prefix": "evaluations/qwen38/claims/"},
        }
        summary = st.collect(
            policy, hub, dest, p, st.plan, st.config, token, submission_override=local
        )

        # Keep the historical manifest graph. This campaign has a worker submission
        # claim and no persisted historical coordinator logical-claim transition.
        class Staged(Exception):
            pass

        def stage(payload, journal):
            files = {}
            for name, raw in payload.items():
                if name.startswith(PREFIX):
                    st.core.atomic(
                        dest / "payload" / st.core.safe_path(name), raw, raw=True
                    )
                    files[name] = sha(raw)
            require(len(files) == 5, "unexpected result graph")
            st.core.atomic(
                dest / "staged.json",
                dict(
                    repo=repo,
                    task_id=p["task_id"],
                    run_id=p["run_id"],
                    measurement_key=p["measurement_key"],
                    protocol=p["protocol_id"],
                    worker_revision=worker_revision,
                    files=files,
                    prepared_sha256=st.receipt_pin,
                ),
            )
            raise Staged

        try:
            st.publisher.publish_manifest(
                policy, hub, dest, p, summary, token, None, append=stage
            )
        except Staged:
            return {
                "status": summary["status"],
                "valid_attempts": summary.get("valid_attempts"),
                "planned_attempts": ATTEMPTS[p["protocol_id"]],
                "worker_revision": worker_revision,
            }
        raise RuntimeError("staging did not capture an immutable worker manifest")
    finally:
        hub.close()


def graph(directory):
    meta = json.loads((directory / "staged.json").read_bytes())
    require(
        re.fullmatch(r"coding-[a-f0-9]{64}", meta["run_id"])
        and re.fullmatch(r"[a-f0-9]{64}", meta["measurement_key"]),
        "invalid run identity",
    )
    prefix = (
        f"{PREFIX}{meta['measurement_key']}/{meta['run_id']}/manifest-collections-v1/"
    )
    files = {}
    for name, digest in meta["files"].items():
        require(
            re.fullmatch(re.escape(prefix) + r"[a-f0-9]{64}/[a-z-]+\.json", name),
            "invalid result path",
        )
        raw = (directory / "payload" / name).read_bytes()
        require(sha(raw) == digest, "result payload changed")
        files[name] = raw
    expected = {
        "summary.json",
        "collection-receipt.json",
        "runtime-jobs.json",
        "preparation.json",
        "worker-artifact-manifest.json",
    }
    require(
        len({name.rsplit("/", 1)[0] for name in files}) == 1
        and {Path(n).name for n in files} == expected,
        "result graph membership differs",
    )
    return meta, files


def private_commit(directory, parent):
    from huggingface_hub import CommitOperationAdd

    require(re.fullmatch(r"[a-f0-9]{40}", parent), "expected a full parent commit")
    meta, files = graph(directory)
    api = client(meta["repo"])
    info = api.dataset_info(meta["repo"])
    require(
        info.id == meta["repo"] and info.private is True and info.sha == parent,
        "expected private results dataset at the supplied parent",
    )
    require(
        not api.get_paths_info(
            meta["repo"], list(files), revision=parent, repo_type="dataset"
        ),
        "result paths already exist",
    )
    # A durable intent prevents a duplicate request following an unknown response.
    with (directory / "publication-intent.json").open("x") as stream:
        json.dump(
            {"repo": meta["repo"], "parent": parent, "files": meta["files"]}, stream
        )
        stream.flush()
        os.fsync(stream.fileno())
    ops = [
        CommitOperationAdd(path_in_repo=n, path_or_fileobj=b) for n, b in files.items()
    ]
    revision = api.create_commit(
        meta["repo"],
        operations=ops,
        repo_type="dataset",
        parent_commit=parent,
        commit_message="Add independently inspected Qwen result and immutable worker manifest",
    ).oid
    (directory / "publication-commit.json").write_text(
        json.dumps({"revision": revision, "parent": parent}) + "\n"
    )
    return revision


def seal(directory, revision, out, *, download=None):
    require(
        re.fullmatch(r"[a-f0-9]{40}", revision),
        "expected immutable publication revision",
    )
    meta, files = graph(directory)
    repo = meta["repo"]
    if download is None:
        from huggingface_hub import hf_hub_download

        info = client(repo).dataset_info(repo, revision=revision)
        require(
            info.id == repo and info.private is True and info.sha == revision,
            "exact private revision required",
        )

        def download(name, rev):
            return Path(
                hf_hub_download(
                    repo,
                    name,
                    repo_type="dataset",
                    revision=rev,
                    token=os.environ["HF_TOKEN"],
                    endpoint="https://huggingface.co",
                )
            ).read_bytes()

    require(
        all(download(name, revision) == raw for name, raw in files.items()),
        "published result graph differs",
    )
    summary_path = next(p for p in files if p.endswith("/summary.json"))
    manifest_path = next(
        p for p in files if p.endswith("/worker-artifact-manifest.json")
    )
    summary_raw, manifest_raw = files[summary_path], files[manifest_path]
    manifest, summary = json.loads(manifest_raw), json.loads(summary_raw)
    worker = meta["worker_revision"]
    require(
        worker == summary["revision"] == manifest["worker_revision"]
        and manifest["repo_id"] == repo
        and summary["evidence_manifest_path"] == manifest_path
        and summary["protocol_id"] == meta["protocol"],
        "inconsistent worker and summary identity",
    )
    objects = {"summary": summary_raw, "worker_manifest_bytes": manifest_raw}
    for field, name in (
        ("audit_config_bytes", "audit/config.json"),
        ("audit_sha256sums", "audit/SHA256SUMS"),
    ):
        item = manifest["files"][name]
        raw = download(item["path"], worker)
        require(sha(raw) == item["sha256"], "worker audit readback differs")
        objects[field] = raw
    gate = json.loads(objects["audit_config_bytes"])["source_gate"]
    objects["source_gate_report_bytes"] = gate["report_json"].encode()
    require(
        sha(objects["source_gate_report_bytes"]) == gate["report_sha256"],
        "source gate digest differs",
    )

    def raw_json(obj):
        return (json.dumps(obj, sort_keys=True, separators=(",", ":")) + "\n").encode()

    objects["task_inventory"] = raw_json(
        {
            k: dict(sha256=v["sha256"], size=v["bytes"], mode=oct(v["mode"]))
            for k, v in manifest["source_files"].items()
        }
    )
    objects["summary_locator"] = raw_json(
        dict(
            task_id=meta["task_id"],
            protocol_id=meta["protocol"],
            summary_revision=revision,
            summary_path=summary_path,
            summary_sha256=sha(summary_raw),
            repo_id=repo,
        )
    )
    objects["worker_manifest_locator"] = raw_json(
        dict(
            repo_id=repo,
            revision=revision,
            path=manifest_path,
            sha256=sha(manifest_raw),
        )
    )
    objects["results.json"] = raw_json(
        {"records": [{k: k for k in objects}], "claims": []}
    )
    if out.exists():
        require(
            out.is_dir()
            and all((out / k).read_bytes() == v for k, v in objects.items()),
            "existing local sealed capture differs",
        )
    else:
        out.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=out.parent) as temp:
            staged = Path(temp) / "capture"
            staged.mkdir()
            for key, raw in objects.items():
                (staged / key).write_bytes(raw)
            staged.rename(out)
    return {
        "revision": revision,
        "status": summary["status"],
        "records": 1,
        "manifest": str(out / "results.json"),
    }


def merge(inputs, out):
    """Combine relative artifact references without modifying source captures."""
    require(not out.exists(), "supply a new output folder")
    out.parent.mkdir(parents=True, exist_ok=True)
    merged = {"records": [], "claims": []}
    with tempfile.TemporaryDirectory(dir=out.parent) as temp:
        stage = Path(temp) / "capture"
        stage.mkdir()
        for i, path in enumerate(inputs):
            path = (path / "results.json" if path.is_dir() else path).resolve(
                strict=True
            )
            document = json.loads(path.read_bytes())
            for group in merged:
                for record in document.get(group, []):
                    row = {}
                    for key, reference in record.items():
                        rel = Path(reference)
                        require(
                            rel.parts
                            and not rel.is_absolute()
                            and ".." not in rel.parts,
                            "unsafe captured path",
                        )
                        source = path.parent / rel
                        require(
                            source.is_file() and source.resolve() == source,
                            "missing or linked capture artifact",
                        )
                        local = Path(f"capture-{i}") / rel
                        dest = stage / local
                        if not dest.exists():
                            dest.parent.mkdir(parents=True, exist_ok=True)
                            shutil.copyfile(source, dest)
                        row[key] = local.as_posix()
                    merged[group].append(row)
        (stage / "results.json").write_text(json.dumps(merged) + "\n")
        stage.rename(out)
    return {
        "records": len(merged["records"]),
        "claims": len(merged["claims"]),
        "manifest": str(out / "results.json"),
    }


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("check", "collect"):
        p = sub.add_parser(name)
        p.add_argument("run", type=Path)
        p.add_argument("--prepared-sha256", required=True)
        p.add_argument(
            "--helpers",
            type=Path,
            help="alternate directory with pinned collection helper sources",
        )
        if name == "collect":
            p.add_argument("output", type=Path)
    p = sub.add_parser("publish")
    p.add_argument("stage", type=Path)
    p.add_argument("--parent", required=True)
    p = sub.add_parser("seal")
    p.add_argument("stage", type=Path)
    p.add_argument("output", type=Path)
    p.add_argument("--revision", required=True)
    p = sub.add_parser("merge", help="combine sealed captures for a multi-task view")
    p.add_argument("output", type=Path)
    p.add_argument("inputs", type=Path, nargs="+")
    args = parser.parse_args()
    if args.command in ("collect", "check"):
        state = load(args)
        if args.command == "check":
            result = {
                "task_id": state.prep["task_id"],
                "bound_plan": state.prep["plan_sha256"],
                "collector_sha256": state.source_pin,
                "protocol": state.prep["protocol_id"],
            }
        else:
            out = args.output.resolve()
            require(not out.exists(), "supply a fresh collection output")
            out.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(dir=out.parent) as tmp:
                dest = Path(tmp) / "stage"
                dest.mkdir()
                result = collect(state, dest)
                dest.rename(out)
    elif args.command == "merge":
        result = merge(args.inputs, args.output)
    elif args.command == "publish":
        revision = private_commit(args.stage, args.parent)
        result = seal(args.stage, revision, args.stage / "sealed")
    else:
        result = seal(args.stage, args.revision, args.output)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
