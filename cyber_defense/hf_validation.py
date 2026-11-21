"""Stage an immutable private OpenEnv validation input and attest its HF Job result."""

import argparse
import hashlib
import inspect
import io
import json
from pathlib import Path
import subprocess
import zipfile

REVISION = "bb027fa3f7b50718df4b8d8a2312d8bee1760c41"
IMAGE = "python@sha256:0f086103b026048cc50cb5da25ec435c023c5241a83fc44daea593377abc61c4"
VALIDATOR_FILES = ("__init__.py", "environment.py", "grading.py", "validate.py")
RESULT_KEYS = ("cohort_sha256", "receipts_sha256", "validated")
MARKER = "OPENENV_REPLAY "


def sha(data):
    return hashlib.sha256(data).hexdigest()


def dump(path, payload):
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def run_worker():
    import hashlib
    import importlib.metadata
    import json
    import os
    from pathlib import Path
    import platform
    import subprocess
    import sys
    import tarfile
    import tempfile
    import zipfile

    root = Path(tempfile.mkdtemp(prefix="openenv-replay-"))
    bundle = Path(os.environ["INPUT_DIR"]) / (os.environ["BUNDLE_SHA256"] + ".zip")
    if hashlib.sha256(bundle.read_bytes()).hexdigest() != os.environ["BUNDLE_SHA256"]:
        raise ValueError("Remote bundle digest mismatch")
    with zipfile.ZipFile(bundle) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        for filename, expected_sha in manifest["files"].items():
            blob = archive.read(filename)
            if hashlib.sha256(blob).hexdigest() != expected_sha:
                raise ValueError("Remote input digest mismatch")
            dest = root / filename
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(blob)
    native = root / "pinned"
    native.mkdir()
    with tarfile.open(root / "openenv.tar.gz") as tar:
        tar.extractall(native, filter="data")
    subprocess.run([sys.executable, "-m", "pip", "--disable-pip-version-check", "install",
                    "--quiet", "--no-cache-dir", str(native)], check=True)
    # Use the verified native source tree directly, even if another package is installed.
    sys.path[:0] = [str(root), str(native / "src")]
    from openenv.core.env_server import interfaces, types
    from cyber_defense.validate import replay

    for module in (interfaces, types):
        if not Path(module.__file__).resolve().is_relative_to((native / "src").resolve()):
            raise ValueError("OpenEnv was imported from outside the verified tree")
    result = replay(root / "tasks.jsonl")
    result.update(openenv_revision=manifest["openenv_revision"],
                  openenv_version=importlib.metadata.version("openenv"),
                  python=platform.python_version(), platform=platform.system(),
                  machine=platform.machine(), bundle_sha256=os.environ["BUNDLE_SHA256"])
    print("OPENENV_REPLAY " + json.dumps(result, sort_keys=True), flush=True)


def prepare(run_dir, checkout, repo):
    from huggingface_hub import HfApi, CommitOperationAdd, hf_hub_download

    evidence = run_dir / "hf-validation"
    evidence.mkdir(parents=True, exist_ok=True)
    local = json.loads((run_dir / "validation-summary.json").read_bytes())
    content = {"tasks.jsonl": (run_dir / "tasks.jsonl").read_bytes()}
    if sha(content["tasks.jsonl"]) != local["cohort_sha256"]:
        raise ValueError("Local cohort does not match validation summary")
    for name in VALIDATOR_FILES:
        content["cyber_defense/" + name] = Path(__file__).with_name(name).read_bytes()
    content["openenv.tar.gz"] = subprocess.check_output([
        "git", "-C", str(checkout), "archive", "--format=tar.gz", REVISION,
        "src/openenv", "pyproject.toml", "README.md", "LICENSE",
    ])
    manifest = {"openenv_revision": REVISION,
                "files": {name: sha(data) for name, data in content.items()}}
    content["manifest.json"] = json.dumps(manifest, sort_keys=True).encode()
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        for name, data in content.items():
            info = zipfile.ZipInfo(name)
            archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED)
    blob = stream.getvalue()
    bundle_sha = sha(blob)
    name = bundle_sha + ".zip"
    (evidence / name).write_bytes(blob)

    api = HfApi(endpoint="https://huggingface.co")
    owner = api.whoami()["name"]
    if repo.split("/")[0] != owner:
        raise ValueError("Use a private staging repo in the authenticated user namespace")
    api.create_repo(repo, repo_type="dataset", private=True, exist_ok=True)
    initial = api.dataset_info(repo)
    if initial.private is not True or initial.id != repo:
        raise ValueError("Staging repository identity or private visibility mismatch")
    package = Path(__file__).parent
    notices = {
        "licenses/OpenFGA-LICENSE.txt": (package / "access-review-LICENSE.txt").read_bytes(),
        "licenses/Cedar-LICENSE.txt": (package / "vendor/cedar-integration-tests-LICENSE").read_bytes(),
        "licenses/Cedar-NOTICE.txt": (package / "vendor/cedar-integration-tests-NOTICE").read_bytes(),
    }
    files = {name: blob, **notices}
    missing = {path: data for path, data in files.items()
               if not api.file_exists(repo, path, repo_type="dataset", revision=initial.sha)}
    if not missing:
        revision = initial.sha
    else:
        commit = api.create_commit(repo, repo_type="dataset",
                                   parent_commit=initial.sha, commit_message="Stage sealed OpenEnv replay input",
                                   operations=[CommitOperationAdd(path_in_repo=path, path_or_fileobj=data)
                                               for path, data in missing.items()])
        revision = commit.oid
    for path, data in files.items():
        pinned_path = hf_hub_download(repo, path, repo_type="dataset", revision=revision,
                                      token=True, force_download=True)
        if sha(Path(pinned_path).read_bytes()) != sha(data):
            raise ValueError("Private Hub readback differs from the prepared input")
    source = inspect.getsource(run_worker) + "\nrun_worker()"
    job_args = {"name": f"cyber-openenv-{bundle_sha[:12]}", "image": IMAGE, "flavor": "cpu-basic",
                "timeout": "20m", "namespace": owner, "command": ["python", "-c", source],
                "env": {"INPUT_DIR": "/inputs", "BUNDLE_SHA256": bundle_sha},
                "volumes": [f"hf://datasets/{repo}:/inputs:ro"], "detach": True}
    dump(evidence / "job-args.json", job_args)
    request = {"expected": {k: local[k] for k in RESULT_KEYS}, "repo": repo,
               "private": True, "repo_revision": revision, "bundle_sha256": bundle_sha,
               "manifest": manifest, "job_name": job_args["name"], "image": IMAGE,
               "license_files": {path: sha(data) for path, data in notices.items()}}
    dump(evidence / "prepared.json", request)
    return request


def collect(run_dir, job_id):
    from huggingface_hub import HfApi
    evidence = run_dir / "hf-validation"
    prepared = json.loads((evidence / "prepared.json").read_bytes())
    api = HfApi(endpoint="https://huggingface.co")
    owner = prepared["repo"].split("/")[0]
    job = api.inspect_job(job_id=job_id, namespace=owner)
    if job.owner.name != owner or job.id != job_id:
        raise ValueError("Job identity mismatch")
    args = json.loads((evidence / "job-args.json").read_bytes())
    if (job.environment != args["env"] or job.docker_image != IMAGE or job.command != args["command"]
            or len(job.volumes) != 1 or job.volumes[0].source != prepared["repo"]
            or not job.volumes[0].read_only):
        raise ValueError("Job inputs differ from prepared validation")
    state = {"job_id": job_id, "url": job.url, "stage": job.status.stage,
             "created_at": job.created_at.isoformat(), "flavor": job.flavor,
             "source": prepared["repo"], "source_revision": prepared["repo_revision"],
             "bundle_sha256": prepared["bundle_sha256"]}
    dump(evidence / "job.json", state)
    if job.status.stage != "COMPLETED":
        return state
    lines = list(api.fetch_job_logs(job_id=job_id, namespace=owner))
    (evidence / "job.log").write_text("\n".join(lines) + "\n")
    reports = [json.loads(line.split(MARKER, 1)[1]) for line in lines if MARKER in line]
    if len(reports) != 1:
        raise ValueError("Expected one terminal replay report")
    report = reports[0]
    if (report["bundle_sha256"] != prepared["bundle_sha256"] or report["platform"] != "Linux"
            or report["openenv_revision"] != REVISION
            or any(report[k] != v for k, v in prepared["expected"].items())):
        raise ValueError("Remote replay failed local receipt reconciliation")
    receipt = dict(state, **{k: v for k,v in report.items() if k not in state}, matches_local=True)
    dump(evidence / "terminal.json", receipt)
    return receipt


def submit(run_dir):
    """Submit the prepared specification, or recover the previously named job."""
    from huggingface_hub import HfApi, Volume
    from itertools import islice
    evidence = run_dir / "hf-validation"
    prepared = json.loads((evidence / "prepared.json").read_bytes())
    args = json.loads((evidence / "job-args.json").read_bytes())
    owner = prepared["repo"].split("/")[0]
    api = HfApi(endpoint="https://huggingface.co")
    if api.dataset_info(prepared["repo"]).private is not True:
        raise ValueError("Validation input repository must be private")
    previous = list(islice(api.list_jobs(namespace=owner, labels={"name": args["name"]}), 2))
    if len(previous) > 1:
        raise ValueError("Multiple jobs match this prepared input; collect by explicit job ID")
    if previous:
        return collect(run_dir, previous[0].id)
    volume = Volume(type="dataset", source=prepared["repo"], mount_path="/inputs",
                    revision=prepared["repo_revision"], read_only=True)
    job = api.run_job(name=args["name"], namespace=owner, image=args["image"],
                      command=args["command"], env=args["env"], timeout=args["timeout"],
                      flavor=args["flavor"], volumes=[volume])
    return collect(run_dir, job.id)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("prepare", "submit", "collect"))
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("--openenv", type=Path, default=Path(".local/openenv"))
    parser.add_argument("--repo", default="burtenshaw/cyber-defense-1000-validation")
    parser.add_argument("--job-id")
    args = parser.parse_args()
    if args.operation == "prepare":
        payload = prepare(args.run_dir, args.openenv, args.repo)
    elif args.operation == "submit":
        payload = submit(args.run_dir)
    else:
        payload = collect(args.run_dir, args.job_id)
    print(json.dumps(payload, sort_keys=True))
