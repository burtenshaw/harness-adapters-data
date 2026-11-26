"""Recover the OpenEnv checkout and run the original scale800 operators."""

import argparse
import gzip
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
PINS = json.loads((HERE / "pins.json").read_bytes())
OPERATORS = HERE / "operators"
PILOT = Path("outputs/full-hub-run-20261110/scale800-pilot-v1")
DEFAULT = HERE.parent / ".local" / "openenv"
GATES = {
    "go": "hf-check-gate-v1",
    **{f"python-v{v}": f"hf-check-gate-python-v{v}" for v in (1, 2, 3)},
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def checked(path, digest):
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"Expected regular file: {path}")
    raw = path.read_bytes()
    if sha(raw) != digest:
        raise ValueError(f"SHA256 mismatch: {path}")
    return raw


def verify():
    for name, digest in PINS["operator_files_sha256"].items():
        checked(OPERATORS / name, digest)
    for name, digest in PINS["runtime_overlay_sha256"].items():
        checked(HERE / name, digest)
    checked(HERE / "openenv-tip.pack", PINS["tip_pack_sha256"])
    lock = gzip.decompress((HERE / "uv.lock.gz").read_bytes())
    if sha(lock) != PINS["uv_lock_sha256"]:
        raise ValueError("Historical uv.lock differs")
    return lock


def git(cwd, *args, **kwargs):
    return (
        subprocess.run(
            ["git", "-C", str(cwd), *args], check=True, stdout=subprocess.PIPE, **kwargs
        )
        .stdout.decode()
        .strip()
    )


def bootstrap(args):
    lock = verify()
    target = args.checkout
    if target.exists() or target.is_symlink():
        raise ValueError(f"Bootstrap needs a fresh checkout path: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    parent, tip = PINS["openenv_public_parent"], PINS["openenv_historical"]
    source = (
        args.git_source.resolve().as_uri() if args.git_source else PINS["openenv_url"]
    )
    with tempfile.TemporaryDirectory(
        prefix="openenv-bootstrap-", dir=target.parent
    ) as temp:
        repo = Path(temp) / "repo"
        repo.mkdir()
        git(repo, "init", "-q")
        git(repo, "fetch", "-q", "--depth=1", "--no-tags", source, parent)
        git(
            repo,
            "index-pack",
            "--stdin",
            input=checked(HERE / "openenv-tip.pack", PINS["tip_pack_sha256"]),
        )
        if git(repo, "rev-parse", tip + "^{tree}") != PINS["openenv_tree"]:
            raise ValueError("Recovered tree identity differs")
        # The tip's first (local) parent is deliberately outside this shallow snapshot.
        with (repo / ".git/shallow").open("a") as boundaries:
            boundaries.write(tip + "\n")
        git(repo, "checkout", "-q", "--detach", tip)
        git(repo, "fsck", "--connectivity-only", "--no-dangling")
        (repo / "uv.lock").write_bytes(lock)
        for name, digest in PINS["operator_files_sha256"].items():
            dest = repo / PILOT / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(checked(OPERATORS / name, digest))
        repo.rename(target)
    print(target)


def check_checkout(repo):
    if git(repo, "rev-parse", "HEAD") != PINS["openenv_historical"]:
        raise ValueError("OpenEnv checkout differs from the historical tip")
    if git(repo, "status", "--porcelain", "--untracked-files=normal"):
        raise ValueError(
            "Use a clean bootstrapped OpenEnv checkout; keep run data outside it"
        )
    checked(repo / "uv.lock", PINS["uv_lock_sha256"])
    for name, digest in PINS["operator_files_sha256"].items():
        checked(repo / PILOT / name, digest)


def load(path):
    spec = importlib.util.spec_from_file_location("scale800_" + path.stem, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def screen(args):
    runner = load(OPERATORS / "eligibility/eligibility.py")
    policy = json.loads(args.policy.read_bytes())
    existing = json.loads(args.existing.read_bytes())
    with args.candidates.open() as stream, args.output.open("x") as out:
        for row in runner.assess_many(
            (json.loads(line) for line in stream), policy, existing
        ):
            print(json.dumps(row, sort_keys=True), file=out)


def run_in_env(args, argv):
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(
        str(args.checkout / part) for part in (".", "src", "envs")
    )
    python = args.python or args.checkout / ".venv/bin/python"
    if not python.is_file():
        raise ValueError("Install the pinned environment or supply --python PATH")
    env.pop("PYTHONOPTIMIZE", None)
    env["PATH"] = str(python.parent) + os.pathsep + env.get("PATH", "")
    subprocess.run([str(python), "-B", *map(str, argv)], env=env, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", type=Path, default=DEFAULT)
    parser.add_argument(
        "--python",
        type=Path,
        help="Interpreter with the historical OpenEnv dependencies",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    boot = sub.add_parser("bootstrap")
    boot.add_argument("--checkout", type=Path, default=argparse.SUPPRESS)
    boot.add_argument(
        "--git-source",
        type=Path,
        help="Local OpenEnv repository containing the public parent",
    )
    sub.add_parser("verify")
    s = sub.add_parser("screen")
    s.add_argument("--candidates", required=True, type=Path)
    s.add_argument("--policy", type=Path, default=OPERATORS / "eligibility/policy.json")
    s.add_argument(
        "--existing",
        type=Path,
        default=OPERATORS / "eligibility/existing-identities.json",
    )
    s.add_argument("--output", required=True, type=Path)
    s = sub.add_parser(
        "capture",
        help="Read selected train tasks from pinned Parquet and bind native source",
    )
    from capture import add_arguments as capture_arguments

    capture_arguments(s)
    s = sub.add_parser(
        "convert", help="Prepare Harbor drafts from portable, source-proven captures"
    )
    from convert import add_arguments

    add_arguments(s)
    s = sub.add_parser(
        "accepted", help="Capture registered source splits at an immutable revision"
    )
    s.add_argument("--source-repo", required=True)
    s.add_argument("--revision", required=True)
    s.add_argument(
        "--snapshot",
        type=Path,
        help="Read files from an immutable local snapshot instead of the Hub",
    )
    s.add_argument("--output", type=Path, required=True)
    s = sub.add_parser("views")
    s.add_argument("--source-repo", default="harness-hub/agentic-coding-envs")
    s.add_argument("--results-repo", default="harness-hub/agentic-coding-envs")
    s.add_argument("--accepted-capture", required=True, type=Path)
    s.add_argument("--results-manifest", required=True, type=Path)
    s.add_argument("--sample-manifest", type=Path)
    s.add_argument("--output", required=True, type=Path)
    s = sub.add_parser(
        "replay-views",
        help="Rebuild published views with correction, sample and phase authorities",
    )
    s.add_argument("--capture", type=Path, required=True)
    s.add_argument(
        "--snapshots",
        type=Path,
        required=True,
        help="Directory containing revision/path from the private dataset",
    )
    s.add_argument(
        "--authorities", type=Path, default=HERE / "historical-view-inputs.json"
    )
    s.add_argument("--output", type=Path, required=True)
    s = sub.add_parser(
        "terminal-proof",
        help="Independently recheck completed gate Jobs through read-only SDK calls",
    )
    s.add_argument("--plan", required=True, type=Path)
    s.add_argument("--plan-sha256", required=True)
    s.add_argument("--report-sha256", required=True)
    s.add_argument("--output", required=True, type=Path)
    s = sub.add_parser(
        "stage", help="Build a local accepted source split after gate completion"
    )
    s.add_argument("language", choices=["go", "python"])
    s.add_argument("--roster", required=True, type=Path)
    s.add_argument("--campaign", required=True)
    s.add_argument("--batch", required=True)
    s.add_argument("--prior-index", type=Path, action="append", default=[])
    s.add_argument("--output", required=True, type=Path)
    s = sub.add_parser("gate")
    s.add_argument("language", choices=GATES)
    s.add_argument("args", nargs=argparse.REMAINDER)
    s = sub.add_parser("native")
    s.add_argument(
        "module",
        choices=(
            "pipeline",
            "real_tasks",
            "prepared_batch",
            "full_run",
            "cloud",
            "demo",
        ),
    )
    s.add_argument("args", nargs=argparse.REMAINDER)
    s = sub.add_parser("smoke")
    s.add_argument("--output", required=True, type=Path)
    s = sub.add_parser(
        "containerize",
        help="Build, OCI-append, push, and pin Harbor task containers via OpenEnv (no Spaces)",
    )
    from containerize import add_arguments as containerize_arguments

    containerize_arguments(s)
    args = parser.parse_args()
    args.checkout = args.checkout.resolve()
    if args.python:
        # Keep a venv interpreter symlink intact.
        args.python = args.python.absolute()
    if args.command == "bootstrap":
        return bootstrap(args)
    if args.command == "containerize":
        from containerize import execute as run_containerize

        return run_containerize(args)
    verify()
    if args.command == "verify":
        print(
            f"Verified {len(PINS['operator_files_sha256'])} operator files, OpenEnv tip pack and dependency lock"
        )
        return
    if args.command == "screen":
        return screen(args)
    check_checkout(args.checkout)
    root = args.checkout / PILOT / "production"
    if args.command == "capture":
        argv = [
            HERE / "capture.py",
            "--operators",
            args.checkout / PILOT,
            args.family,
            "--shards",
            args.shards,
            "--policy",
            args.policy,
            "--existing",
            args.existing,
            "--output",
            args.output,
        ]
        for k in args.task:
            argv += ["--task", k]
        for cache in args.offline_cache:
            argv += ["--offline-cache", cache]
    elif args.command == "convert":
        argv = [
            HERE / "convert.py",
            "--operators",
            root,
            args.family,
            "--source",
            args.source,
            "--manifest",
            args.manifest,
            "--expected-sha256",
            args.expected_sha256,
            "--output",
            args.output,
        ]
        for key in ("index_sha256", "runtime_lock", "go_profile"):
            if getattr(args, key):
                argv += ["--" + key.replace("_", "-"), getattr(args, key)]
        for task_id in args.task:
            argv += ["--task", task_id]
    elif args.command == "replay-views":
        argv = [
            HERE / "replay_views.py",
            root / "derived-dataset-views-corrections-v1",
            args.capture,
            args.snapshots,
            args.authorities,
            args.output,
        ]
    elif args.command == "accepted":
        argv = [
            HERE / "accepted.py",
            root / "derived-dataset-views-corrections-v1/refresh.py",
            args.source_repo,
            args.revision,
            args.output,
        ]
        if args.snapshot:
            argv += [args.snapshot]
    elif args.command == "views":
        readset = args.accepted_capture.parent / "readset.json"
        if readset.exists() and json.loads(readset.read_bytes()).get(
            "corrections_index_locator"
        ):
            raise ValueError(
                "This capture declares a correction index. Use replay-views with its authorities"
            )
        if args.output.exists() or args.output.is_symlink():
            raise ValueError("View output must be fresh")
        argv = [
            HERE / "views.py",
            root / "derived-dataset-views-corrections-v1/build.py",
            args.results_repo,
            args.source_repo,
            args.accepted_capture,
            args.results_manifest,
            args.output,
        ]
        if args.sample_manifest:
            argv += [args.sample_manifest]
    elif args.command == "terminal-proof":
        argv = [
            HERE / "terminal.py",
            root / "python-gate-publication-v5/publish.py",
            args.plan,
            args.plan_sha256,
            args.report_sha256,
            args.output,
        ]
    elif args.command == "stage":
        argv = [
            HERE / "stage.py",
            root,
            args.language,
            args.roster,
            args.output,
            args.campaign,
            args.batch,
            *args.prior_index,
        ]
    elif args.command == "gate":
        if not args.args or args.args[0] not in ("prepare", "execute", "--help"):
            raise ValueError("Choose gate prepare or execute")
        if args.args[0] == "prepare" and "--deadline-utc" not in args.args:
            raise ValueError(
                "Supply this campaign's --deadline-utc for gate preparation"
            )
        argv = [root / GATES[args.language] / "run.py", *args.args]
    elif args.command == "native":
        argv = ["-m", "examples.hub_validation_pipeline." + args.module, *args.args]
    else:
        argv = [HERE / "smoke.py", args.output, args.checkout]
    return run_in_env(args, argv)


if __name__ == "__main__":
    try:
        main()
    except (
        ValueError,
        FileNotFoundError,
        FileExistsError,
        subprocess.CalledProcessError,
    ) as exc:
        sys.exit(str(exc))
