"""Check that public starter bytes exclude the private verifier and solution."""

import hashlib
import json
from pathlib import Path


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def files(directory):
    return {
        p.relative_to(directory).as_posix(): p
        for p in directory.rglob("*")
        if p.is_file()
    }


def audit(t):
    env, tests, sol = (
        files(t / "environment"),
        files(t / "tests"),
        files(t / "solution"),
    )
    contract = json.loads((t / "tests/contract.json").read_text())
    envsrc = {
        k.removeprefix("source/"): v for k, v in env.items() if k.startswith("source/")
    }
    testsrc = {
        k.removeprefix("source/"): v
        for k, v in tests.items()
        if k.startswith("source/")
    }
    hidden_names = {
        "grade.py",
        "contract.json",
        "test_driver.py",
        "test_results.py",
        "test.sh",
        "solve.sh",
    }
    test_files = {p.split("::")[0] for p in contract["test_paths"]}
    ref = {
        k.removeprefix("reference/"): v
        for k, v in sol.items()
        if k.startswith("reference/")
    }
    problems = []
    if hidden_names & {Path(k).name for k in env}:
        problems.append("verifier file in environment/")
    leaked_tests = sorted(
        f
        for f in test_files
        if f in envsrc and (f not in testsrc or sha(envsrc[f]) == sha(testsrc[f]))
    )
    if leaked_tests:
        problems.append(f"hidden test files in environment: {len(leaked_tests)}")
    leaked_ref = sorted(
        k for k, v in ref.items() if k in envsrc and sha(envsrc[k]) == sha(v)
    )
    if leaked_ref:
        problems.append(
            f"environment file equals reference solution: {len(leaked_ref)}"
        )
    mismatch = sorted(
        k for k in envsrc if k in testsrc and sha(envsrc[k]) != sha(testsrc[k])
    )
    env_only = sorted(k for k in envsrc if k not in testsrc)
    dockerfile = (t / "environment/Dockerfile").read_text()
    copies = [
        line
        for line in dockerfile.splitlines()
        if line.split()[:1] in (["COPY"], ["ADD"])
    ]
    if any(
        ("tests" in line or "solution" in line or line.startswith("ADD"))
        for line in copies
    ):
        problems.append("Dockerfile copies tests/solution or uses ADD")
    if mismatch:
        problems.append("starter and verifier source disagree")
    if env_only:
        problems.append("starter files missing from verifier source")
    if set(env) - {"Dockerfile"} - {"source/" + k for k in envsrc}:
        problems.append("unexpected environment files")
    if any(p.is_symlink() for p in t.rglob("*")):
        problems.append("symbolic link in bundle")
    if problems:
        raise ValueError(f"{t.name}: {', '.join(problems)}")


def context(task):
    environment = task / "environment"
    return {
        "README.md": b"---\nsdk: docker\napp_port: 7860\n---\n",
        **{k: v.read_bytes() for k, v in sorted(files(environment).items())},
    }
