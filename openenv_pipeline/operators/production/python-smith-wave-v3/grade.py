"""Trusted private pytest panel runner. Installed only in a fresh grader Job."""

import hashlib
import importlib.util
import json
import os
import shutil
import stat
import subprocess
from pathlib import Path, PurePosixPath


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def safe(value):
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or not path.parts
        or any(part in {".", "..", ".git"} for part in path.parts)
    ):
        raise ValueError("Unsafe trusted test path")
    return path


def restore(worktree, private, manifest):
    worktree, private = Path(worktree), Path(private)
    captured = {}
    for name, expected in manifest["files"].items():
        path = private / safe(name)
        info = path.lstat()
        raw = path.read_bytes() if stat.S_ISREG(info.st_mode) else b""
        if (
            not stat.S_ISREG(info.st_mode)
            or len(raw) != expected["bytes"]
            or sha(raw) != expected["sha256"]
            or stat.S_IMODE(info.st_mode) != expected["mode"]
        ):
            raise ValueError("Trusted private test bytes or modes drifted")
        captured[name] = (raw, expected["mode"])
    # Capture and verify every private byte before changing the submitted tree.
    for name in manifest["directory_roots"]:
        destination = worktree / safe(name)
        if destination.is_symlink():
            raise ValueError("Submitted test directory is a symlink")
        for parent in destination.parents:
            if parent == worktree:
                break
            if parent.is_symlink():
                raise ValueError("Submitted test parent is a symlink")
        if destination.exists():
            if not destination.is_dir():
                raise ValueError("Submitted test directory is not a directory")
            shutil.rmtree(destination)
    for name, (raw, mode) in captured.items():
        destination = worktree / safe(name)
        for parent in destination.parents:
            if parent == worktree:
                break
            if parent.is_symlink():
                raise ValueError("Submitted test parent is a symlink")
        if destination.is_symlink():
            raise ValueError("Submitted trusted file is a symlink")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
        destination.chmod(mode)


def run(worktree, private_root, output, invoke=None):
    private_root, output, worktree = Path(private_root), Path(output), Path(worktree)
    expected = json.loads((private_root / "expected-panels.json").read_bytes())
    config = json.loads((private_root / "panel-config.json").read_bytes())
    manifest = json.loads((private_root / "trusted-inventory.json").read_bytes())
    restore(worktree, private_root / "trusted", manifest)
    output.mkdir(parents=True, exist_ok=True)
    for name in (
        "reward.txt",
        "pass-to-pass.xml",
        "fail-to-pass.xml",
        "pytest-evidence.json",
    ):
        (output / name).unlink(missing_ok=True)
    environment = dict(os.environ)
    for key in ("PYTEST_ADDOPTS", "PYTEST_DISABLE_PLUGIN_AUTOLOAD", "PYTHONPATH"):
        environment.pop(key, None)
    commands, native_exit = [], 0
    invoke = invoke or subprocess.run
    for group in ("pass-to-pass", "fail-to-pass"):
        if (
            not isinstance(expected[group], list)
            or not expected[group]
            or any(
                not isinstance(target, str) or not target for target in expected[group]
            )
        ):
            raise ValueError("Frozen native pytest selectors are incomplete")
        command = [
            *config["official_pytest_argv"],
            "--override-ini=addopts=",
            "--junitxml=" + str(output / (group + ".xml")),
            *expected[group],
        ]
        result = invoke(command, cwd=worktree, env=environment, check=False)
        native_exit = result.returncode
        commands.append({"group": group, "argv": command, "exit_code": native_exit})
        if native_exit != 0:
            break
    (output / "pytest-commands.json").write_text(
        json.dumps(commands, sort_keys=True) + "\n"
    )
    spec = importlib.util.spec_from_file_location(
        "trusted_pytest_result", private_root / "check_pytest.py"
    )
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)
    result = checker.assess(output, expected, native_exit)
    (output / "reward.txt").write_text(str(result["reward"]) + "\n")
    (output / "pytest-evidence.json").write_text(
        json.dumps(result, sort_keys=True) + "\n"
    )
    return result


if __name__ == "__main__":
    run("/testbed/repo", "/tests", "/logs/verifier")
