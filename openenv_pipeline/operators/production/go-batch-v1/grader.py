"""Frozen package-qualified Go test grading, executed only in task sandboxes."""

import hashlib
import json
import os
import selectors
import signal
import subprocess
import time
from pathlib import Path, PurePosixPath


def assess(events, expected, returncode):
    required = [(row["package"], row["test"]) for row in expected]
    if not required or len(set(required)) != len(required):
        raise ValueError("Required Go identities must be nonempty and unique")
    runs, passes, package_passes, bad = {}, {}, set(), []
    malformed = 0
    for line in events.splitlines():
        try:
            event = json.loads(line)
        except (ValueError, TypeError):
            malformed += 1
            continue
        if not isinstance(event, dict) or not isinstance(event.get("Package"), str):
            malformed += 1
            continue
        package, name, action = event["Package"], event.get("Test"), event.get("Action")
        if name is None:
            if action == "pass":
                package_passes.add(package)
            elif action == "fail":
                bad.append([package, None, action])
            continue
        if not isinstance(name, str):
            malformed += 1
            continue
        key = (package, name)
        if action == "run":
            runs[key] = runs.get(key, 0) + 1
        elif action == "pass":
            passes[key] = passes.get(key, 0) + 1
        elif action in {"fail", "skip"}:
            bad.append([package, name, action])
        # Never parse Output strings as event records.
    missing = [
        list(key) for key in required if runs.get(key) != 1 or passes.get(key) != 1
    ]
    passed = (
        returncode == 0
        and not missing
        and not bad
        and not malformed
        and all(package in package_passes for package, _ in required)
    )
    return {
        "passed": passed,
        "reward": int(passed),
        "required": len(required),
        "missing_or_duplicate": missing,
        "failed_or_skipped": bad,
        "malformed_lines": malformed,
        "exit_code": returncode,
    }


def bounded_run(argv, cwd, seconds):
    process = subprocess.Popen(
        argv,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    output, deadline = bytearray(), time.monotonic() + seconds
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                if time.monotonic() >= deadline:
                    raise TimeoutError("Go verifier deadline exceeded")
                for key, _ in selector.select(min(1, deadline - time.monotonic())):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        output.extend(chunk)
                        if len(output) > 4 * 1024 * 1024:
                            raise ValueError("Go verifier output bound exceeded")
        return process.wait(timeout=max(0.001, deadline - time.monotonic())), bytes(
            output
        )
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        raise
    finally:
        process.stdout.close()


def main():
    private, workspace, output = (
        Path(__file__).resolve().parent,
        Path("/testbed"),
        Path("/logs/verifier"),
    )
    output.mkdir(parents=True, exist_ok=True)
    reward = output / "reward.txt"
    reward.unlink(missing_ok=True)
    try:
        manifest = json.loads((private / "manifest.json").read_bytes())
        fixtures = {}
        for name, item in manifest["frozen_files"].items():
            path = PurePosixPath(name)
            if path.is_absolute() or path.as_posix() != name or ".." in path.parts:
                raise ValueError("Unsafe frozen fixture path")
            raw = (private / "frozen" / name).read_bytes()
            if hashlib.sha256(raw).hexdigest() != item["sha256"]:
                raise ValueError("Frozen fixture hash mismatch")
            fixtures[name] = raw
        if (workspace / ".git").exists():
            raise ValueError("Task Git history is unsupported")
        for path in workspace.rglob("*_test.go"):
            if path.is_symlink() or not path.is_file():
                raise ValueError("Unsafe submitted test path")
            path.unlink()
        for name, raw in fixtures.items():
            target = workspace / name
            if target.is_symlink() or any(p.is_symlink() for p in target.parents):
                raise ValueError("Unsafe fixture destination")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
            target.chmod(manifest["frozen_files"][name]["mode"])
        code, _ = bounded_run(["/usr/local/go/bin/go", "mod", "verify"], workspace, 30)
        if code:
            raise ValueError("Offline dependency verification failed")
        code, raw = bounded_run(manifest["command"], workspace, 240)
        if code not in {0, 1}:
            raise ValueError("Go verifier terminated unexpectedly")
        result = assess(raw.decode("utf-8"), manifest["expected"], code)
        (output / "test-result.json").write_text(
            json.dumps(result, sort_keys=True) + "\n"
        )
        reward.write_text(str(result["reward"]) + "\n")
        return 0
    except Exception as error:
        (output / "infrastructure-error.json").write_text(
            json.dumps({"error_type": type(error).__name__}) + "\n"
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
