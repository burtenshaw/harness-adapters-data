"""Prepare private Python Git-patch Jobs tasks from captured TaskTrove bytes."""

import argparse
import hashlib
import json
import re
import shlex
import stat
from pathlib import Path, PurePosixPath

HERE = Path(__file__).resolve().parent
PILOT = HERE.parents[1]
SOURCE = PILOT / "expanded-python-intake/release-v1"
INDEX_SHA = "55a8cdf68e0bab301ae92a7f48615d145e87a03563c02781f5dc0ffbf0b23597"
MAX_PATCH = 16 * 1024**2
PYTEST = 'if python3 -m pytest -q -x --override-ini=addopts= "${tests[@]}"; then'
PILOT_IDS = ("swegym-0627", "swegym-1899", "swegym-1099", "swegym-0385")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def safe(name):
    path = PurePosixPath(name)
    if (
        not re.fullmatch(r"[A-Za-z0-9_+./@-]+", name)
        or path.is_absolute()
        or path.as_posix() != name
        or any(p in {".", "..", ".git"} for p in path.parts)
    ):
        raise ValueError("Unsupported patch/source path")
    return path


def validate_patch(raw):
    if type(raw) is not bytes or len(raw) > MAX_PATCH:
        raise ValueError("Patch byte envelope exceeded")
    text = raw.decode("utf-8")
    paths = []
    current = None
    if not text:
        return []
    if not text.startswith("diff --git "):
        raise ValueError("Canonical Git diff required")
    for line in text.splitlines():
        if line.startswith("diff --git "):
            tokens = shlex.split(line)
            if (
                len(tokens) != 4
                or not tokens[2].startswith("a/")
                or not tokens[3].startswith("b/")
            ):
                raise ValueError("Malformed patch header")
            old, new = tokens[2][2:], tokens[3][2:]
            safe(old)
            safe(new)
            if old != new or old in paths:
                raise ValueError("Renames or repeated file patches unsupported")
            paths.append(old)
            current = old
        elif line.startswith(
            (
                "rename from ",
                "rename to ",
                "copy from ",
                "copy to ",
                "similarity index ",
            )
        ):
            raise ValueError("Canonical no-renames diff required")
        elif line.startswith(
            ("new file mode ", "deleted file mode ", "old mode ", "new mode ")
        ):
            if line.rsplit(" ", 1)[-1] not in {"100644", "100755"}:
                raise ValueError("Symlink/submodule/special modes unsupported")
        elif line.startswith(("--- ", "+++ ")):
            value = line[4:]
            if value != "/dev/null":
                prefix = "a/" if line.startswith("--- ") else "b/"
                if not value.startswith(prefix) or value[2:] != current:
                    raise ValueError("Patch path differs from header")
        if len(paths) > 512:
            raise ValueError("Too many patch paths")
    if not paths:
        raise ValueError("Empty noncanonical patch")
    return paths


def gold_patch(solution):
    found = re.findall(
        r"<<'SOLUTION_PATCH_EOF'[^\n]*\n(.*?)\nSOLUTION_PATCH_EOF(?:\n|$)",
        solution,
        re.S,
    )
    if len(found) != 1:
        raise ValueError("Expected one frozen solution patch heredoc")
    raw = (found[0] + "\n").encode()
    validate_patch(raw)
    return raw


def partial_patch(raw):
    lines = raw.decode().splitlines(keepends=True)
    hunks = [i for i, line in enumerate(lines) if line.startswith("@@ ")]
    if len(hunks) < 2:
        return None
    first = hunks[0]
    start = max(
        i for i, line in enumerate(lines[:first]) if line.startswith("diff --git ")
    )
    end = next(
        (
            i
            for i in range(first + 1, len(lines))
            if lines[i].startswith(("@@ ", "diff --git "))
        ),
        len(lines),
    )
    value = "".join(lines[start:end]).encode()
    validate_patch(value)
    return value


def dependency_setup(stock):
    # Delimit using the next function, because later source contains braces too.
    begins = list(re.finditer(r"(?m)^[ \t]*ensure_dependencies\(\) \{\s*$", stock))
    ends = list(re.finditer(r"(?m)^[ \t]*run_test_group\(\) \{\s*$", stock))
    if len(begins) != 1 or len(ends) != 1 or begins[0].start() >= ends[0].start():
        raise ValueError("Unknown dependency function shape")
    function = stock[begins[0].start() : ends[0].start()].rstrip()
    if not function.endswith("}"):
        raise ValueError("Incomplete dependency function")
    if function.count("ensure_dependencies() {") != 1:
        raise ValueError("Ambiguous dependency function")
    return (
        '#!/bin/bash\nset -Eeuo pipefail\nsource /opt/miniconda3/bin/activate\nconda activate testbed\ncd /testbed/repo\nlog(){ printf "[setup] %s\\n" "$*"; }\n'
        + function
        + "\nensure_dependencies\ntouch /tmp/tasktrove-agent-setup-complete\n"
    ).encode()


def instrument(stock):
    if stock.count(PYTEST) != 1:
        raise ValueError("Unsupported native pytest invocation")
    return stock.replace(
        PYTEST,
        'if python3 -m pytest -q -x --override-ini=addopts= --junitxml="$VERIFIER_DIR/${label}.xml" "${tests[@]}"; then',
    ).encode()


def capture(row):
    inventory_raw = (SOURCE / row["inventory_path"]).read_bytes()
    if sha(inventory_raw) != row["native_inventory_sha256"]:
        raise ValueError("Original native inventory drift")
    expected = json.loads(inventory_raw)
    root = SOURCE / row["task_path"]
    files = {}
    for name, item in expected.items():
        safe(name)
        p = root / name
        before = p.lstat()
        if not stat.S_ISREG(before.st_mode) or p.is_symlink():
            raise ValueError("Native file is not a regular captured file")
        raw = p.read_bytes()
        mode = stat.S_IMODE(before.st_mode)
        if (
            sha(raw) != item["sha256"]
            or len(raw) != item["bytes"]
            or mode != item["mode"]
        ):
            raise ValueError("Native bytes or mode drift")
        files[name] = (raw, mode)
    if set(files) != {
        p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()
    }:
        raise ValueError("Native path set drift")
    return files


def prepare(output):
    raw = (SOURCE / "candidates.jsonl").read_bytes()
    if sha(raw) != INDEX_SHA:
        raise ValueError("Approved source index drift")
    rows = [json.loads(line) for line in raw.splitlines()]
    seen = set()
    compat = []
    selected = []
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    for row in rows:
        key = (row["source_repo"].casefold(), row["source_pr_url"])
        if key in seen:
            raise ValueError("Repeated source PR identity")
        seen.add(key)
        files = capture(row)
        try:
            solution = files["solution/solve.sh"][0].decode()
            stock = files["tests/test.sh"][0].decode()
            patch = gold_patch(solution)
            if any(
                "requirements" in p
                or PurePosixPath(p).name
                in {"setup.py", "setup.cfg", "pyproject.toml", "Pipfile", "poetry.lock"}
                for p in validate_patch(patch)
            ):
                raise ValueError(
                    "Dependency-file repairs require post-patch environment reconstruction"
                )
            setup = dependency_setup(stock)
            instrumented = instrument(stock)
            if not row["fail_to_pass"] or not row["pass_to_pass"]:
                raise ValueError("Both native test panels required")
            status = "source_adapter_shape_supported_pending_runtime"
        except (ValueError, UnicodeError) as e:
            compat.append(
                {
                    "task_id": row["task_id"],
                    "source_repo": row["source_repo"],
                    "status": "blocked_native_script_shape",
                    "reason": str(e),
                }
            )
            continue
        compat.append(
            {
                "task_id": row["task_id"],
                "source_repo": row["source_repo"],
                "status": status,
                "runtime_resource_review_required": row[
                    "runtime_resource_review_required"
                ],
            }
        )
        if row["task_id"] not in PILOT_IDS:
            continue
        target = output / "tasks" / row["task_id"]
        for name, (payload, mode) in files.items():
            p = target / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(payload)
            p.chmod(mode)
        (target / "tests/native-test.sh").write_bytes(stock.encode())
        (target / "tests/native-test-instrumented.sh").write_bytes(instrumented)
        (target / "tests/expected-panels.json").write_bytes(
            canonical(
                {
                    "pass-to-pass": row["pass_to_pass"],
                    "fail-to-pass": row["fail_to_pass"],
                }
            )
        )
        (target / "tests/check_pytest.py").write_bytes(
            (HERE / "pytest_result.py").read_bytes()
        )
        wrapper = b'#!/bin/bash\nset -Eeuo pipefail\nmkdir -p /logs/verifier\nrm -f /logs/verifier/pass-to-pass.xml /logs/verifier/fail-to-pass.xml\nset +e\nbash /tests/native-test-instrumented.sh\ncode=$?\nset -e\nexec python3 /tests/check_pytest.py --root /logs/verifier --expected /tests/expected-panels.json --native-exit "$code"\n'
        (target / "tests/test.sh").write_bytes(wrapper)
        (target / "tests/test.sh").chmod(0o755)
        validation = target / "validation"
        (validation / "canaries").mkdir(parents=True)
        (validation / "canaries/unmodified.sh").write_text("#!/bin/bash\n:\n")
        (validation / "canaries/test-delete.sh").write_text(
            "#!/bin/bash\nset -eu\ncd /testbed/repo\nwhile IFS= read -r path; do rm -rf -- \"$path\"; done <<'CONTROL_PATHS'\n"
            + files["tests/trusted_test_paths.txt"][0].decode()
            + "\nCONTROL_PATHS\n"
        )
        (validation / "canaries/stale-reward.sh").write_text(
            '#!/bin/bash\nmkdir -p /logs/verifier\nprintf "1\\n" > /logs/verifier/reward.txt\n'
        )
        partial = partial_patch(patch)
        if partial is not None:
            (validation / "canaries/test-delete.sh").unlink()
            (validation / "canaries/partial-repair.sh").write_text(
                "#!/bin/bash\nset -eu\ncd /testbed/repo\ncat > /tmp/openenv-partial.diff <<'OPENENV_PARTIAL'\n"
                + partial.decode()
                + "OPENENV_PARTIAL\ngit -c core.hooksPath=/dev/null apply --whitespace=nowarn /tmp/openenv-partial.diff\n"
            )
        for p in (validation / "canaries").glob("*.sh"):
            p.chmod(0o755)
        contract = {
            "profile": "harbor-semantic-v1",
            "reward_key": "reward",
            "reward": {"range": [0, 1], "oracle_tolerance": 0, "floor_margin": 0.1},
            "resources": {
                "cpu": 2,
                "memory_mb": 8192,
                "disk_mb": 16384,
                "episode_timeout_s": 1800,
            },
            "types": {"tags": ["swe", "python", "repository-repair"]},
            "canaries": "validation/canaries",
            "requires_credentials": False,
        }
        (validation / "openenv.json").write_bytes(canonical(contract))
        descriptor = {
            "schema": "python-git-patch-jobs-v1",
            "task_id": row["task_id"],
            "source_repo": row["source_repo"],
            "source_base_commit": row["source_commit"],
            "source_pr_url": row["source_pr_url"],
            "repo_url": "https://github.com/" + row["source_repo"] + ".git",
            "source_index_sha256": INDEX_SHA,
            "native_inventory_sha256": row["native_inventory_sha256"],
            "gold_patch_sha256": sha(patch),
            "collector_sha256": sha((HERE / "collect.py").read_bytes()),
            "dependency_setup_sha256": sha(setup),
            "dependency_installation_pinned": False,
            "runtime_ready": False,
            "transfer": "index-independent-worktree-to-Git-binary-patch",
            "transfer_path": "/testbed/submission.patch",
            "new_files_deletions_and_executable_modes_supported": True,
            "symlink_submodule_changes_supported": False,
            "known_wrong_semantic_implementations": 0,
            "partial_repair_canary": partial is not None,
            "partial_repair_sha256": None if partial is None else sha(partial),
            "partial_repair_wrongness_established": False,
            "canary_selection": "Fixed first gold hunk, never selected from observed rewards; reward1 requires semantic review",
            "extra_canaries": "test-reset and stale-reward boundary probes, not distinct semantic bugs",
            "runtime_image": None,
            "source_record": row,
        }
        (target / "adapter.json").write_bytes(canonical(descriptor))
        (target / "dependency-setup.sh").write_bytes(setup)
        (target / "provided-gold.diff").write_bytes(patch)
        selected.append(
            {
                "task_id": row["task_id"],
                "task_path": target.relative_to(output).as_posix(),
                "source_repo": row["source_repo"],
                "status": "prepared_private_adapter_pending_runtime_and_dependency_lock",
                "adapter_sha256": sha(canonical(descriptor)),
            }
        )
    (output / "compatibility.jsonl").write_text(
        "".join(json.dumps(x, sort_keys=True) + "\n" for x in compat)
    )
    result = {
        "source_index_sha256": INDEX_SHA,
        "source_rows": len(rows),
        "supported_shapes": sum(
            x["status"] == "source_adapter_shape_supported_pending_runtime"
            for x in compat
        ),
        "pilot_tasks": selected,
        "runtime_qualified": 0,
        "paid_calls": 0,
        "remote_writes": 0,
    }
    (output / "manifest.json").write_bytes(canonical(result))
    return result


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    print(json.dumps(prepare(a.output)))
