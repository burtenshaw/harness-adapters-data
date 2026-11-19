"""Package source-bound SWE-smith mutations for the frozen Python Jobs adapter."""

import argparse
import ast
import difflib
import hashlib
import importlib.util
import json
import re
import shlex
import stat
import types
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
PILOT = HERE.parents[1]
SOURCE = PILOT / "additional-repositories-v2"
ADAPTER = HERE.parent / "python-jobs-wave-v1"
INDEX_SHA = None
RECEIPTS_SHA = None
CHECKER_SHA = "f0a641064b725415e23a0221bb53c90446d7efcb7f9ece5ede93a220d18dd9e7"
SOURCE_INDEX = None
SOURCE_RECEIPTS = None
PROFILE_SHA = "eadf29551ca2e706950d3f2311b47a3d08c2ccee3c8dd217fa299014a08e4286"
GRADE_SHA = "96de34c90678a8438ee8606a21356a664262b869dc088594eb986f0cc0614250"
FROZEN = {
    "adapter.py": "f1d00402201618e916ef6e7d81941013c53f7f0c8db5e560c09078f988461bb8",
    "backend.py": "49e2d28eb490a9307d4f0077829532de2f1639e88fcdc2b723a34feda1046be7",
    "collect.py": "352e555112f2de8a1393f939903e4971c9ace0e944843762b707a725c5c72481",
    "pytest_result.py": "ce5f5ada4c63ab61c57177833687df68fcfe04df971699cb3e6ceada5722d2ed",
}
TEST_CONFIG = {
    "pyproject.toml",
    "setup.cfg",
    "setup.py",
    "pytest.ini",
    "tox.ini",
    "conftest.py",
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def captured(path, expected, read=None):
    if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
        raise ValueError("Captured source is not a regular real file")
    raw = (read or Path.read_bytes)(path)
    if sha(raw) != expected:
        raise ValueError("Captured source differs from original proof")
    return raw


def frozen():
    sources = {}
    for name, digest in FROZEN.items():
        sources[name] = captured(ADAPTER / name, digest)
    module = types.ModuleType("frozen_python_jobs_adapter")
    module.__file__ = str(ADAPTER / "adapter.py")
    exec(compile(sources["adapter.py"], module.__file__, "exec"), module.__dict__)
    return module


def rows():
    return [json.loads(line) for line in captured(SOURCE_INDEX, INDEX_SHA).splitlines()]


def capture_task(row):
    root = SOURCE / Path(row["provenance_path"]).parent
    receipts = json.loads(captured(SOURCE_RECEIPTS, RECEIPTS_SHA))[
        "completion_receipts_sha256"
    ]
    relative = (Path(row["provenance_path"]).parent / "completion.json").as_posix()
    receipt_raw = captured(root / "completion.json", receipts[relative])
    receipt = json.loads(receipt_raw)
    observed = {
        p.relative_to(root).as_posix()
        for p in root.rglob("*")
        if p.is_file() and p.name != "completion.json"
    }
    if observed != set(receipt["files"]):
        raise ValueError("Original captured source file set drifted")
    raw = {
        name: captured(root / name, digest) for name, digest in receipt["files"].items()
    }
    if json.loads(raw["candidate.json"]) != row:
        raise ValueError("Source row differs from exact captured candidate")
    proof, native, inventories = (
        json.loads(raw[name])
        for name in ("source-proof.json", "row.json", "file-inventories.json")
    )
    surfaces = {}
    for role in ("learner", "private-tests", "reference"):
        values = {}
        for name, item in inventories[role].items():
            path = root / role / name
            payload = raw[role + "/" + name]
            mode = 0o755 if item["mode"] == "100755" else 0o644
            blob = hashlib.sha1(
                b"blob " + str(len(payload)).encode() + b"\0" + payload
            ).hexdigest()
            if (
                sha(payload) != item["sha256"]
                or len(payload) != item["size"]
                or blob != item["git_blob_sha1"]
                or stat.S_IMODE(path.stat().st_mode) != mode
            ):
                raise ValueError("Source byte/Git/mode inventory drifted")
            values[name] = (payload, mode)
        surfaces[role] = values
    if set(surfaces["learner"]) & set(surfaces["private-tests"]):
        raise ValueError("Private F2P files leaked into learner")
    bug = {**surfaces["learner"], **surfaces["private-tests"]}
    for group in ("FAIL_TO_PASS", "PASS_TO_PASS"):
        if native[group] != proof[group] or not native[group]:
            raise ValueError("Exact native pytest panel drifted")
        if any(target.split("::", 1)[0] not in bug for target in native[group]):
            raise ValueError("Native pytest file missing")
    if any(
        target.split("::", 1)[0] not in surfaces["private-tests"]
        for target in native["FAIL_TO_PASS"]
    ):
        raise ValueError("F2P file remains public")
    if proof["commits"]["learner"] != row["source_commit"] or not re.fullmatch(
        r"[a-f0-9]{40}", row["source_commit"]
    ):
        raise ValueError("Broken source BASE identity drifted")
    return native, proof, surfaces, raw, sha(receipt_raw)


def patch_for(files, reference):
    pieces = []
    for name, (healthy, mode) in sorted(reference.items()):
        old, old_mode = files[name]
        if old_mode != mode:
            raise ValueError("Reference changes an executable mode")
        if old == healthy:
            raise ValueError("Reference contains an unchanged source file")
        diff = difflib.unified_diff(
            old.decode().splitlines(keepends=True),
            healthy.decode().splitlines(keepends=True),
            fromfile="a/" + name,
            tofile="b/" + name,
        )
        body = []
        for line in diff:
            body.append(
                line
                if line.endswith("\n")
                else line + "\n\\ No newline at end of file\n"
            )

        def git_blob(value):
            return hashlib.sha1(
                b"blob " + str(len(value)).encode() + b"\0" + value
            ).hexdigest()

        pieces.append(
            "diff --git a/"
            + name
            + " b/"
            + name
            + "\nindex "
            + git_blob(old)
            + ".."
            + git_blob(healthy)
            + " "
            + ("100755" if mode & 0o111 else "100644")
            + "\n"
            + "".join(body)
        )
    return "".join(pieces).encode()


def trusted_surface(bug):
    roots = set()
    for name in bug:
        parts = Path(name).parts
        for index, part in enumerate(parts[:-1]):
            if part in {"test", "tests"}:
                roots.add("/".join(parts[: index + 1]))
                break
    trusted = {
        name: value
        for name, value in bug.items()
        if any(name.startswith(root + "/") for root in roots)
        or name in TEST_CONFIG
        or Path(name).name == "conftest.py"
    }
    return trusted, sorted(roots)


def official_declarations(profile):
    raw = captured(SOURCE / "python-profiles.py", PROFILE_SHA)
    classes = {
        node.name: node
        for node in ast.parse(raw).body
        if isinstance(node, ast.ClassDef)
    }
    node = classes[profile["profile_class"]]
    if not any(
        isinstance(base, ast.Name) and base.id == "PythonProfile" for base in node.bases
    ):
        raise ValueError("Unsupported official profile inheritance")
    fields = {}
    for cls in (classes["PythonProfile"], node):
        for declaration in cls.body:
            if isinstance(declaration, ast.AnnAssign) and isinstance(
                declaration.target, ast.Name
            ):
                fields[declaration.target.id] = declaration.value
    version = ast.literal_eval(fields["python_version"])
    install = fields["install_cmds"]
    if not isinstance(install, ast.Call):
        raise ValueError("Unsupported official install declaration")
    factories = [
        keyword.value
        for keyword in install.keywords
        if keyword.arg == "default_factory"
    ]
    if len(factories) != 1 or not isinstance(factories[0], ast.Lambda):
        raise ValueError("Unsupported official install factory")
    commands = ast.literal_eval(factories[0].body)
    if not isinstance(commands, list) or any(
        not isinstance(value, str) for value in commands
    ):
        raise ValueError("Official commands are not a literal string list")
    test = fields["test_cmd"]
    if not isinstance(test, ast.JoinedStr):
        raise ValueError("Unsupported official test invocation")
    text = ""
    for value in test.values:
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            text += value.value
        elif (
            isinstance(value, ast.FormattedValue)
            and isinstance(value.value, ast.Name)
            and value.value.id == "ENV_NAME"
        ):
            text += "testbed"
        else:
            raise ValueError("Unsupported official test substitution")
    prefix = "source /opt/miniconda3/bin/activate; conda activate testbed; "
    if not text.startswith(prefix):
        raise ValueError("Unknown official environment activation")
    argv = shlex.split(text.removeprefix(prefix))
    if version != "3.10" or argv != [
        "pytest",
        "--disable-warnings",
        "--color=no",
        "--tb=no",
        "--verbose",
    ]:
        raise ValueError(
            "Official Python version or pytest invocation needs separate runtime qualification"
        )
    return commands, argv, text


def recipe(repo, bug, profile):
    # All eight admitted official profiles inherit Python3.10 and this exact
    # PythonProfile invocation. Supplemental dependencies come from the frozen
    # repository's own test environment declarations, recorded below.
    if profile["profile_source_sha256"] != PROFILE_SHA:
        raise ValueError("Official Python profile pin changed")
    extras = {
        "davidhalter/parso": (["python -m pip install -e '.[testing]'"], ["setup.py"]),
        "lepture/mistune": ([], ["pyproject.toml"]),
        "kayak/pypika": (
            ["python -m pip install parameterized==0.7.0"],
            ["setup.py", "requirements-dev.txt", "tox.ini"],
        ),
        "agronholm/exceptiongroup": (
            ["python -m pip install -e '.[test]'"],
            ["pyproject.toml"],
        ),
        "python-hyper/h11": (
            ["python -m pip install -r test-requirements.txt"],
            ["setup.py", "test-requirements.txt", "tox.ini"],
        ),
        "life4/textdistance": ([], ["setup.py", "setup.cfg"]),
        "cloudpipe/cloudpickle": (
            ["python -m pip install -r dev-requirements.txt"],
            ["pyproject.toml", "dev-requirements.txt", "tox.ini"],
        ),
        "facelessuser/soupsieve": (
            ["python -m pip install -r requirements/tests.txt"],
            ["pyproject.toml", "requirements/tests.txt"],
        ),
        "Suor/funcy": (
            ["python -m pip install -r test_requirements.txt"],
            ["setup.py", "test_requirements.txt", "tox.ini"],
        ),
    }
    supplement, evidence_paths = extras[repo]
    official, pytest_argv, official_test = official_declarations(profile)
    for name in evidence_paths:
        if name not in bug:
            raise ValueError("Source-bound dependency declaration missing: " + name)
    # Operator runner prerequisite is separate from native project requirements.
    # Funcy's source explicitly pins pytest7.4.3; retain that native declaration.
    operator = [] if repo == "Suor/funcy" else ["python -m pip install pytest==8.4.2"]
    setup = [
        "#!/bin/bash",
        "set -Eeuo pipefail",
        "source /opt/miniconda3/bin/activate",
        "conda activate testbed",
        "cd /testbed/repo",
        "python -c 'import sys; assert sys.version_info[:2] == (3, 10)'",
        *operator,
        *official,
        *supplement,
    ]
    return ("\n".join(setup) + "\n").encode(), {
        "python_version": "3.10",
        "official_install_cmds": official,
        "operator_test_runner_prerequisites": operator,
        "operator_test_runner_reason": "The official profile invokes pytest, but the common tools runtime does not provide it; pinned separately from source-native project requirements.",
        "source_bound_test_dependency_cmds": supplement,
        "test_dependency_source_sha256": {
            name: sha(bug[name][0]) for name in evidence_paths
        },
        "official_pytest_argv": pytest_argv,
        "official_test_command": official_test,
        "panel_normalization": "Override project addopts only to execute the exact frozen native panels; add JUnit output, preserve official pytest options and all selectors.",
        "dependency_installation_pinned": False,
    }


def write(root, name, raw, mode=0o644):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    path.chmod(mode)


def apply_script(patch, delimiter="OPENENV_REFERENCE"):
    return (
        "#!/bin/bash\nset -Eeuo pipefail\ncd /testbed/repo\ncat > /tmp/openenv-reference.diff <<'"
        + delimiter
        + "'\n"
        + patch.decode()
        + delimiter
        + "\n/usr/bin/git -c core.hooksPath=/dev/null -c core.fsmonitor=false apply --whitespace=nowarn /tmp/openenv-reference.diff\n"
    ).encode()


def prepare_one(row, output, adapter, grade_source):
    native, proof, surfaces, raw, receipt_sha = capture_task(row)
    bug = {**surfaces["learner"], **surfaces["private-tests"]}
    if set(surfaces["reference"]) != set(proof["source_paths"]):
        raise ValueError("Reference/source mutation path set drifted")
    patch = patch_for(bug, surfaces["reference"])
    if any(Path(name).name in TEST_CONFIG for name in adapter.validate_patch(patch)):
        raise ValueError(
            "Dependency/test-configuration repairs require another qualified adapter"
        )
    partial = adapter.partial_patch(patch)
    trusted, test_roots = trusted_surface(bug)
    if any(
        target.split("::", 1)[0] not in trusted
        for group in ("FAIL_TO_PASS", "PASS_TO_PASS")
        for target in native[group]
    ):
        raise ValueError("Native test file outside trusted restoration surface")
    setup, config = recipe(row["upstream_repo"], bug, proof["official_profile"])
    key = sha(row["task_id"].encode())[:24]
    target = output / "tasks" / key
    target.mkdir(parents=True, exist_ok=False)
    write(target, "instruction.md", native["problem_statement"].encode())
    write(target, "provided-gold.diff", patch)
    write(target, "solution/solve.sh", apply_script(patch), 0o755)
    write(target, "dependency-setup.sh", setup, 0o755)
    write(target, "tests/grade.py", grade_source)
    write(
        target,
        "tests/check_pytest.py",
        captured(HERE / "check_pytest.py", CHECKER_SHA),
    )
    expected = {
        "fail-to-pass": native["FAIL_TO_PASS"],
        "pass-to-pass": native["PASS_TO_PASS"],
    }
    write(target, "tests/expected-panels.json", encode(expected))
    write(target, "tests/panel-config.json", encode(config))
    inventory = {
        name: {"sha256": sha(payload), "bytes": len(payload), "mode": mode}
        for name, (payload, mode) in sorted(trusted.items())
    }
    write(
        target,
        "tests/trusted-inventory.json",
        encode({"directory_roots": test_roots, "files": inventory}),
    )
    for name, (payload, mode) in trusted.items():
        write(target, "tests/trusted/" + name, payload, mode)
    write(
        target,
        "tests/test.sh",
        b"#!/bin/bash\nset -Eeuo pipefail\nsource /opt/miniconda3/bin/activate\nconda activate testbed\ncd /testbed/repo\nexec python -I /tests/grade.py\n",
        0o755,
    )
    write(
        target,
        "validation/canaries/original-bug.sh",
        b"#!/bin/bash\nset -Eeuo pipefail\n:\n",
        0o755,
    )
    if partial is not None:
        write(
            target,
            "validation/canaries/first-hunk-only.sh",
            apply_script(partial, "OPENENV_PARTIAL"),
            0o755,
        )
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
        "types": {"tags": ["swe", "python", "mutation-repair"]},
        "canaries": "validation/canaries",
        "requires_credentials": False,
    }
    write(target, "validation/openenv.json", encode(contract))
    write(
        target,
        "task.toml",
        b'version = "1.0"\n\n[agent]\ntimeout_sec = 1800.0\n\n[verifier]\ntimeout_sec = 900.0\n\n[environment]\nbuild_timeout_sec = 600.0\ncpus = 2\nmemory_mb = 8192\nstorage_mb = 16384\n\n[metadata]\nauthor_name = "SWE-smith source adapter"\ncategory = "bugfix"\ntags = ["swe", "python", "mutation-repair"]\n',
    )
    write(
        target,
        "environment/Dockerfile",
        b"# Runtime is selected only by an independently qualified immutable amd64 receipt.\nFROM ubuntu:22.04\nRUN false\n",
    )
    descriptor = {
        "schema": "python-git-patch-jobs-v1",
        "task_id": row["task_id"],
        "source_repo": row["source_repo"],
        "upstream_repo": row["upstream_repo"],
        "source_base_commit": row["source_commit"],
        "source_pr_url": None,
        "repo_url": "https://github.com/" + row["source_repo"] + ".git",
        "source_index_sha256": INDEX_SHA,
        "source_completion_sha256": receipt_sha,
        "native_inventory_sha256": sha(raw["file-inventories.json"]),
        "gold_patch_sha256": sha(patch),
        "collector_sha256": FROZEN["collect.py"],
        "dependency_setup_sha256": sha(setup),
        "dependency_installation_pinned": False,
        "runtime_ready": False,
        "runtime_image": None,
        "transfer": "index-independent-worktree-to-Git-binary-patch",
        "transfer_path": "/testbed/submission.patch",
        "new_files_deletions_and_executable_modes_supported": True,
        "symlink_submodule_changes_supported": False,
        "known_wrong_semantic_implementations": 0,
        "private_checker_sha256": CHECKER_SHA,
        "private_checker_version": "matched-failure-precedence-v2",
        "positive_approval_policy": "All original strict presence/identity/no-skip/no-error/exit checks retained",
        "provided_original_bug_control": True,
        "original_bug_runtime_wrongness_established": False,
        "original_bug_canary_nop_equivalent": True,
        "partial_repair_canary": partial is not None,
        "partial_repair_sha256": None if partial is None else sha(partial),
        "partial_repair_wrongness_established": False,
        "canary_selection": "Fixed first provided gold hunk only when at least2hunks exist; strict subset, never reward-selected. Single-hunk task original-bug canary is explicitly NOP-equivalent and adds no signal beyond floor_gap.",
        "source_record": row,
        "official_profile": proof["official_profile"],
        "runtime_recipe": config,
        "runtime_resource_review_required": False,
        "hostile_code_isolation_established": False,
    }
    write(target, "adapter.json", encode(descriptor))
    write(
        target,
        "metadata.json",
        encode(
            {
                "source_record": row,
                "source_healthy_reference_proof": proof,
                "official_profile": proof["official_profile"],
                "task_kind": "original-source-mutation",
                "all_runtime_and_training_flags": False,
            }
        ),
    )
    write(
        target,
        "provenance.json",
        encode(
            {
                "source_record": row,
                "source_proof_sha256": sha(raw["source-proof.json"]),
                "source_completion_sha256": receipt_sha,
                "source_index_sha256": INDEX_SHA,
                "provided_reference": True,
                "generated_reference": False,
                "healthy_reference_delta_sha256": sha(patch),
                "native_pytest_ids_preserved": True,
                "trusted_tests_sha256": sha(encode(inventory)),
                "original_source_code_license": row["license_evidence"]["source_code"],
                "task_bundle_license": row["license_evidence"]["task_bundle"],
                "runtime_qualified": False,
                "training_admissible": False,
                "qwen_calibrated": False,
            }
        ),
    )
    write(target, "LICENSE.source", raw["LICENSE.source"])
    inventory = {
        p.relative_to(target).as_posix(): {
            "sha256": sha(p.read_bytes()),
            "bytes": p.stat().st_size,
            "mode": stat.S_IMODE(p.stat().st_mode),
        }
        for p in sorted(target.rglob("*"))
        if p.is_file()
    }
    runtime_inventory = {
        name: {
            "sha256": item["sha256"],
            "mode": oct(item["mode"]),
            "size": item["bytes"],
        }
        for name, item in inventory.items()
    }
    return {
        "task_id": row["task_id"],
        "task_path": target.relative_to(output).as_posix(),
        "source_repo": row["source_repo"],
        "upstream_repo": row["upstream_repo"],
        "language": "python",
        "adapter_kind": "python-git-patch-v1",
        "adapter_sha256": sha(encode(descriptor)),
        "task_inventory_sha256": sha(
            json.dumps(
                runtime_inventory, sort_keys=True, separators=(",", ":")
            ).encode()
        ),
        "preparation_file_inventory_sha256": sha(encode(inventory)),
        "files": inventory,
        "fail_to_pass_count": len(native["FAIL_TO_PASS"]),
        "pass_to_pass_count": len(native["PASS_TO_PASS"]),
        "canaries": 2 if partial is not None else 1,
        "runtime_ready": False,
        "cloud_launch_ready": False,
        "training_admissible": False,
    }


def prepare(output, pilot=False):
    adapter = frozen()
    grade_source = captured(HERE / "grade.py", GRADE_SHA)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    selected = rows()
    if pilot:
        chosen = []
        for repo in ("lepture/mistune", "python-hyper/h11"):
            eligible = [row for row in selected if row["upstream_repo"] == repo]
            chosen.append(
                min(
                    eligible,
                    key=lambda row: sum(
                        len(
                            json.loads((SOURCE / row["provenance_path"]).read_bytes())[
                                group
                            ]
                        )
                        for group in ("FAIL_TO_PASS", "PASS_TO_PASS")
                    ),
                )
            )
        selected = chosen
    prepared, blocked = [], []
    for row in selected:
        try:
            value = prepare_one(row, output, adapter, grade_source)
            prepared.append(value)
            print(
                json.dumps(
                    {
                        "prepared": len(prepared),
                        "task_id": row["task_id"],
                        "repo": row["upstream_repo"],
                    }
                ),
                flush=True,
            )
        except (ValueError, OSError, UnicodeError) as error:
            blocked.append(
                {
                    "task_id": row["task_id"],
                    "repo": row["upstream_repo"],
                    "reason": str(error),
                }
            )
    raw = "".join(
        json.dumps(value, sort_keys=True) + "\n" for value in prepared
    ).encode()
    write(output, "candidates.jsonl", raw)
    result = {
        "schema": "python-smith-jobs-preparation-v1",
        "source_index_sha256": INDEX_SHA,
        "source_rows": len(selected),
        "prepared": len(prepared),
        "repo_counts": dict(Counter(x["upstream_repo"] for x in prepared)),
        "blocked": blocked,
        "candidate_index_sha256": sha(raw),
        "frozen_adapter_module_sha256": FROZEN,
        "local_module_sha256": {
            name: sha((HERE / name).read_bytes()) for name in ("prepare.py", "grade.py")
        },
        "runtime_qualified": False,
        "cloud_launch_ready": False,
        "paid_calls": 0,
        "remote_writes": 0,
    }
    write(output, "manifest.json", encode(result))
    return result


def configure_inputs(manifest_path, expected_sha256):
    global SOURCE_INDEX, SOURCE_RECEIPTS, INDEX_SHA, RECEIPTS_SHA
    manifest = json.loads(captured(Path(manifest_path), expected_sha256))
    if manifest["schema"] != "additional-python-frozen-source-v2":
        raise ValueError("Unsupported frozen source manifest")
    inputs = []
    for key in ("index_path", "receipts_path"):
        path = SOURCE / manifest[key]
        if not path.resolve().is_relative_to(SOURCE.resolve()):
            raise ValueError("Frozen source input escapes owned source root")
        inputs.append(path)
    SOURCE_INDEX, SOURCE_RECEIPTS = inputs
    INDEX_SHA, RECEIPTS_SHA = manifest["index_sha256"], manifest["receipts_sha256"]
    captured(SOURCE_INDEX, INDEX_SHA)
    captured(SOURCE_RECEIPTS, RECEIPTS_SHA)
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--source-manifest", required=True, type=Path)
    parser.add_argument("--expected-source-manifest-sha256", required=True)
    parser.add_argument("--pilot", action="store_true")
    args = parser.parse_args()
    configure_inputs(args.source_manifest, args.expected_source_manifest_sha256)
    print(json.dumps(prepare(args.output, args.pilot)))
