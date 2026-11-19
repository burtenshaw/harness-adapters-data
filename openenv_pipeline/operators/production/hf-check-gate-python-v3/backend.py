"""Private Git-patch transfer for the Python Jobs semantic profile.

Importing performs no IO. Workloads run only through dedicated HF Sandboxes.
The controller, Git binary and snapshotter are trusted; hostile root-code
isolation is not established by this adapter.
"""

import importlib.util
import json
import re
import shlex
import tempfile
import time
import uuid
from pathlib import Path

from examples.coding_audit.hf import (
    _deadline,
    HFBackendError,
    HFTaskBackend,
    submission_digest,
)
from huggingface_hub import Sandbox
from openenv.validation.runner import source_digest

HERE = Path(__file__).resolve().parent
ADAPTER_DIR = HERE


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


adapter = load("python_patch_adapter", ADAPTER_DIR / "adapter.py")
gate = load("python_jobs_gate", HERE / "gate.py")


def bootstrap(descriptor, gitdir):
    repo, base = descriptor["source_repo"], descriptor["source_base_commit"]
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo) or not re.fullmatch(
        r"[0-9a-f]{40}", base
    ):
        raise ValueError("Canonical repository and full base commit required")
    url = "https://github.com/" + repo + ".git"
    return "\n".join(
        [
            "set -Eeuo pipefail",
            "export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 GIT_NO_REPLACE_OBJECTS=1 GIT_TERMINAL_PROMPT=0 GIT_ATTR_NOSYSTEM=1",
            "unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE",
            "test ! -e /testbed/repo",
            "/usr/bin/git -c core.hooksPath=/dev/null init -q /testbed/repo",
            "cd /testbed/repo",
            "/usr/bin/git -c core.hooksPath=/dev/null -c core.fsmonitor=false fetch --quiet --depth=1 --no-tags "
            + shlex.quote(url)
            + " "
            + base,
            "/usr/bin/git -c core.hooksPath=/dev/null checkout --quiet --detach FETCH_HEAD",
            'test "$(/usr/bin/git rev-parse HEAD)" = ' + base,
            'test "$(/usr/bin/git rev-list --count --all HEAD)" = 1',
            # A task may edit/replace its own Git index. Keep an independently
            # checked base database for the controller's fresh snapshot index.
            "cp -R /testbed/repo/.git " + shlex.quote(gitdir),
        ]
    )


class Backend(HFTaskBackend):
    def __init__(
        self,
        task_root,
        execution,
        *,
        expected_task_digest,
        expected_seed_digest,
        expected_task_inventory_sha256,
        checkpoint=None,
        **kwargs,
    ):
        self.checkpoint = checkpoint or (lambda value: None)
        self._snapshot = tempfile.TemporaryDirectory(prefix="openenv-python-jobs-")
        root = Path(self._snapshot.name).resolve()
        try:
            inventory = gate._capture(Path(task_root), root)
            self.task_inventory_sha256 = adapter.sha(
                json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()
            )
            if (
                self.task_inventory_sha256 != expected_task_inventory_sha256
                or source_digest(root) != expected_task_digest
            ):
                raise ValueError("Approved full task bytes or modes changed")
            raw = (root / "adapter.json").read_bytes()
            if adapter.sha(raw) != expected_seed_digest:
                raise ValueError("Approved Python adapter descriptor changed")
            self.descriptor = json.loads(raw)
            self.collector = (ADAPTER_DIR / "collect.py").read_bytes()
            self.setup = (root / "dependency-setup.sh").read_bytes()
            self.restore_code = (HERE / "restore.py").read_bytes()
            if adapter.sha(self.restore_code) != execution.get("restore_helper_sha256"):
                raise ValueError("Approved fresh-grader restoration helper changed")
            if (
                adapter.sha(self.collector) != self.descriptor["collector_sha256"]
                or adapter.sha(self.setup) != self.descriptor["dependency_setup_sha256"]
            ):
                raise ValueError("Approved collector or dependency recipe changed")
            if (
                execution.get("submission_paths") != ["/testbed/submission.patch"]
                or execution.get("workdir") != "/testbed"
            ):
                raise ValueError("Python patch transfer has a fixed private boundary")
            if execution.get("agent_image") != execution.get("verifier_image"):
                raise ValueError(
                    "Solver and verifier must use the same immutable runtime"
                )
            factory = kwargs.pop("sandbox_factory", Sandbox.create)

            def create(*args, **spec):
                self.checkpoint(
                    {
                        "status": "creating_job",
                        "creation_label": spec["labels"]["openenv-coding-attempt"],
                        "image_ref": spec["image"],
                        "namespace": spec.get("namespace"),
                    }
                )
                sandbox = factory(*args, **spec)
                self.checkpoint(
                    {
                        "status": "created_job",
                        "sandbox_id": sandbox.id,
                        "image_ref": spec["image"],
                    }
                )
                return sandbox

            super().__init__(root, execution, sandbox_factory=create, **kwargs)
            self.expected_task_digest = expected_task_digest
            self.seed_sha256 = expected_seed_digest
            self.gitdir = "/tmp/openenv-base-" + uuid.uuid4().hex + ".git"
            self._grading_files = None
            self._dependency_lock = execution.get("dependency_lock_sha256")
        except BaseException:
            self._snapshot.cleanup()
            raise

    def close(self):
        self._snapshot.cleanup()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def _create(self, image, record, *, grader=False):
        sandbox = super()._create(image, record, grader=grader)
        if sandbox.files.list(self.workdir):
            raise HFBackendError("Python runtime must have an empty workdir")
        start = time.monotonic()
        deadline = start + self.timeout
        code, _ = super()._run(
            sandbox,
            ["/bin/bash", "-c", bootstrap(self.descriptor, self.gitdir)],
            deadline,
        )
        if code != 0:
            raise HFBackendError("Pinned base worktree bootstrap failed")
        sandbox.files.write("/tmp/openenv-dependency-setup.sh", self.setup, mode="700")
        code, _ = super()._run(
            sandbox, ["/bin/bash", "/tmp/openenv-dependency-setup.sh"], deadline
        )
        if code != 0:
            raise HFBackendError("Repository dependency setup failed")
        code, freeze = super()._run(
            sandbox,
            ["/opt/miniconda3/envs/testbed/bin/python", "-m", "pip", "freeze", "--all"],
            deadline,
        )
        if code != 0 or len(freeze.encode()) > 65536:
            raise HFBackendError("Repository dependency lock could not be measured")
        record.update(
            source_base_commit=self.descriptor["source_base_commit"],
            dependency_lock_sha256=adapter.sha(
                ("\n".join(sorted(freeze.splitlines())) + "\n").encode()
            ),
            dependency_installation_pinned=False,
            task_inventory_sha256=self.task_inventory_sha256,
        )
        if (
            self._dependency_lock is not None
            and self._dependency_lock != record["dependency_lock_sha256"]
        ):
            raise HFBackendError(
                "Repository dependency lock differs from the approved environment"
            )
        self._dependency_lock = record["dependency_lock_sha256"]
        self.checkpoint(
            {
                "status": "base_worktree_ready",
                "sandbox_id": sandbox.id,
                "image_ref": image,
                "source_base_commit": record["source_base_commit"],
                "dependency_lock_sha256": record["dependency_lock_sha256"],
            }
        )
        return sandbox

    def _collect(self, sandbox):
        sandbox.files.write("/tmp/openenv-collect.py", self.collector, mode="700")
        code, _ = super()._run(
            sandbox,
            [
                "/opt/miniconda3/bin/python",
                "-I",
                "/tmp/openenv-collect.py",
                "--workspace",
                "/testbed/repo",
                "--git-dir",
                self.gitdir,
                "--base",
                self.descriptor["source_base_commit"],
                "--output",
                "/testbed/submission.patch",
            ],
            time.monotonic() + self.timeout,
        )
        if code != 0:
            raise HFBackendError("Faithful repository patch collection failed")
        files = super()._collect(sandbox)
        if set(files) != {"/testbed/submission.patch"}:
            raise HFBackendError("Patch output is missing")
        adapter.validate_patch(files["/testbed/submission.patch"])
        return files

    def run_control(self, script, role):
        record = self._record()
        record.update(role=role, agent_exit_code=None)
        sandbox = None
        started = time.monotonic()
        try:
            with _deadline(self.timeout):
                if (
                    not isinstance(script, str)
                    or len(script.encode()) > self.max_script
                ):
                    raise HFBackendError("Control script byte limit exceeded")
                sandbox = self._create(self.execution["agent_image"], record)
                self._audit_solver(sandbox)
                code, output = self._run(
                    sandbox, ["/bin/bash", "-c", script], started + self.timeout
                )
                record["agent_exit_code"] = code
                record["transcript"].append(
                    {"role": role, "exit_code": code, "output": output}
                )
                record["files"] = self._collect(sandbox)
                record["submission_digest"] = submission_digest(record["files"])
        except Exception as exc:
            record["error"] = self._error(exc)
        finally:
            self._cleanup(record, sandbox)
            record["latency_seconds"] = time.monotonic() - started
        return self._redact(record)

    def grade(self, submission):
        self._grading_files = submission.get("files", {})
        try:
            if set(self._grading_files) != {"/testbed/submission.patch"}:
                raise HFBackendError("Invalid Python patch transfer")
            adapter.validate_patch(self._grading_files["/testbed/submission.patch"])
            return super().grade(submission)
        finally:
            self._grading_files = None

    def _run(self, sandbox, argv, end, **kwargs):
        if self._grading_files is not None and argv == self.execution.get(
            "verifier_command", ["/bin/bash", "/tests/test.sh"]
        ):
            patch = self._grading_files["/testbed/submission.patch"]
            new_files, current = [], None
            for line in patch.decode("utf-8").splitlines():
                if line.startswith("diff --git "):
                    current = adapter.header_path(line)
                elif line.startswith("new file mode "):
                    new_files.append(current)
            sandbox.files.write(
                "/tmp/openenv-restore.py", self.restore_code, mode="700"
            )
            code, _ = super()._run(
                sandbox,
                [
                    "/opt/miniconda3/bin/python",
                    "-I",
                    "/tmp/openenv-restore.py",
                    "--workspace",
                    "/testbed/repo",
                    "--base",
                    self.descriptor["source_base_commit"],
                    "--new-files-json",
                    json.dumps(new_files),
                ],
                end,
            )
            if code != 0:
                raise HFBackendError(
                    "Fresh grader BASE restoration or new-file collision validation failed"
                )
            if patch:
                code, _ = super()._run(
                    sandbox,
                    [
                        "/usr/bin/git",
                        "-c",
                        "safe.directory=/testbed/repo",
                        "-c",
                        "core.hooksPath=/dev/null",
                        "-c",
                        "core.fsmonitor=false",
                        "-c",
                        "core.autocrlf=false",
                        "apply",
                        "--index",
                        "--binary",
                        "--whitespace=nowarn",
                        "/testbed/submission.patch",
                    ],
                    end,
                    cwd="/testbed/repo",
                )
                if code != 0:
                    raise HFBackendError(
                        "Patch differs from the independently bootstrapped base"
                    )
        return super()._run(sandbox, argv, end, **kwargs)

    def _cleanup(self, record, sandbox):
        try:
            super()._cleanup(record, sandbox)
        finally:
            self.checkpoint(
                {
                    key: record.get(key)
                    for key in (
                        "sandbox_id",
                        "grade_sandbox_id",
                        "creation_label",
                        "cleanup_job_ids",
                        "cleanup_verified",
                        "error",
                        "dependency_lock_sha256",
                    )
                }
            )
