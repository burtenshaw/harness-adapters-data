"""Source-seeded control trials using the merged, dedicated HF Sandbox adapter.

No model calls. Every control and its private verifier use separate fresh Jobs.
Only the complete approved public source surface is seeded into the empty runtime.
"""

import base64
import hashlib
import importlib.util
import json
import tempfile
import time
from pathlib import Path, PurePosixPath

from examples.coding_audit.hf import (
    _deadline,
    _local_file,
    HFBackendError,
    HFTaskBackend,
    submission_digest,
)
from huggingface_hub import Sandbox
from openenv.validation.runner import source_digest


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def seed_inventory(files):
    return {
        name: {"sha256": sha(raw), "mode": oct(mode), "size": len(raw)}
        for name, (raw, mode) in sorted(files.items())
    }


def seed_digest(files):
    return sha(
        json.dumps(
            seed_inventory(files), sort_keys=True, separators=(",", ":")
        ).encode()
    )


class Backend(HFTaskBackend):
    def __init__(
        self,
        task_root,
        execution,
        *,
        expected_task_digest,
        expected_seed_digest,
        expected_task_inventory_sha256=None,
        checkpoint=None,
        **kwargs,
    ):
        self.checkpoint = checkpoint or (lambda value: None)
        self._snapshot = tempfile.TemporaryDirectory(prefix="openenv-jobs-task-")
        snapshot_root = Path(self._snapshot.name).resolve()
        spec = importlib.util.spec_from_file_location(
            "jobs_gate_snapshot", Path(__file__).with_name("gate.py")
        )
        gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gate)
        try:
            inventory = gate._capture(Path(task_root), snapshot_root)
            self.task_inventory_sha256 = sha(
                json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()
            )
            if (
                expected_task_inventory_sha256 is not None
                and self.task_inventory_sha256 != expected_task_inventory_sha256
            ):
                raise ValueError(
                    "Captured task inventory or modes differ from approved source"
                )
            if source_digest(snapshot_root) != expected_task_digest:
                raise ValueError("Captured task differs from approved source digest")
        except BaseException:
            self._snapshot.cleanup()
            raise
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

        super().__init__(snapshot_root, execution, sandbox_factory=create, **kwargs)
        self._grading_files = None
        self.expected_task_digest = expected_task_digest
        if source_digest(self.task_root) != expected_task_digest:
            raise ValueError("Task changed before source capture")
        root = self.task_root / "environment/source"
        files = {}
        remaining = self.max_bytes
        for path in sorted(root.rglob("*")):
            if path.is_symlink():
                raise ValueError("Public seed links are unsupported")
            if path.is_dir():
                continue
            rel = path.relative_to(root).as_posix()
            parts = PurePosixPath(rel).parts
            if any(
                p
                in {
                    ".git",
                    "tests",
                    "test",
                    "testdata",
                    "fixtures",
                    "solution",
                    "validation",
                }
                or p.lower().startswith(".env")
                for p in parts
            ) or rel.endswith("_test.go"):
                raise ValueError("Private paths are not public seed inputs")
            raw, mode = _local_file(path, remaining)
            mode = int(mode, 8)
            remaining -= len(raw)
            if mode not in {0o644, 0o755}:
                raise ValueError("Unsupported public seed mode")
            if any(
                v.encode() in raw or base64.b64encode(v.encode()) in raw
                for v in self._credentials
            ):
                raise ValueError("Credential in public seed")
            files[rel] = (raw, mode)
        if (
            not files
            or seed_digest(files) != expected_seed_digest
            or source_digest(self.task_root) != expected_task_digest
        ):
            raise ValueError("Approved public seed bytes or task identity changed")
        if set(self.submission_paths) != {
            str(PurePosixPath(self.workdir) / p) for p in files
        }:
            raise ValueError("Transfer surface must cover every public seed file")
        self.public_files = files
        self.seed_sha256 = expected_seed_digest

    def close(self):
        self._snapshot.cleanup()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def _collect(self, sandbox):
        files = super()._collect(sandbox)
        for path in files:
            relative = PurePosixPath(path).relative_to(self.workdir).as_posix()
            if (
                int(sandbox.files.stat(path).mode, 8) & 0o777
                != self.public_files[relative][1]
            ):
                raise HFBackendError(
                    "Submitted mode changes are unsupported by this file adapter"
                )
        return files

    def grade(self, submission):
        self._grading_files = submission.get("files", {})
        try:
            return super().grade(submission)
        finally:
            self._grading_files = None

    def _run(self, sandbox, argv, end, **kwargs):
        if self._grading_files is not None:
            for name, (_, mode) in self.public_files.items():
                path = str(PurePosixPath(self.workdir) / name)
                if mode != 0o644 and path in self._grading_files:
                    sandbox.files.write(
                        path, self._grading_files[path], mode=f"{mode:o}"
                    )
        return super()._run(sandbox, argv, end, **kwargs)

    def _create(self, image, record, *, grader=False):
        sandbox = super()._create(image, record, grader=grader)
        if sandbox.files.list(self.workdir):
            raise HFBackendError("Shared runtime workdir must initially be empty")
        for name, (raw, mode) in self.public_files.items():
            path = str(PurePosixPath(self.workdir) / name)
            sandbox.files.mkdir(str(PurePosixPath(path).parent))
            sandbox.files.write(path, raw, mode=f"{mode:o}")
            entry = sandbox.files.stat(path)
            if (
                entry.type != "file"
                or entry.size != len(raw)
                or int(entry.mode, 8) & 0o777 != mode
                or sandbox.files.read(path) != raw
            ):
                raise HFBackendError("Initial public source seed verification failed")
        record["public_seed_sha256"] = self.seed_sha256
        self.checkpoint(
            {
                "status": "public_source_seeded",
                "sandbox_id": sandbox.id,
                "image_ref": image,
                "public_seed_sha256": self.seed_sha256,
                "grader": grader,
            }
        )
        return sandbox

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
                    raise HFBackendError("Control script exceeds byte limit")
                sandbox = self._create(self.execution["agent_image"], record)
                self._audit_solver(sandbox)
                code, output = self._run(
                    sandbox, ["/bin/bash", "-c", script], started + self.timeout
                )
                record["agent_exit_code"] = code
                record["transcript"].append(
                    {"role": role, "exit_code": code, "output": output}
                )
                # A real nonzero oracle exit is semantic evidence, not a reason
                # to discard its actual files or skip the independent verifier.
                record["files"] = self._collect(sandbox)
                record["submission_digest"] = submission_digest(record["files"])
        except Exception as exc:
            record["error"] = self._error(exc)
        finally:
            self._cleanup(record, sandbox)
            record["latency_seconds"] = time.monotonic() - started
        return self._redact(record)

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
                        "public_seed_sha256",
                    )
                }
            )
