"""Offline tests for the Spaces-free Harbor containerization pipeline."""

import contextlib
import hashlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import containerize  # noqa: E402


def _load_module(name, path, extra_sys_path=None):
    added = False
    if extra_sys_path and str(extra_sys_path) not in sys.path:
        sys.path.append(str(extra_sys_path))
        added = True
    try:
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    finally:
        if added and str(extra_sys_path) in sys.path:
            sys.path.remove(str(extra_sys_path))


population = _load_module(
    "qwen_population_under_test", ROOT / "qwen_pipeline" / "population.py", ROOT / "qwen_pipeline"
)


class ContainerizeTest(unittest.TestCase):
    def _base_args(self, **overrides):
        defaults = dict(
            path=None,
            bootstrap_openenv_images=False,
            source_manifest=None,
            task=[],
            registry="ghcr.io/harness-hub/test-suite",
            builder="kaniko",
            output_dir=None,
            in_place=False,
            receipts=None,
            per_task_receipts_dir=None,
            extra_dockerfile=None,
            tag_prefix="",
            concurrency=2,
            namespace="harness-hub",
            flavor="cpu-basic",
            timeout="30m",
            kaniko_image="ghcr.io/osscontainertools/kaniko:debug",
            bucket="openenv-kaniko-builds",
            cache_repo=None,
            no_oci_append=False,
            rebuild_pinned=False,
            strip_dockerfile=False,
            no_verify_public=False,
            plan=True,
            verify_only=False,
            require_digest_pin=False,
            no_push=False,
            registry_user=None,
            registry_password=None,
            openenv_src=None,
            json_output=True,
        )
        defaults.update(overrides)
        return SimpleNamespace(**defaults)

    def test_plan_classifies_copy_only_run_shared_and_manifest_selection(self):
        with tempfile.TemporaryDirectory() as tmp_str:
            root = Path(tmp_str)
            tasks = root / "tasks"

            # 1. COPY-only Go task -> oci_append
            t_go = tasks / "go-task"
            (t_go / "environment/source").mkdir(parents=True)
            (t_go / "task.toml").write_text(
                'version = "1.0"\n[environment]\ncpus = 1\n', encoding="utf-8"
            )
            (t_go / "instruction.md").write_text("Fix bug.\n", encoding="utf-8")
            (t_go / "environment/Dockerfile").write_text(
                "FROM ghcr.io/harness-hub/go-base:v1\nWORKDIR /testbed\nCOPY source/ /testbed/\n",
                encoding="utf-8",
            )
            (t_go / "environment/source/main.go").write_text("package main\n", encoding="utf-8")

            # 2. RUN Python task -> build
            t_py = tasks / "py-task"
            (t_py / "environment").mkdir(parents=True)
            (t_py / "task.toml").write_text(
                'version = "1.0"\n[environment]\ncpus = 1\n', encoding="utf-8"
            )
            (t_py / "instruction.md").write_text("Fix py bug.\n", encoding="utf-8")
            (t_py / "environment/Dockerfile").write_text(
                "FROM python:3.12-slim\nRUN pip install pytest\n", encoding="utf-8"
            )

            # 3. Shared-image task (no Dockerfile, pinned docker_image) -> keep_pinned
            t_shared = tasks / "shared-task"
            (t_shared / "environment/inputs").mkdir(parents=True)
            (t_shared / "task.toml").write_text(
                'version = "1.0"\n[environment]\n'
                f'docker_image = "ghcr.io/harness-hub/office@sha256:{"a" * 64}"\n',
                encoding="utf-8",
            )
            (t_shared / "instruction.md").write_text("Analyze file.\n", encoding="utf-8")
            (t_shared / "environment/inputs/a.txt").write_text("hello\n", encoding="utf-8")

            with contextlib.redirect_stdout(io.StringIO()):
                payload = containerize.execute(self._base_args(path=root))
            self.assertEqual(payload["total_tasks"], 3)
            self.assertEqual(payload["actions"]["oci_append"], 1)
            self.assertEqual(payload["actions"]["build"], 1)
            self.assertEqual(payload["actions"]["keep_pinned"], 1)

            # Manifest selection (Tasksmith verified.jsonl format): skips unverified rows
            manifest = root / "verified.jsonl"
            manifest.write_text(
                json.dumps({"task_id": "py-task", "tasksmith_verified": True}) + "\n"
                + json.dumps({"task_id": "go-task", "tasksmith_verified": False}) + "\n",
                encoding="utf-8",
            )
            with contextlib.redirect_stdout(io.StringIO()):
                filtered = containerize.execute(
                    self._base_args(path=root, source_manifest=manifest)
                )
            self.assertEqual(filtered["total_tasks"], 1)
            self.assertEqual(filtered["tasks"][0]["task_id"], "py-task")

    def test_tasksmith_build_oci_batches_parallel_and_records_extra_dockerfile(self):
        ts_dir = ROOT / "tasksmith_final"
        sys.path.insert(0, str(ts_dir))
        try:
            import adapt as ts_adapt
            import images as ts_images
            import smoke as ts_smoke
        finally:
            sys.path.remove(str(ts_dir))

        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            t1, _ = ts_smoke.starter(tmp / "src", "tasksmith-000000000001")
            t2, _ = ts_smoke.starter(tmp / "src", "tasksmith-000000000002")
            extra = tmp / "pi.Dockerfile"
            extra.write_text("RUN echo install-pi\n", encoding="utf-8")
            receipts_dir = tmp / "receipts"
            digest = "sha256:" + "f" * 64
            seen_calls = []

            class FakeImagesModule:
                def build_harbor_images(self, root, **kwargs):
                    seen_calls.append((Path(root), kwargs))
                    return {
                        "tasks": {
                            tid: {
                                "status": "resolved",
                                "builder": "kaniko",
                                "image": f"ghcr.io/harness-hub/tasksmith@{digest}",
                                "registry_digest": digest,
                                "tag": tid,
                                "config": {"os": "linux", "architecture": "amd64"},
                                "public_pull_verified": True,
                                "env_hash": "e" * 64,
                                "job_id": f"job-{tid}",
                            }
                            for tid in kwargs["task_ids"]
                        }
                    }

            with patch.object(ts_images, "_load_openenv_images", return_value=FakeImagesModule()):
                built = ts_images.build_oci(
                    [t1, t2],
                    receipts_dir,
                    registry="ghcr.io/harness-hub/tasksmith",
                    builder="kaniko",
                    namespace="harness-hub",
                    concurrency=8,
                    extra_dockerfile=extra,
                )

            # Both tasks share one parent dir -> dispatched in ONE parallel batch!
            self.assertEqual(len(seen_calls), 1)
            self.assertEqual(seen_calls[0][1]["concurrency"], 8)
            self.assertEqual(
                sorted(seen_calls[0][1]["task_ids"]),
                ["tasksmith-000000000001", "tasksmith-000000000002"],
            )
            self.assertEqual(len(built), 2)
            expected_extra_sha = hashlib.sha256(extra.read_bytes()).hexdigest()
            self.assertEqual(
                built["tasksmith-000000000001"]["extra_dockerfile_sha256"],
                expected_extra_sha,
            )

            # adapt.modify accepts the OCI receipt and preserves extra_dockerfile_sha256
            prov = ts_adapt.modify(
                t1,
                built["tasksmith-000000000001"],
                tmp / "adapted",
                "tasks/tasksmith-000000000001",
                "a" * 40,
            )
            self.assertEqual(prov["image_builder"], "kaniko")
            self.assertEqual(prov["extra_dockerfile_sha256"], expected_extra_sha)

    def test_qwen_population_accepts_oci_and_legacy_space_receipts(self):
        digest = "sha256:" + "d" * 64
        oci_receipt = {
            "status": "resolved",
            "builder": "kaniko",
            "image": f"ghcr.io/harness-hub/scale800@{digest}",
            "registry_digest": digest,
        }
        parsed_oci = population.image_identity(oci_receipt)
        self.assertEqual(parsed_oci["image"], oci_receipt["image"])
        self.assertIn("space_id", parsed_oci["omitted_fields"])

        space_receipt = {
            "image": f"registry.hf.space/harness-hub-test@{digest}",
            "space_id": "harness-hub/test",
            "space_commit": "e" * 40,
        }
        parsed_space = population.image_identity(space_receipt)
        self.assertEqual(parsed_space["space_id"], "harness-hub/test")

        # Incomplete OCI receipt without matching registry_digest is rejected.
        with self.assertRaises(ValueError):
            population.image_identity({"image": f"ghcr.io/harness-hub/x@{digest}"})


if __name__ == "__main__":
    unittest.main()
