"""Offline unit tests for openenv_pipeline/migrate_datasets_ghcr.py."""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any

HERE = Path(__file__).resolve().parent


def _load_migrate_module():
    mod_name = "_test_openenv_migrate_datasets_ghcr"
    existing = sys.modules.get(mod_name)
    if existing is not None:
        return existing
    spec = importlib.util.spec_from_file_location(
        mod_name, HERE / "migrate_datasets_ghcr.py"
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


M = _load_migrate_module()

OLD_OFFICE = (
    "registry.hf.space/harness-hub-apex-office-tools-env"
    "@sha256:" + "1" * 64
)
NEW_OFFICE = (
    "ghcr.io/burtenshaw/harness-adapters"
    "@sha256:" + "a" * 64
)
OLD_SSBV = (
    "registry.hf.space/harness-hub-spreadsheetbench-verified-env"
    "@sha256:" + "2" * 64
)
NEW_SSBV = (
    "ghcr.io/burtenshaw/harness-adapters"
    "@sha256:" + "b" * 64
)
OLD_GDPVAL = (
    "registry.hf.space/harness-hub-gdpval-env"
    "@sha256:" + "3" * 64
)
NEW_GDPVAL = (
    "ghcr.io/burtenshaw/harness-adapters"
    "@sha256:" + "c" * 64
)
OLD_JOBBENCH = (
    "registry.hf.space/harness-hub-jobbench-env"
    "@sha256:" + "4" * 64
)
NEW_JOBBENCH = (
    "ghcr.io/burtenshaw/harness-adapters"
    "@sha256:" + "d" * 64
)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class FakeOCIClientFactory:
    """Mock openenv.harbor.images module exposing OCIRegistryClient."""

    def __init__(self, responses: dict[str, Any]):
        self.responses = responses
        self.calls: list[tuple[bool, str]] = []

    @property
    def OCIRegistryClient(self):
        factory = self

        class _Client:
            def __init__(self, *, anonymous: bool = False):
                self.anonymous = anonymous

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def resolve_linux_amd64(self, image: str):
                factory.calls.append((self.anonymous, image))
                entry = factory.responses.get(image)
                if entry is None:
                    raise RuntimeError(f"401 Unauthorized (private package): {image}")
                if isinstance(entry, Exception):
                    raise entry
                return entry, {}, {}

        return _Client


def _ok_resolved(image_ref: str, *, os_name: str = "linux", arch: str = "amd64", public: bool = True):
    digest = image_ref.split("@", 1)[1]
    cfg_digest = "sha256:" + hashlib.sha256(image_ref.encode()).hexdigest()
    return SimpleNamespace(
        image=image_ref,
        registry_digest=digest,
        index_digest=None,
        config={
            "digest": cfg_digest,
            "sha256": cfg_digest.split(":", 1)[1],
            "os": os_name,
            "architecture": arch,
        },
        public_pull_verified=public,
        tag=None,
    )


class InMemoryHfApi:
    """In-memory mock of huggingface_hub.HfApi for offline Hub migration tests."""

    def __init__(
        self,
        repos: dict[str, dict[str, bytes]],
        *,
        private_repos: set[str] | None = None,
        corrupt_on_commit: dict[str, bytes] | None = None,
    ):
        self.private_repos = private_repos or set()
        self.corrupt_on_commit = corrupt_on_commit or {}
        self.history: dict[str, dict[str, dict[str, bytes]]] = {}
        self.head: dict[str, str] = {}
        self.commits: list[dict[str, object]] = []
        for repo_id, files in repos.items():
            init_sha = hashlib.sha1(f"init:{repo_id}".encode()).hexdigest()
            self.history[repo_id] = {init_sha: dict(files)}
            self.head[repo_id] = init_sha

    def dataset_info(self, repo_id: str, revision: str | None = None):
        if repo_id not in self.head:
            raise FileNotFoundError(f"Unknown dataset: {repo_id}")
        sha = self.head[repo_id] if revision in (None, "main") else revision
        if sha not in self.history[repo_id]:
            raise FileNotFoundError(f"Unknown revision {sha} for {repo_id}")
        return SimpleNamespace(
            id=repo_id,
            sha=sha,
            private=repo_id in self.private_repos,
        )

    def _snapshot(self, repo_id: str, revision: str | None) -> dict[str, bytes]:
        sha = self.head[repo_id] if revision in (None, "main") else revision
        return self.history[repo_id][sha]

    def list_repo_files(
        self, repo_id: str, *, repo_type: str = "dataset", revision: str | None = None
    ) -> list[str]:
        assert repo_type == "dataset"
        return sorted(self._snapshot(repo_id, revision).keys())

    def hf_hub_download(
        self,
        repo_id: str,
        filename: str,
        *,
        repo_type: str = "dataset",
        revision: str | None = None,
    ) -> bytes:
        assert repo_type == "dataset"
        snap = self._snapshot(repo_id, revision)
        if filename not in snap:
            raise FileNotFoundError(f"{repo_id}@{revision}:{filename}")
        return snap[filename]

    def create_commit(
        self,
        *,
        repo_id: str,
        repo_type: str,
        operations,
        commit_message: str,
        parent_commit: str | None = None,
    ):
        assert repo_type == "dataset"
        current_head = self.head[repo_id]
        if parent_commit is not None and parent_commit != current_head:
            raise RuntimeError(
                f"Parent commit mismatch: {parent_commit} != {current_head}"
            )
        new_files = dict(self.history[repo_id][current_head])
        op_paths = []
        for op in operations:
            data = op.path_or_fileobj
            if isinstance(data, (str, Path)):
                data = Path(data).read_bytes()
            elif hasattr(data, "read"):
                data = data.read()
            new_files[op.path_in_repo] = bytes(data)
            op_paths.append(op.path_in_repo)

        for path, bad_bytes in self.corrupt_on_commit.items():
            if path in new_files:
                new_files[path] = bad_bytes

        new_sha = hashlib.sha1(
            f"commit:{repo_id}:{len(self.commits)}:{current_head}".encode()
        ).hexdigest()
        self.history[repo_id][new_sha] = new_files
        self.head[repo_id] = new_sha
        self.commits.append(
            {
                "repo_id": repo_id,
                "parent_commit": parent_commit,
                "oid": new_sha,
                "commit_message": commit_message,
                "paths": sorted(op_paths),
            }
        )
        return SimpleNamespace(oid=new_sha)


def _make_hub_repo_fixture() -> dict[str, bytes]:
    """Create an in-memory Harbor dataset mirroring harness-hub/automation-adapter-envs."""
    t1_toml = (
        'schema_version = "1.3"\n\n'
        "[task]\n"
        'name = "apex-gap/task-alpha"\n\n'
        "[environment]\n"
        f'docker_image = "{OLD_OFFICE}"  # pinned learner image\n'
        'workdir = "/workspace"\n'
        "cpus = 1\n"
    ).encode("utf-8")
    t1_inst = b"Reconcile accounts.\n"
    t1_test = b"#!/bin/sh\necho ok\n"

    t2_toml = (
        'schema_version = "1.3"\n\n'
        "[task]\n"
        'name = "apex-gap/task-beta"\n\n'
        "[environment]\n"
        f"docker_image = '{OLD_OFFICE}'\n"
        "cpus = 2\n"
    ).encode("utf-8")
    t2_inst = b"Review merger filing.\n"

    t3_img = "ghcr.io/burtenshaw/already-migrated@sha256:" + "e" * 64
    t3_toml = (
        'schema_version = "1.3"\n\n'
        "[task]\n"
        'name = "apex-gap/task-gamma"\n\n'
        "[environment]\n"
        f'docker_image = "{t3_img}"\n'
    ).encode("utf-8")
    t3_inst = b"Already migrated.\n"

    t1_tree = M.compute_tree_sha256(
        {
            "task.toml": _sha(t1_toml),
            "instruction.md": _sha(t1_inst),
            "tests/test.sh": _sha(t1_test),
        }
    )
    t2_tree = M.compute_tree_sha256(
        {
            "task.toml": _sha(t2_toml),
            "instruction.md": _sha(t2_inst),
        }
    )
    t3_tree = M.compute_tree_sha256(
        {
            "task.toml": _sha(t3_toml),
            "instruction.md": _sha(t3_inst),
        }
    )

    split_rows = [
        {
            "task_id": "task-alpha",
            "task_path": "tasks/task-alpha",
            "instruction": "Reconcile accounts — Q4.",
            "docker_image": OLD_OFFICE,
            "tree_sha256": t1_tree,
        },
        {
            "task_id": "task-beta",
            "task_path": "tasks/task-beta",
            "instruction": "Review merger filing.",
            "docker_image": OLD_OFFICE,
            "tree_sha256": t2_tree,
        },
        {
            "task_id": "task-gamma",
            "task_path": "tasks/task-gamma",
            "instruction": "Already migrated.",
            "docker_image": t3_img,
            "tree_sha256": t3_tree,
        },
    ]
    split_bytes = (
        "\n".join(json.dumps(r, ensure_ascii=False) for r in split_rows) + "\n"
    ).encode("utf-8")

    licenses_bytes = b"Mixed licenses.\n"
    readme_bytes = (
        "# Automation adapter environments\n\n"
        "Every task runs in a public image under `registry.hf.space/harness-hub-…`, "
        "pinned by digest in `task.toml`.\n"
        f"Historical pin: `{OLD_OFFICE}`.\n"
    ).encode("utf-8")

    # Deliberately non-ASCII-sorted order matching real automation-adapter-envs SHA256SUMS
    sha256sums_entries = [
        ("LICENSES.md", licenses_bytes),
        ("splits/train.jsonl", split_bytes),
        ("tasks/task-alpha/instruction.md", t1_inst),
        ("tasks/task-alpha/task.toml", t1_toml),
        ("tasks/task-alpha/tests/test.sh", t1_test),
        ("tasks/task-beta/instruction.md", t2_inst),
        ("tasks/task-beta/task.toml", t2_toml),
        ("tasks/task-gamma/instruction.md", t3_inst),
        ("tasks/task-gamma/task.toml", t3_toml),
    ]
    sha256sums_bytes = (
        "\n".join(f"{_sha(data)}  {path}" for path, data in sha256sums_entries) + "\n"
    ).encode("utf-8")

    files = {path: data for path, data in sha256sums_entries}
    files["README.md"] = readme_bytes
    files["SHA256SUMS"] = sha256sums_bytes
    return files


def _make_local_repo_fixture(root: Path) -> dict[str, str]:
    """Populate a temp directory matching all 7 local migration targets + GHCR receipts."""
    receipts_dir = root / "knowledge/image/receipts"
    ghcr_dir = receipts_dir / "ghcr"
    bench_dir = root / "knowledge/broad_eval/benchmarks"
    ghcr_dir.mkdir(parents=True)
    bench_dir.mkdir(parents=True)

    (receipts_dir / "apex-office-tools.json").write_text(
        json.dumps(
            {
                "task_id": "apex-office-tools",
                "space_id": "harness-hub/apex-office-tools-env",
                "space_commit": "0" * 40,
                "context_files": {"Dockerfile": "f" * 64},
                "status": "resolved",
                "image": OLD_OFFICE,
                "registry_digest": "sha256:" + "1" * 64,
            },
            indent=1,
        )
        + "\n",
        encoding="utf-8",
    )
    (receipts_dir / "spreadsheetbench-verified.json").write_text(
        json.dumps(
            {
                "task_id": "spreadsheetbench-verified",
                "space_id": "harness-hub/spreadsheetbench-verified-env",
                "space_commit": "1" * 40,
                "context_files": {"Dockerfile": "e" * 64},
                "status": "resolved",
                "image": OLD_SSBV,
                "registry_digest": "sha256:" + "2" * 64,
            },
            indent=1,
        )
        + "\n",
        encoding="utf-8",
    )

    # GHCR receipts written by build pipeline
    for name, new_ref, df_sha in [
        ("apex-office-tools", NEW_OFFICE, "f" * 64),
        ("spreadsheetbench-verified", NEW_SSBV, "cf2d9e96" + "0" * 56),
        ("gdpval", NEW_GDPVAL, "5ddd7940" + "0" * 56),
        ("jobbench", NEW_JOBBENCH, "f543b685" + "0" * 56),
    ]:
        digest = new_ref.split("@", 1)[1]
        (ghcr_dir / f"{name}.json").write_text(
            json.dumps(
                {
                    "task_id": name,
                    "status": "resolved",
                    "builder": "kaniko",
                    "image": new_ref,
                    "registry": "ghcr.io/burtenshaw/harness-adapters",
                    "registry_digest": digest,
                    "tag": name,
                    "config": {
                        "digest": "sha256:" + hashlib.sha256(name.encode()).hexdigest(),
                        "sha256": hashlib.sha256(name.encode()).hexdigest(),
                        "os": "linux",
                        "architecture": "amd64",
                    },
                    "public_pull_verified": True,
                    "dockerfile_sha256": df_sha,
                    "contents": "environment/Dockerfile only (OCI registry, no Space)",
                },
                indent=1,
            )
            + "\n",
            encoding="utf-8",
        )

    mappings = {
        OLD_OFFICE: NEW_OFFICE,
        OLD_SSBV: NEW_SSBV,
        OLD_GDPVAL: NEW_GDPVAL,
        OLD_JOBBENCH: NEW_JOBBENCH,
    }
    (ghcr_dir / "manifest.json").write_text(
        json.dumps({"mappings": mappings}, indent=2) + "\n",
        encoding="utf-8",
    )

    (root / "knowledge/automation_grade_job.py").write_text(
        'REPO = "burtenshaw/t5-automation-work"\n'
        f'IMAGE = "{OLD_OFFICE}"\n',
        encoding="utf-8",
    )
    (root / "knowledge/automation_canary_job.py").write_text(
        'REPO = "burtenshaw/t5-automation-work"\n'
        f'IMAGE = "{OLD_OFFICE}"\n'
        'FILES = ["knowledge/automation_canary.py"]\n',
        encoding="utf-8",
    )
    (bench_dir / "gdpval.py").write_text(
        f'IMAGE = "{OLD_GDPVAL}"\n'
        "IMAGE_RECEIPT = {\n"
        '    "space_id": "harness-hub/gdpval-env",\n'
        '    "space_commit": "07b8ca661162c9e32b16079ad861f2de58a3bfb5",\n'
        f'    "dockerfile_sha256": "{"5ddd7940" + "0" * 56}",\n'
        '    "config_digest": "sha256:' + "9" * 64 + '",\n'
        '    "platform": "linux/amd64",\n'
        "}\n",
        encoding="utf-8",
    )
    (bench_dir / "jobbench.py").write_text(
        f'IMAGE = "{OLD_JOBBENCH}"\n'
        "IMAGE_RECEIPT = {\n"
        '    "space_id": "harness-hub/jobbench-env",\n'
        '    "space_commit": "cfe83ec25f9dc1edcc88a1045593ed46efb75d8c",\n'
        f'    "dockerfile_sha256": "{"f543b685" + "0" * 56}",\n'
        '    "config_digest": "sha256:' + "8" * 64 + '",\n'
        '    "platform": "linux/amd64",\n'
        "}\n",
        encoding="utf-8",
    )
    # Multi-line parenthesized IMAGE literal matching real spreadsheetbench.py
    ssbv_repo, ssbv_digest = OLD_SSBV.split("@", 1)
    (bench_dir / "spreadsheetbench.py").write_text(
        f'IMAGE = ("{ssbv_repo}"\n'
        f'         "@{ssbv_digest}")\n'
        "IMAGE_PROVENANCE = {\n"
        '    "space_id": "harness-hub/spreadsheetbench-verified-env",\n'
        '    "space_commit": "71accf1a7af334d2b66c3fbf1c410c01a583bb68",\n'
        f'    "dockerfile_sha256": "{"cf2d9e96" + "0" * 56}",\n'
        '    "config_digest": "sha256:' + "7" * 64 + '",\n'
        '    "platform": "linux/amd64",\n'
        "}\n"
        'TASKS_SHA256 = "904281c789981ddda636e7953edda07c1b8533b0f11d34ba04f94d61f0ad2187"\n',
        encoding="utf-8",
    )
    return mappings


class MigrateDatasetsGhcrTest(unittest.TestCase):
    def test_safety_gate_rejects_private_or_unpullable_targets_before_any_write(self):
        # 1. Hub apply blocked before any commit when target is private (401)
        api = InMemoryHfApi({"harness-hub/automation-adapter-envs": _make_hub_repo_fixture()})
        private_oci = FakeOCIClientFactory({})  # returns 401 Unauthorized
        with self.assertRaises(M.PublicImageVerificationError):
            M.migrate_hub_dataset(
                "harness-hub/automation-adapter-envs",
                {OLD_OFFICE: NEW_OFFICE},
                apply=True,
                api=api,
                images_module=private_oci,
            )
        self.assertEqual(len(api.commits), 0)
        self.assertEqual(private_oci.calls, [(True, NEW_OFFICE)])

        # 2. Wrong architecture (linux/arm64) rejected
        arm_oci = FakeOCIClientFactory(
            {NEW_OFFICE: _ok_resolved(NEW_OFFICE, os_name="linux", arch="arm64")}
        )
        with self.assertRaises(M.PublicImageVerificationError):
            M.verify_public_targets([NEW_OFFICE], images_module=arm_oci)

        # 3. Local apply blocked before modifying ANY file on disk
        with tempfile.TemporaryDirectory() as tmp_str:
            root = Path(tmp_str)
            mappings = _make_local_repo_fixture(root)
            before_grade = (root / "knowledge/automation_grade_job.py").read_text(
                encoding="utf-8"
            )
            before_receipt = (
                root / "knowledge/image/receipts/apex-office-tools.json"
            ).read_text(encoding="utf-8")
            partial_oci = FakeOCIClientFactory(
                {
                    NEW_OFFICE: _ok_resolved(NEW_OFFICE),
                    # NEW_SSBV, NEW_GDPVAL, NEW_JOBBENCH missing -> fail gate
                }
            )
            with self.assertRaises(M.PublicImageVerificationError):
                M.migrate_local_repo(
                    mappings,
                    repo_root=root,
                    apply=True,
                    images_module=partial_oci,
                )
            self.assertEqual(
                (root / "knowledge/automation_grade_job.py").read_text(encoding="utf-8"),
                before_grade,
            )
            self.assertEqual(
                (root / "knowledge/image/receipts/apex-office-tools.json").read_text(
                    encoding="utf-8"
                ),
                before_receipt,
            )

    def test_load_mappings_validation(self):
        with tempfile.TemporaryDirectory() as tmp_str:
            mf = Path(tmp_str) / "manifest.json"
            mf.write_text(
                json.dumps({"mappings": {OLD_OFFICE: NEW_OFFICE}}),
                encoding="utf-8",
            )
            loaded = M.load_mappings(mf, [f"{OLD_SSBV}={NEW_SSBV}"])
            self.assertEqual(
                loaded, {OLD_OFFICE: NEW_OFFICE, OLD_SSBV: NEW_SSBV}
            )

        with self.assertRaises(ValueError):
            M.load_mappings(None, [f"{OLD_OFFICE}=ghcr.io/burtenshaw/unpinned:latest"])
        with self.assertRaises(ValueError):
            M.load_mappings(
                None,
                [f"{OLD_OFFICE}=registry.hf.space/other@sha256:{'a' * 64}"],
            )

    def test_hub_migration_dry_run_atomic_apply_and_idempotent_rerun(self):
        repo_id = "harness-hub/automation-adapter-envs"
        api = InMemoryHfApi({repo_id: _make_hub_repo_fixture()})
        initial_head = api.head[repo_id]
        oci = FakeOCIClientFactory({NEW_OFFICE: _ok_resolved(NEW_OFFICE)})
        mappings = {OLD_OFFICE: NEW_OFFICE}

        # 1. Dry-run produces exact plan and makes 0 commits
        dry = M.migrate_hub_dataset(
            repo_id, mappings, apply=False, api=api, images_module=oci
        )
        self.assertEqual(dry["mode"], "dry-run")
        self.assertEqual(dry["head_sha"], initial_head)
        self.assertTrue(dry["public_verification"]["verified"])
        self.assertEqual(dry["counts"]["task_tomls_scanned"], 3)
        self.assertEqual(dry["counts"]["task_tomls_updated"], 2)
        self.assertEqual(dry["counts"]["splits_updated"], 1)
        self.assertEqual(dry["counts"]["split_rows_updated"], 2)
        self.assertTrue(dry["counts"]["readme_updated"])
        self.assertTrue(dry["counts"]["sha256sums_updated"])
        self.assertEqual(dry["counts"]["sha256sums_entries_updated"], 3)
        self.assertEqual(dry["counts"]["total_files_to_commit"], 5)
        self.assertEqual(len(api.commits), 0)

        # 2. Apply submits ONE atomic commit with parent_commit == initial_head + readback OK
        applied = M.migrate_hub_dataset(
            repo_id, mappings, apply=True, api=api, images_module=oci
        )
        self.assertEqual(applied["status"], "committed")
        self.assertEqual(applied["committed_files"], 5)
        self.assertTrue(applied["readback"]["ok"])
        self.assertEqual(applied["readback"]["files_verified"], 5)
        self.assertEqual(len(api.commits), 1)
        self.assertEqual(api.commits[0]["parent_commit"], initial_head)
        self.assertEqual(
            api.commits[0]["paths"],
            [
                "README.md",
                "SHA256SUMS",
                "splits/train.jsonl",
                "tasks/task-alpha/task.toml",
                "tasks/task-beta/task.toml",
            ],
        )

        # Verify updated repo invariants at new HEAD
        new_head = applied["commit_oid"]
        snap = api.history[repo_id][new_head]

        # task.toml parsed cleanly, comments preserved, untouched task preserved
        alpha_text = snap["tasks/task-alpha/task.toml"].decode("utf-8")
        self.assertIn("# pinned learner image", alpha_text)
        self.assertEqual(
            tomllib.loads(alpha_text)["environment"]["docker_image"], NEW_OFFICE
        )
        beta_text = snap["tasks/task-beta/task.toml"].decode("utf-8")
        self.assertEqual(
            tomllib.loads(beta_text)["environment"]["docker_image"], NEW_OFFICE
        )
        self.assertEqual(
            snap["tasks/task-gamma/task.toml"],
            api.history[repo_id][initial_head]["tasks/task-gamma/task.toml"],
        )

        # README updated cleanly (both exact ref and prose prefix)
        readme = snap["README.md"].decode("utf-8")
        self.assertNotIn("registry.hf.space", readme)
        self.assertIn(NEW_OFFICE, readme)
        self.assertIn("ghcr.io/burtenshaw/harness-adapters", readme)

        # splits/train.jsonl updated docker_image AND recomputed tree_sha256, preserved unicode
        split_text = snap["splits/train.jsonl"].decode("utf-8")
        self.assertIn("Reconcile accounts — Q4.", split_text)
        split_rows = [json.loads(l) for l in split_text.splitlines()]
        for row in split_rows:
            tid = row["task_id"]
            if tid in ("task-alpha", "task-beta"):
                self.assertEqual(row["docker_image"], NEW_OFFICE)
            expected_tree = M.compute_tree_sha256(
                {
                    p[len(f"tasks/{tid}/") :]: _sha(data)
                    for p, data in snap.items()
                    if p.startswith(f"tasks/{tid}/")
                }
            )
            self.assertEqual(row["tree_sha256"], expected_tree)

        # SHA256SUMS preserved exact order, exact count, untouched lines, and matches every file
        old_sum_paths = [
            l.split("  ", 1)[1]
            for l in api.history[repo_id][initial_head]["SHA256SUMS"]
            .decode("utf-8")
            .splitlines()
        ]
        new_sum_lines = snap["SHA256SUMS"].decode("utf-8").splitlines()
        new_sum_paths = [l.split("  ", 1)[1] for l in new_sum_lines]
        self.assertEqual(new_sum_paths, old_sum_paths)
        for line in new_sum_lines:
            hex_digest, rel = line.split("  ", 1)
            self.assertEqual(hex_digest, _sha(snap[rel]), f"SHA256SUMS mismatch for {rel}")

        # 3. Second run is completely idempotent: 0 ops, no new commit!
        rerun = M.migrate_hub_dataset(
            repo_id, mappings, apply=True, api=api, images_module=oci
        )
        self.assertEqual(rerun["status"], "up_to_date")
        self.assertEqual(rerun["committed_files"], 0)
        self.assertEqual(rerun["counts"]["total_files_to_commit"], 0)
        self.assertEqual(len(api.commits), 1)

    def test_hub_readback_detects_corruption_and_immutable_guard(self):
        repo_id = "harness-hub/automation-adapter-envs"
        api = InMemoryHfApi(
            {repo_id: _make_hub_repo_fixture()},
            corrupt_on_commit={"SHA256SUMS": b"corrupted\n"},
        )
        oci = FakeOCIClientFactory({NEW_OFFICE: _ok_resolved(NEW_OFFICE)})
        with self.assertRaisesRegex(RuntimeError, "Readback verification failed"):
            M.migrate_hub_dataset(
                repo_id, {OLD_OFFICE: NEW_OFFICE}, apply=True, api=api, images_module=oci
            )

        # Immutable baseline guard rejects apply on harness-hub/harness-adapters by default
        hist_api = InMemoryHfApi(
            {"harness-hub/harness-adapters": _make_hub_repo_fixture()}
        )
        with self.assertRaisesRegex(ValueError, "immutable baseline"):
            M.migrate_hub_dataset(
                "harness-hub/harness-adapters",
                {OLD_OFFICE: NEW_OFFICE},
                apply=True,
                api=hist_api,
                images_module=oci,
            )
        self.assertEqual(len(hist_api.commits), 0)

    def test_hub_splits_tree_sha256_fallback_without_sha256sums(self):
        files = _make_hub_repo_fixture()
        del files["SHA256SUMS"]
        repo_id = "harness-hub/no-sums-dataset"
        api = InMemoryHfApi({repo_id: files})
        res = M.migrate_hub_dataset(
            repo_id,
            {OLD_OFFICE: NEW_OFFICE},
            apply=True,
            skip_public_check=True,
            api=api,
        )
        self.assertEqual(res["status"], "committed")
        self.assertFalse(res["counts"]["sha256sums_updated"])
        snap = api.history[repo_id][res["commit_oid"]]
        rows = [
            json.loads(l) for l in snap["splits/train.jsonl"].decode("utf-8").splitlines()
        ]
        alpha = next(r for r in rows if r["task_id"] == "task-alpha")
        expected_tree = M.compute_tree_sha256(
            {
                p[len("tasks/task-alpha/") :]: _sha(data)
                for p, data in snap.items()
                if p.startswith("tasks/task-alpha/")
            }
        )
        self.assertEqual(alpha["tree_sha256"], expected_tree)

    def test_local_migration_dry_run_apply_and_idempotency(self):
        with tempfile.TemporaryDirectory() as tmp_str:
            root = Path(tmp_str)
            mappings = _make_local_repo_fixture(root)
            oci = FakeOCIClientFactory(
                {ref: _ok_resolved(ref) for ref in mappings.values()}
            )

            expected_files = sorted(
                [
                    "knowledge/image/receipts/apex-office-tools.json",
                    "knowledge/image/receipts/spreadsheetbench-verified.json",
                    "knowledge/automation_grade_job.py",
                    "knowledge/automation_canary_job.py",
                    "knowledge/broad_eval/benchmarks/gdpval.py",
                    "knowledge/broad_eval/benchmarks/jobbench.py",
                    "knowledge/broad_eval/benchmarks/spreadsheetbench.py",
                ]
            )

            # 1. Dry-run reports all 7 diffs and touches nothing on disk
            dry = M.migrate_local_repo(
                mappings, repo_root=root, apply=False, images_module=oci
            )
            self.assertEqual(dry["mode"], "dry-run")
            self.assertFalse(dry["applied"])
            self.assertEqual(dry["changed_files"], expected_files)
            self.assertEqual(sorted(dry["diffs"].keys()), expected_files)
            self.assertTrue(
                any("TASKS_SHA256" in w for w in dry["warnings"])
            )
            self.assertIn(
                OLD_OFFICE,
                (root / "knowledge/automation_grade_job.py").read_text(encoding="utf-8"),
            )

            # 2. Apply updates all 7 files cleanly
            applied = M.migrate_local_repo(
                mappings, repo_root=root, apply=True, images_module=oci
            )
            self.assertEqual(applied["mode"], "apply")
            self.assertTrue(applied["applied"])
            self.assertEqual(applied["changed_files"], expected_files)

            # Verify JSON receipts copied cleanly from ghcr receipts
            office_rec = json.loads(
                (root / "knowledge/image/receipts/apex-office-tools.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(office_rec["image"], NEW_OFFICE)
            self.assertTrue(office_rec["public_pull_verified"])
            self.assertNotIn("space_id", office_rec)

            ssbv_rec = json.loads(
                (
                    root / "knowledge/image/receipts/spreadsheetbench-verified.json"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(ssbv_rec["image"], NEW_SSBV)

            # Verify Python AST assignments & preserved dockerfile_sha256
            for rel, expected_img, meta_var, expected_df in [
                ("knowledge/automation_grade_job.py", NEW_OFFICE, None, None),
                ("knowledge/automation_canary_job.py", NEW_OFFICE, None, None),
                (
                    "knowledge/broad_eval/benchmarks/gdpval.py",
                    NEW_GDPVAL,
                    "IMAGE_RECEIPT",
                    "5ddd7940" + "0" * 56,
                ),
                (
                    "knowledge/broad_eval/benchmarks/jobbench.py",
                    NEW_JOBBENCH,
                    "IMAGE_RECEIPT",
                    "f543b685" + "0" * 56,
                ),
                (
                    "knowledge/broad_eval/benchmarks/spreadsheetbench.py",
                    NEW_SSBV,
                    "IMAGE_PROVENANCE",
                    "cf2d9e96" + "0" * 56,
                ),
            ]:
                src = (root / rel).read_text(encoding="utf-8")
                self.assertNotIn("registry.hf.space", src)
                tree = ast.parse(src)
                img_node = M._find_top_level_assign(tree, "IMAGE")
                self.assertIsNotNone(img_node)
                self.assertEqual(ast.literal_eval(img_node.value), expected_img)
                if meta_var:
                    mnode = M._find_top_level_assign(tree, meta_var)
                    self.assertIsNotNone(mnode)
                    meta = ast.literal_eval(mnode.value)
                    self.assertEqual(meta["dockerfile_sha256"], expected_df)
                    self.assertEqual(meta["platform"], "linux/amd64")
                    self.assertTrue(meta["public_pull_verified"])
                    self.assertNotIn("space_id", meta)

            # 3. Second run is completely idempotent (0 changes)
            rerun = M.migrate_local_repo(
                mappings, repo_root=root, apply=True, images_module=oci
            )
            self.assertFalse(rerun["applied"])
            self.assertEqual(rerun["changed_files"], [])
            self.assertEqual(rerun["diffs"], {})

    def test_audit_datasets_classifies_repos(self):
        migrated_toml = (
            'version = "1.0"\n[environment]\n'
            f'docker_image = "{NEW_OFFICE}"\n'
        ).encode("utf-8")
        bundle_toml = (
            'version = "1.0"\n[environment]\n'
            f'docker_image = "{OLD_OFFICE}"\n'
        ).encode("utf-8")

        api = InMemoryHfApi(
            {
                "harness-hub/automation-adapter-envs": _make_hub_repo_fixture(),
                "harness-hub/scale800-harbor": {
                    "tasks/t1/task.toml": migrated_toml,
                    "README.md": b"# scale800\n",
                },
                "burtenshaw/apex-knowledge-rl-bundle": {
                    "tasks/t1/task.toml": bundle_toml,
                    "manifest/train.jsonl": b'{"task_id": "t1"}\n',
                },
                "harness-hub/harness-adapters": _make_hub_repo_fixture(),
            },
            private_repos={"burtenshaw/apex-knowledge-rl-bundle"},
        )
        report = M.audit_datasets(
            [
                "harness-hub/automation-adapter-envs",
                "harness-hub/scale800-harbor",
                "burtenshaw/apex-knowledge-rl-bundle",
                "harness-hub/harness-adapters",
            ],
            api=api,
        )
        by_repo = {row["repo_id"]: row for row in report["datasets"]}
        self.assertEqual(by_repo["harness-hub/automation-adapter-envs"]["status"], "needs_migration")
        self.assertEqual(by_repo["harness-hub/scale800-harbor"]["status"], "migrated")
        self.assertEqual(
            by_repo["burtenshaw/apex-knowledge-rl-bundle"]["status"],
            "needs_migration_bundle",
        )
        self.assertEqual(
            by_repo["harness-hub/harness-adapters"]["status"],
            "immutable_historical",
        )
        self.assertEqual(report["summary"]["needs_migration"], 1)
        self.assertEqual(report["summary"]["needs_migration_bundle"], 1)
        self.assertEqual(report["summary"]["immutable_historical"], 1)
        self.assertEqual(report["summary"]["migrated"], 1)

    def test_rewrite_task_toml_preserves_native_datetimes_and_verifier_env(self):
        raw = (
            'schema_version = "1.3"\n'
            "[metadata]\n"
            "created_at = 2026-11-26T12:00:00Z\n"
            "[environment]\n"
            f'docker_image = "{OLD_OFFICE}"\n'
            "[verifier.environment]\n"
            f'docker_image = "{OLD_SSBV}"\n'
        )
        updated, changes = M.rewrite_task_toml(
            raw, {OLD_OFFICE: NEW_OFFICE, OLD_SSBV: NEW_SSBV}
        )
        self.assertEqual(
            changes,
            [
                ("environment", OLD_OFFICE, NEW_OFFICE),
                ("verifier.environment", OLD_SSBV, NEW_SSBV),
            ],
        )
        parsed = tomllib.loads(updated)
        self.assertEqual(parsed["environment"]["docker_image"], NEW_OFFICE)
        self.assertEqual(parsed["verifier"]["environment"]["docker_image"], NEW_SSBV)
        self.assertEqual(parsed["metadata"]["created_at"].year, 2026)


if __name__ == "__main__":
    unittest.main()
