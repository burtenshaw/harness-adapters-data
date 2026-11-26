"""Exercise the fresh campaign path offline using fixture validation and Qwen receipts."""

import argparse
import hashlib
import json
import tempfile
from pathlib import Path
from types import SimpleNamespace

from admission import DEFAULT_SPEND, ledger_module, reserve, stage_plan
from adapt import ENV_DOCKERFILE_TAIL, ORIGINAL_TEST_SH, TESTS_DOCKERFILE_TAIL
from audit import context
from common import jsonl, read, require, sha, source_digest, write
from evidence import CHECKS
from pipeline import init, prepare
from publish import file_manifest, publish
from rows import PROTOCOL
from stage import stage, write_jsonl


def starter(root, tid):
    task = root / "tasks" / tid
    for folder in ("environment/source", "tests/source", "solution/reference"):
        (task / folder).mkdir(parents=True)
    (task / "instruction.md").write_text("Return the square of the input.\n")
    cfg = f"""task_name = "fixture"
[task]
name = "repo2rlenv/{tid}"
[environment]
network_mode = "no-network"
cpus = 1
memory_mb = 512
[agent]
user = "learner"
network_mode = "no-network"
[verifier]
environment_mode = "separate"
user = "root"
network_mode = "no-network"
[verifier.environment]
network_mode = "no-network"
[metadata.repo2env]
bundle_hash = "fixture-native-hash"
"""
    (task / "task.toml").write_text(cfg)
    for folder in ("environment", "tests"):
        tail = ENV_DOCKERFILE_TAIL if folder == "environment" else TESTS_DOCKERFILE_TAIL
        (task / folder / "Dockerfile").write_text(
            "\n".join(["FROM python:3.12-slim", "COPY source /workspace", *tail])
        )
        (task / folder / "source/square.py").write_text("def square(x): return x\n")
    (task / "solution/reference/square.py").write_text("def square(x): return x*x\n")
    (task / "tests/test.sh").write_text(ORIGINAL_TEST_SH)
    write(task / "tests/contract.json", {"test_paths": ["test_square.py::test_square"]})
    write(root / "provenance/fixture/source.json", {"fixture": True})
    row = {
        "task_id": tid,
        "task_path": f"tasks/{tid}",
        "provenance_path": "provenance/fixture",
        "tasksmith_verified": True,
        "tasksmith_bundle_hash": "fixture-native-hash",
        "source_repo": "https://github.com/example/square",
        "source_head_commit": "a" * 40,
        "source_pr_url": "https://github.com/example/square/pull/1",
        "split": "candidates",
        "source_license_spdx": "MIT",
    }
    return task, row


def record_fixture(run, tid, mod):
    effective = mod["effective_digest"]
    report = {
        "source_digest": effective,
        "verdict": "warn",
        "results": [{"check_id": key, "status": "pass"} for key in CHECKS],
    }
    report_path = run / "validation/final" / f"{tid}.json"
    artifacts = report_path.with_suffix(".artifacts")
    write(report_path, report)
    write(artifacts / "report.json", report)
    write(artifacts / "run-manifest.json", {"source_digest": effective})
    write(artifacts / "cleanup.json", {"verified": True})
    write(
        artifacts / "harbor-evidence.json",
        {
            "task_effective_digest": effective,
            "image_ref": mod["image"],
            "original_source_digest": mod["original_source_digest"],
            "sandbox": "hf-sandbox",
            "profile": "harbor-semantic-v1",
            "cleanup": {"verified": True},
            "trials": [
                {"role": role, "rewards": {"reward": int(role != "nop")}}
                for role in ("oracle", "oracle-replay", "nop")
            ],
        },
    )
    (artifacts / "SHA256SUMS").write_text(
        "".join(f"{sha(p)}  {p.name}\n" for p in sorted(artifacts.iterdir()))
    )
    scores = run / "qwen/runs"
    write(scores / "cleanup.json", {"run_id": "fixture", "still_running": []})
    (scores / "run_id.txt").write_text("fixture")
    for index in range(8):
        valid = index < 7
        write(
            scores / tid / f"attempt-{index}.json",
            {
                "task_id": tid,
                "run_id": "fixture",
                "attempt": index,
                "task_digest": effective,
                "protocol": PROTOCOL,
                "exception": None if valid else "ProviderError",
                "valid": valid,
                "reward": int(index == 0) if valid else None,
                "solved": (index == 0) if valid else None,
            },
        )


class OfflineHub:
    def __init__(self, root, base, base_view):
        self.path = root
        self.head = "1" * 40
        self.snapshots = {
            self.head: {
                "README.md": b"---\nconfigs:\n- config_name: baseline\n---\nCard\n",
                base_view: base.read_bytes(),
            }
        }
        for row in jsonl(base):
            for key, value in row.items():
                if key.endswith("_path") and value:
                    self.snapshots[self.head][value] = (
                        b"fixture for existing repository entry"
                    )
        self.parents = []

    def dataset_info(self, repo):
        return SimpleNamespace(id=repo, private=True, sha=self.head)

    def download(self, repo, path, *, repo_type, revision):
        target = self.path / revision / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(self.snapshots[revision][path])
        return target

    def get_paths_info(self, repo, paths, *, repo_type, revision):
        for path in paths:
            if path in self.snapshots[revision]:
                data = self.snapshots[revision][path]
                yield SimpleNamespace(
                    path=path,
                    blob_id=hashlib.sha1(
                        f"blob {len(data)}\0".encode() + data
                    ).hexdigest(),
                )

    def create_commit(
        self, repo, *, repo_type, operations, parent_commit, commit_message
    ):
        assert parent_commit == self.head
        updated = self.snapshots[self.head].copy()
        for op in operations:
            value = op.path_or_fileobj
            updated[op.path_in_repo] = (
                value if isinstance(value, bytes) else Path(value).read_bytes()
            )
        self.parents.append(self.head)
        self.head = str(len(self.parents) + 1) * 40
        self.snapshots[self.head] = updated
        return SimpleNamespace(oid=self.head)


def must_reject(call, reason):
    try:
        call()
    except ValueError as exc:
        assert reason in str(exc), str(exc)
    else:
        raise AssertionError(f"expected rejection: {reason}")


def check_reservation(tmp, run, tid, mod):
    ledger = tmp / "campaign-ledger.json"
    args = SimpleNamespace(
        command="score",
        namespace="fixture",
        concurrency=1,
        spend_tool=DEFAULT_SPEND,
        ledger=ledger,
        budget_usd="6.25",
        plan_sha256="0" * 64,
    )
    plan = stage_plan(run, args, {tid: mod}, [tid])
    assert plan["reservation_usd"] == "6.25" and not ledger.exists()
    spend = ledger_module(DEFAULT_SPEND)
    spend.init(ledger, "6")
    must_reject(lambda: reserve(run, args, plan), "reviewed stage hash differs")
    args.plan_sha256 = plan["plan_sha256"]
    must_reject(lambda: reserve(run, args, plan), "Shared budget exceeded")
    assert not (run / "score-reservation.json").exists()
    args.ledger = tmp / "funded-ledger.json"
    spend.init(args.ledger, "10")
    args.budget_usd = "6"
    must_reject(lambda: reserve(run, args, plan), "exceeds supplied budget")
    args.budget_usd = "6.25"
    check = reserve(run, args, plan)
    check()
    reserve(run, args, plan)()
    assert len(read(args.ledger)["reservations"]) == 1
    spend.settle(
        args.ledger, read(run / "score-reservation.json")["id"], "1", "fixture"
    )
    must_reject(check, "no longer has its plan-bound shared reservation")


def check(tmp, base, check_publish, check_budget):
    source, run = tmp / "input", tmp / "run"
    tid = "tasksmith-000000000001"
    native, row = starter(source, tid)
    base_rows = jsonl(base)
    inputs = [row]
    old = next((r for r in base_rows if r.get("task_origin") == "tasksmith"), None)
    if old:
        inputs.append(
            {
                **row,
                "task_id": old["task_id"],
                "task_path": "tasks/" + old["task_id"],
                "source_repo": old["source_repo"],
                "source_head_commit": old["source_commit"],
                "source_pr_url": old["source_pr_url"],
            }
        )
    manifest = source / "verified.jsonl"
    write_jsonl(manifest, inputs)
    init(
        SimpleNamespace(
            sources=source,
            run=run,
            base=base,
            tag="smoke",
            split=[manifest],
            revision=None,
        )
    )
    cfg = read(run / "campaign.json")
    assert set(cfg["selected"]) == {tid}
    if old:
        assert cfg["already_present"] == [old["task_id"]]
    digest = "sha256:" + "b" * 64
    image = {
        "task_id": tid,
        "status": "resolved",
        "builder": "kaniko",
        "tag": tid,
        "registry_digest": digest,
        "config": {"os": "linux", "architecture": "amd64"},
        "image": f"ghcr.io/harness-hub/tasksmith-smoke@{digest}",
        "public_pull_verified": True,
        "context_files": {
            k: hashlib.sha256(v).hexdigest()
            for k, v in context(native).items()
            if k != "README.md"
        },
    }
    write(tmp / "images" / f"{tid}.json", image)
    prepare(run, cfg, tmp / "images")
    mod = read(run / "modified/modifications.json")[tid]
    record_fixture(run, tid, mod)
    if check_budget:
        check_reservation(tmp, run, tid, mod)
    out = tmp / "export"
    result = stage(run, out, cfg)
    final = jsonl(out / "views/final_smoke/train.jsonl")
    assert (
        final[:-1] == base_rows
        and final[-1]["qwen_valid_attempts"] == 7
        and final[-1]["qwen_solved"] == 1
    )
    assert (
        final[-1]["qwen_status"] == "incomplete"
        and jsonl(out / "views/final_best_smoke/train.jsonl")[-1] == final[-1]
    )
    for key in (
        "task_path",
        "provenance_path",
        "image_receipt_path",
        "gate_report_path",
        "execution_path",
        "task_file_inventory_path",
    ):
        assert (out / final[-1][key]).exists()
    assert source_digest(out / row["task_path"]) == source_digest(native)
    if check_publish:
        paths = file_manifest(out)
        write(run / "stage-manifest.json", {"out": str(out), "files": paths})
        base_view = "views/baseline/train.jsonl"
        hub = OfflineHub(tmp / "hub", base, base_view)
        args = SimpleNamespace(
            run=run, parent=hub.head, base_view=base_view, repo="example/private"
        )
        write(run / "campaign.json", {**cfg, "source_repo": "another/owner"})
        must_reject(
            lambda: publish(args, hub, SimpleNamespace, hub.download),
            "bound source repository",
        )
        write(run / "campaign.json", {**cfg, "source_repo": args.repo})
        if old:
            locator = old["task_path"]
            saved = hub.snapshots[hub.head].pop(locator)
            must_reject(
                lambda: publish(args, hub, SimpleNamespace, hub.download),
                "referenced paths",
            )
            hub.snapshots[hub.head][locator] = saved
        assert not hub.parents
        receipt = publish(args, hub, SimpleNamespace, hub.download)
        assert receipt["verified_files"] == len(paths) and len(hub.parents) == 2
        assert (
            publish(args, hub, SimpleNamespace, hub.download) == receipt
            and len(hub.parents) == 2
        )
    # Cross-task attempt substitutions must fail even when all counts still match.
    bad = run / "qwen/runs" / tid / "attempt-1.json"
    write(bad, {**read(bad), "task_digest": "a" * 64})
    try:
        stage(run, tmp / "invalid", cfg)
    except ValueError as exc:
        require(
            "attempt input mismatch" in str(exc),
            "unexpected failure in negative control",
        )
    else:
        raise AssertionError("unbound attempt accepted")
    print(
        json.dumps(
            {
                "retained_base_rows": len(base_rows),
                "fixture_rows_added": 1,
                "publication_test": check_publish,
                "budget_test": check_budget,
                "stage": result,
            }
        )
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base", type=Path, help="optional 62-column final view to exercise expansion"
    )
    parser.add_argument(
        "--mock-publish",
        action="store_true",
        help="exercise the two-commit publisher using PyYAML and an in-memory Hub",
    )
    parser.add_argument(
        "--check-budget",
        action="store_true",
        help="exercise the restored OpenEnv ledger offline",
    )
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as work:
        tmp = Path(work)
        base = args.base or (tmp / "empty.jsonl")
        if not args.base:
            base.touch()
        check(tmp, base, args.mock_publish, args.check_budget)
