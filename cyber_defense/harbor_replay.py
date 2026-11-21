"""Replay existing authorization answers as data files in isolated Harbor trials."""

import argparse
import asyncio
import base64
from collections import Counter
import fcntl
import hashlib
import json
from pathlib import Path
import shutil
from uuid import uuid4

from harbor.agents.nop import NopAgent
from harbor.models.trial.config import TrialConfig
from harbor.trial.trial import Trial

from . import grading
from .grading import canonical, payload_sha256
from .harbor import bundle_files


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def store(path, value):
    temp = path.with_suffix(".tmp")
    temp.write_bytes(canonical(value) + b"\n")
    temp.replace(path)


class SavedAnswer(NopAgent):
    def __init__(self, *args, reply_file: str, **kwargs):
        super().__init__(*args, **kwargs)
        self.reply_file = Path(reply_file)

    @staticmethod
    def name():
        return "replay-static-answer"

    async def run(self, instruction, environment, context):
        await environment.upload_file(self.reply_file, "/tmp/answer.json")


def records(root):
    raw = (root / "episode-replay.jsonl").read_bytes()
    summary = json.loads((root / "difficulty-summary.json").read_bytes())
    if sha(raw) != summary["episode_receipts_sha256"]:
        raise ValueError("OpenEnv replay digest mismatch")
    ledger = {r["completion_id"]: r for r in map(json.loads, raw.splitlines())}
    for final in sorted((root / "rollouts/attempts").glob("*/*/final.json")):
        scored = json.loads(final.read_bytes())
        if scored["reward"] is None:
            continue
        row = ledger.pop(scored["completion_id"])
        receipt_path = final.parent / f"{scored['provider_call']}.response.json"
        receipt = receipt_path.read_bytes()
        if (sha(receipt) != row["response_sha256"] or row["task_id"] != scored["task_id"]
                or row["slot"] != scored["slot"] or row["reward"] != scored["reward"]):
            raise ValueError("Conflicting source slot or response digest")
        envelope = json.loads(receipt)
        body = base64.b64decode(envelope["body_base64"], validate=True)
        message = json.loads(body)["choices"][0]["message"]
        if sha(body) != envelope["body_sha256"]:
            raise ValueError("Response body digest mismatch")
        text = "" if message.get("refusal") else message["content"]
        yield row, text.encode(), final.parent.parent.name
    if ledger:
        raise ValueError("OpenEnv replay names missing completions")


async def replay(root, limit):
    out = root / "harbor-answer-replay"
    out.mkdir(exist_ok=True)
    receipts = out / "receipts"
    receipts.mkdir(exist_ok=True)
    inputs = out / "inputs"
    inputs.mkdir(exist_ok=True)
    with (out / "coordinator.lock").open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        counts = Counter()
        queue = list(records(root))
        cohort = (root / "tasks.jsonl").read_bytes()
        if sha(cohort) != json.loads((root / "difficulty-summary.json").read_bytes())["cohort_sha256"]:
            raise ValueError("Cohort digest changed")
        by_id = {t["task_id"]: t for t in map(json.loads, cohort.splitlines())}
        validated = set()
        for row, content, index in queue:
            key = f"{index}-{row['slot']}"
            dest = receipts / (key + ".json")
            task = root / "harbor-bundles/tasks" / row["task_id"]
            if row["task_id"] not in validated:
                definition = by_id[row["task_id"]]
                if payload_sha256(definition) != definition["task_sha256"]:
                    raise ValueError("Task definition changed")
                expected = bundle_files(definition, Path(grading.__file__).read_bytes())
                if ({p.relative_to(task).as_posix() for p in task.rglob("*") if p.is_file()} != set(expected)
                        or any((task / name).is_symlink() or (task / name).read_bytes() != data for name, data in expected.items())):
                    raise ValueError("Execution bundle differs from the sealed export")
                validated.add(row["task_id"])
            if dest.exists():
                prev = json.loads(dest.read_bytes())
                trial_dir = root / prev["trial"]
                raw_result = (trial_dir / "result.json").read_bytes()
                native = json.loads(raw_result)
                if (prev["source"] != row or prev["submitted_sha256"] != sha(content)
                        or prev["native_reward"] != row["reward"] or sha(raw_result) != prev["result_sha256"]
                        or native.get("exception_info") or native["verifier_result"]["rewards"]["reward"] != row["reward"]
                        or (trial_dir / "artifacts/tmp/answer.json").read_bytes() != content):
                    raise ValueError("Existing replay conflicts with source")
                counts["verified"] += 1
                continue
            if limit is not None and counts["new"] >= limit:
                break
            if shutil.disk_usage(out).free < 1024**3:
                raise RuntimeError("Less than 1 GiB free in the trial workspace")
            payload = inputs / (key + ".txt")
            payload.write_bytes(content)
            name = f"defaudit-{key}-{uuid4().hex[:10]}"
            cfg = TrialConfig.model_validate({
                "task": {"path": task}, "environment": {"type": "docker", "delete": True},
                "trial_name": name, "trials_dir": out / "trials",
                "agent": {"import_path": "cyber_defense.harbor_replay:SavedAnswer",
                          "kwargs": {"reply_file": str(payload)}},
            })
            trial = await Trial.create(cfg)
            await trial.run()
            trial_dir = out / "trials" / name
            raw_result = (trial_dir / "result.json").read_bytes()
            result = json.loads(raw_result)
            actual = (result.get("verifier_result") or {}).get("rewards", {}).get("reward")
            artifact = trial_dir / "artifacts/tmp/answer.json"
            if result.get("exception_info") or actual != row["reward"] or not artifact.exists() or artifact.read_bytes() != content:
                raise RuntimeError(f"Harbor replay did not verify. Inspect {trial_dir}")
            store(dest, {"source": row, "trial": str(trial_dir.relative_to(root)),
                         "result_sha256": sha(raw_result), "native_reward": actual,
                         "submitted_sha256": sha(content)})
            counts.update(verified=1, new=1)
            store(out / "progress.json", {"verified": counts["verified"], "planned": len(queue), "last_trial": name})
        total = {"verified": counts["verified"], "planned": len(queue), "new": counts["new"]}
        if counts["verified"] == len(queue):
            store(out / "terminal.json", {**total, "cohort_sha256": sha(cohort), "status": "completed"})
        print(json.dumps(total), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--limit", type=int)
    args = parser.parse_args()
    asyncio.run(replay(args.output.resolve(), args.limit))
