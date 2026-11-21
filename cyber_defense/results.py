"""Replay recorded live answers through OpenEnv and tabulate task difficulty."""

import argparse
import base64
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path

from .environment import AuditAction, AuditEnvironment
from .grading import canonical


def read_lines(path):
    return [json.loads(line) for line in path.read_bytes().splitlines()]


def report(out):
    rollouts = out / "rollouts"
    protocol = json.loads((rollouts / "protocol.json").read_bytes())
    cohort = rollouts / "sealed-tasks.jsonl"
    if hashlib.sha256(cohort.read_bytes()).hexdigest() != protocol["input_sha256"]:
        raise ValueError("Population digest mismatch")
    tasks = read_lines(cohort)
    score_rows = read_lines(rollouts / "scores.jsonl")
    summary = json.loads((rollouts / "summary.json").read_bytes())
    if hashlib.sha256((rollouts / "scores.jsonl").read_bytes()).hexdigest() != summary["scores_sha256"]:
        raise ValueError("Score table digest mismatch")
    by_family = defaultdict(Counter)
    model = protocol["model"].split(":")[0].lower()
    provider = protocol["provider"].lower()
    receipts = bytearray()
    histogram = Counter()
    completions = set()
    slots = protocol["slots"]
    started_tasks = 0
    for i, (task, score) in enumerate(zip(tasks, score_rows, strict=True)):
        if task["task_id"] != score["task_id"] or task["task_sha256"] != score["task_sha256"]:
            raise ValueError(f"Wrong score for {task['task_id']}")
        env = AuditEnvironment(task)
        request_path = rollouts / "requests" / f"{i:05d}.json"
        raw_request = request_path.read_bytes()
        request = json.loads(raw_request)
        observed = attempts = 0
        for slot in range(slots):
            attempt = rollouts / "attempts" / f"{i:05d}" / str(slot)
            final_path = attempt / "final.json"
            if not final_path.is_file():
                continue
            final = json.loads(final_path.read_bytes())
            if final["reward"] is None:
                continue
            raw_receipt = (attempt / f"{final['provider_call']}.response.json").read_bytes()
            receipt = json.loads(raw_receipt)
            body = base64.b64decode(receipt["body_base64"], validate=True)
            response = json.loads(body)
            if (receipt["http_status"] != 200 or response["id"] in completions
                    or response["id"] != final["completion_id"] or response["model"].lower() != model
                    or response["provider"].lower() != provider
                    or hashlib.sha256(body).hexdigest() != receipt["body_sha256"]
                    or hashlib.sha256(raw_receipt).hexdigest() != final["receipt_sha256"]
                    or hashlib.sha256(raw_request).hexdigest() != final["request_sha256"]):
                raise ValueError(f"Invalid response binding for {task['task_id']}/{slot}")
            completions.add(response["id"])
            start = env.reset(episode_id=response["id"])
            if request["messages"] != [{"role": "system", "content": protocol["system"]},
                                       {"role": "user", "content": start.prompt}]:
                raise ValueError("Router request differs from environment observation")
            message = response["choices"][0]["message"]
            content = "" if message.get("refusal") else message.get("content") or ""
            result = env.step(AuditAction(submission=content))
            if not result.done or result.reward != final["reward"]:
                raise ValueError("Scorer and OpenEnv disagree")
            observed += int(result.reward)
            attempts += 1
            receipts.extend(canonical({"task_id": task["task_id"], "slot": slot,
                                       "completion_id": response["id"], "reward": result.reward,
                                       "response_sha256": final["receipt_sha256"]}) + b"\n")
        difficulty = (slots - observed) / slots if attempts == slots else None
        if (attempts != score["valid_attempts"] or observed != score["solved"]
                or difficulty != score["difficulty"] or (score["status"] == "scored") != (attempts == slots)):
            raise ValueError("Recorded task difficulty differs from OpenEnv replay")
        started_tasks += bool(attempts)
        counts = by_family[task["family"]]
        counts.update(tasks=1, solved=observed, attempts=attempts)
        if attempts == slots:
            histogram[observed] += 1
            counts.update(completed_groups=1, never_solved=int(observed == 0),
                          always_solved=int(observed == slots), mixed=int(0 < observed < slots))
    result = {"model": protocol["model"], "protocol": protocol["protocol"],
              "tasks": len(tasks), "samples_per_task": slots, "valid_rollouts": len(completions),
              "tasks_with_completed_rollouts": started_tasks, "complete_eight_sample_groups": sum(histogram.values()),
              "solved_rollouts": sum(counts["solved"] for counts in by_family.values()),
              "solves_per_task_histogram": dict(sorted(histogram.items())), "families": by_family,
              "cohort_sha256": protocol["input_sha256"], "scores_sha256": summary["scores_sha256"],
              "episode_receipts_sha256": hashlib.sha256(receipts).hexdigest()}
    (out / "episode-replay.jsonl").write_bytes(receipts)
    (out / "difficulty-summary.json").write_bytes(json.dumps(result, sort_keys=True, indent=2).encode() + b"\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    print(json.dumps(report(parser.parse_args().output), indent=2))
