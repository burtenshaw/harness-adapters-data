"""Replay a sealed cohort against the OpenEnv episode lifecycle and controls."""

import argparse
import copy
import hashlib
import json
from pathlib import Path

from .environment import AuditAction, AuditEnvironment
from .grading import canonical


def plausible_error(expected):
    answer = copy.deepcopy(expected)
    if "decisions" in answer:
        answer["decisions"][0] = not answer["decisions"][0]
    elif "objects" in answer:
        if answer["objects"]:
            answer["objects"].pop()
        else:
            answer["objects"].append("resource:unassigned")
    elif "results" in answer:
        row = answer["results"][0]
        row["decision"] = {"allow": "deny", "deny": "allow"}[row["decision"]]
    else:
        raise ValueError("No valid negative control for the task schema")
    return answer


def validate(task):
    env = AuditEnvironment(task)
    answer = task["answer"]
    winner = canonical(answer).decode()
    inputs = {
        "oracle": (winner, 1),
        "formatted_oracle": (json.dumps(answer, indent=2), 1),
        "wrong_decision": (json.dumps(plausible_error(answer)), 0),
        "empty_action": ("{}", 0),
        "malformed": (winner + " extra", 0),
    }
    for name, (submission, expected) in inputs.items():
        reset = env.reset()
        if (reset.prompt != task["prompt"] or reset.task_id != task["task_id"]
                or reset.done or env.state.step_count != 0 or reset.metadata):
            raise ValueError(f"Bad starting observation on {name}")
        obs = env.step(AuditAction(submission=submission))
        if (obs.reward != expected or not obs.done or obs.prompt is not None
                or env.state.step_count != 1):
            raise ValueError(f"Unexpected environment outcome on {name}")
    try:
        env.step(AuditAction(submission=winner))
    except RuntimeError:
        pass
    else:
        raise ValueError("Environment accepted a second answer")
    return {"task_id": task["task_id"], "task_sha256": task["task_sha256"],
            "results": {name: expected for name, (_, expected) in inputs.items()},
            "second_action_rejected": True}


def replay(cohort, receipts=None):
    raw = Path(cohort).read_bytes()
    rows = [json.loads(line) for line in raw.splitlines()]
    ids = {row["task_id"] for row in rows}
    prompts = {row["prompt"] for row in rows}
    if not rows or len(rows) != len(ids) or len(rows) != len(prompts):
        raise ValueError("Empty or duplicate cohort")
    results = b"".join(canonical(validate(row)) + b"\n" for row in rows)
    if receipts:
        Path(receipts).write_bytes(results)
    return {"validated": len(rows), "cohort_sha256": hashlib.sha256(raw).hexdigest(),
            "receipts_sha256": hashlib.sha256(results).hexdigest()}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cohort", type=Path)
    parser.add_argument("--receipts", type=Path)
    args = parser.parse_args()
    print(json.dumps(replay(args.cohort, args.receipts), sort_keys=True))
