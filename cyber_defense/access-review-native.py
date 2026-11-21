"""Replay solver-visible OpenFGA tasks on the official CLI's in-memory OpenFGA server."""

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import re
import subprocess
from tempfile import TemporaryDirectory


def model_test(task):
    _, model_and_data = task["prompt"].split("\n\nmodel\n", 1)
    model, remaining = ("model\n" + model_and_data).split("\n\nStored relationships:\n", 1)
    tuples = json.loads(remaining.splitlines()[0])
    if "Additional relationships valid only for this query:" in remaining:
        local = remaining.split("Additional relationships valid only for this query:\n", 1)[1]
        tuples.extend(json.loads(local.splitlines()[0]))
    native = {"name": task["task_id"]}
    if task["family"] == "openfga-check":
        qs = json.loads(remaining.split("Access checks in order:\n", 1)[1])
        native["check"] = [
            {"user": user, "object": obj, "assertions": {rel: decision}}
            for (obj, rel, user), decision in zip(qs, task["answer"]["decisions"], strict=True)
        ]
    else:
        query = json.loads(remaining.split("ListObjects request:\n", 1)[1])
        native["list_objects"] = [{"type": query["type"], "user": query["user"],
                                   "assertions": {query["relation"]: task["answer"]["objects"]}}]
    stored = [dict(object=o, relation=r, user=u) for o, r, u in sorted(set(map(tuple, tuples)))]
    return {"name": task["task_id"], "model": model, "tuples": stored, "tests": [native]}


def main(binary, cohort, out):
    data = cohort.read_bytes()
    rows = [t for line in data.splitlines() if (t := json.loads(line))["family"].startswith("openfga-")]
    with TemporaryDirectory() as temp:
        root = Path(temp)

        def check(t):
            target = root / (t["task_id"] + ".fga.yaml")
            record = model_test(t)
            target.write_text(json.dumps(record))
            response = subprocess.run([binary, "model", "test", "--tests", str(target)],
                                      capture_output=True, text=True, timeout=30)
            log = response.stdout + response.stderr
            count = (len(t["answer"]["decisions"]) if "decisions" in t["answer"] else 1)
            operation = "Checks" if "decisions" in t["answer"] else "ListObjects"
            passed = (response.returncode == 0 and f"{operation} {count}/{count} passing" in log)
            return {"task_id": t["task_id"], "task_sha256": t["task_sha256"],
                    "assertions": count, "pass": passed, "output": log.strip().replace(temp, "<temp>")}

        with ThreadPoolExecutor(4) as workers:
            results = list(workers.map(check, rows))
    raw = b"".join(json.dumps(r, sort_keys=True).encode() + b"\n" for r in results)
    out.parent.mkdir(exist_ok=True, parents=True)
    out.write_bytes(raw)
    print(json.dumps({"cohort_sha256": hashlib.sha256(data).hexdigest(),
                      "cli_binary_sha256": hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
                      "rows": len(rows), "passed": sum(r["pass"] for r in results),
                      "assertions": sum(r["assertions"] for r in results),
                      "receipts_sha256": hashlib.sha256(raw).hexdigest()}))
    return all(r["pass"] for r in results)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("cohort", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    raise SystemExit(0 if main(args.binary.resolve(), args.cohort, args.output) else 1)
