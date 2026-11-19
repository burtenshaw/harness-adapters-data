"""Bind independent read-only Job inspections to all gate roles before staging."""

import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

from examples.coding_audit.hf import _deadline
from huggingface_hub import HfApi
from run import checked, load, sha

LABEL = "openenv-coding-attempt"


def events(raw):
    stream = raw.decode().lstrip()
    decoder = json.JSONDecoder()
    while stream:
        record, n = decoder.raw_decode(stream)
        yield record["event"]
        stream = stream[n:].lstrip()


def terminal(plan_path, expected, report_sha, api, helper):
    plan = json.loads(checked(plan_path, expected))
    result = plan_path.parent / "execution-run"
    report_raw = checked(result / "report.json", report_sha)
    if json.loads(report_raw).get("admitted") is not True:
        raise ValueError("Roster eligibility requires an admitted semantic report")
    owner = plan["execution"]["namespace"]
    counts, ids, labeled = set(), set(), set()
    jobs, trials = [], []
    for i, role in enumerate(plan["roles"]):
        folder = result / "trials" / f"{i:04d}"
        records = json.loads((folder / "records.json").read_bytes())
        trial = json.loads((folder / "trial.json").read_bytes())
        if trial["role"] != role["role"] or trial["role"] in counts:
            raise ValueError("Gate role inventory differs from the plan")
        counts.add(trial["role"])
        trials.append(trial)
        journal = list(events((folder / "lifecycle.jsonl").read_bytes()))
        expected_ids, expected_labels = set(), set()
        for kind, field, image_key in (
            ("agent", "sandbox_id", "agent_image"),
            ("grader", "grade_sandbox_id", "verifier_image"),
        ):
            task_id, label = trial[field], records[kind]["creation_label"]
            if (
                task_id in ids
                or label in labeled
                or not label
                or records[kind][field] != task_id
            ):
                raise ValueError("Ambiguous Job ownership in the captured role")
            ids.add(task_id)
            labeled.add(label)
            expected_ids.add(task_id)
            expected_labels.add(label)
            with _deadline(30):
                matches = list(
                    api.list_jobs(namespace=owner, labels={LABEL: label}, timeout=20)
                )
            if len(matches) != 1 or matches[0].id != task_id:
                raise ValueError(
                    "Creation label does not resolve to exactly the recorded Job"
                )
            with _deadline(20):
                job = api.inspect_job(namespace=owner, job_id=task_id)
            if (
                job.id != task_id
                or job.owner.name != owner
                or job.docker_image != plan["execution"][image_key]
                or (job.labels or {}).get(LABEL) != label
                or job.status.stage not in helper.TERMINAL
            ):
                raise ValueError("Live Job identity, image or terminal status differs")
            jobs.append(
                {
                    "role": trial["role"],
                    "kind": kind,
                    "creation_label": label,
                    "job_id": task_id,
                    "image_ref": job.docker_image,
                    "stage": job.status.stage,
                    "owner_label_image_verified": True,
                }
            )
        journal_labels = {
            item["creation_label"] for item in journal if item.get("creation_label")
        }
        journal_ids = {
            item[k]
            for item in journal
            for k in ("sandbox_id", "grade_sandbox_id")
            if item.get(k)
        }
        cleanup_ids = {
            value for item in journal for value in (item.get("cleanup_job_ids") or [])
        }
        if (
            journal_labels != expected_labels
            or journal_ids | cleanup_ids != expected_ids
        ):
            raise ValueError(
                "Lifecycle journal includes missing or additional Job effects"
            )
    proof = {
        "schema": "independent-gate-terminal-inspection-v1",
        "plan_sha256": expected,
        "report_sha256": report_sha,
        "task_digest": plan["task_digest"],
        "task_inventory_sha256": plan["task_inventory_sha256"],
        "dependency_lock_sha256": plan.get("dependency_lock_sha256"),
        "observed_utc": datetime.now(UTC).isoformat(),
        "jobs": jobs,
    }
    raw = helper.encode(proof)
    if "dependency_lock_sha256" in plan:
        helper.terminal_proof(raw, plan, expected, report_raw, trials)
    return raw


if __name__ == "__main__":
    code, plan, expected, report_sha, output = sys.argv[1:]
    raw = terminal(
        Path(plan),
        expected,
        report_sha,
        HfApi(token=os.environ.get("HF_SANDBOX_TOKEN")),
        load(Path(code)),
    )
    with Path(output).open("xb") as stream:
        stream.write(raw)
    print(json.dumps({"proof_sha256": sha(raw), "jobs": len(json.loads(raw)["jobs"])}))
