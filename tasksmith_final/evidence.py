"""Replay the historical six-check gate and eight-slot difficulty protocol."""

from common import inside, read, require, sha, source_digest
from rows import PROTOCOL

CHECKS = (
    "static.manifest",
    "runtime.startup",
    "runtime.reward_well_formed",
    "runtime.episode_determinism",
    "semantic.oracle_max",
    "semantic.floor_gap",
)


def gate(run, task_id, mod):
    task = inside(run / "modified", mod["path"])
    effective = source_digest(task)
    report_path = run / "validation" / "final" / f"{task_id}.json"
    artifacts = report_path.with_suffix(".artifacts")
    report = read(report_path)
    if not artifacts.is_dir():
        require(report["source_digest"] == effective, f"wrong report for {task_id}")
        return report, {}, ["missing runtime evidence"]
    # The external JSON may use different whitespace from the bundle copy.
    require(
        read(artifacts / "report.json") == report,
        f"report differs from bundle for {task_id}",
    )
    hashes = {}
    for line in (artifacts / "SHA256SUMS").read_text().splitlines():
        digest, name = line.split("  ", 1)
        require(
            name not in hashes and sha(inside(artifacts, name)) == digest,
            f"bad evidence checksum: {name}",
        )
        hashes[name] = digest
    required = {"report.json", "run-manifest.json", "cleanup.json"}
    require(required <= hashes.keys(), f"incomplete checksum manifest for {task_id}")
    require(
        effective
        == report["source_digest"]
        == read(artifacts / "run-manifest.json")["source_digest"],
        f"report does not describe the modified bytes for {task_id}",
    )
    if "harbor-evidence.json" not in hashes:
        return report, {}, ["missing Harbor runtime evidence"]
    evidence = read(artifacts / "harbor-evidence.json")
    require(
        evidence.get("task_effective_digest") == effective
        and evidence.get("image_ref") == mod["image"]
        and evidence.get("original_source_digest") == mod["original_source_digest"],
        f"Harbor evidence describes another task for {task_id}",
    )
    require(
        evidence["sandbox"] == "hf-sandbox"
        and evidence["profile"] == "harbor-semantic-v1",
        f"wrong runtime for {task_id}",
    )
    checks = {item["check_id"]: item["status"] for item in report["results"]}
    reasons = [
        f"{key}={checks.get(key)}" for key in CHECKS if checks.get(key) != "pass"
    ]
    if report["verdict"] == "fail":
        reasons.append("report verdict is fail")
    rewards = {
        t["role"]: (t.get("rewards") or {}).get("reward") for t in evidence["trials"]
    }
    if rewards.get("oracle") != 1 or rewards.get("oracle-replay") != 1:
        reasons.append("oracle or oracle-replay did not reach 1")
    if rewards.get("nop") is None or rewards["nop"] >= 1:
        reasons.append("do-nothing reward must be below 1")
    if (
        evidence["cleanup"].get("verified") is not True
        or read(artifacts / "cleanup.json")["verified"] is not True
    ):
        reasons.append("HF Jobs cleanup unverified")
    return report, rewards, reasons


def attempts(run, tid, task_digest, *, historical):
    records = []
    if not historical:
        run_id = (run / "qwen/runs/run_id.txt").read_text().strip()
        cleanup = read(run / "qwen/runs/cleanup.json")
        require(
            cleanup.get("run_id") == run_id and cleanup.get("still_running") == [],
            "unverified scoring cleanup",
        )
    for index in range(8):
        path = run / "qwen" / "runs" / tid / f"attempt-{index}.json"
        record = read(path)
        require(
            record["task_id"] == tid
            and record["attempt"] == index
            and record["protocol"] == PROTOCOL,
            f"attempt identity mismatch: {path}",
        )
        if not historical:
            require(
                record.get("task_digest") == task_digest
                and record.get("run_id") == run_id,
                f"attempt input mismatch: {tid}/{index}",
            )
        valid = record.get("reward") is not None and record.get("exception") in (
            None,
            "AgentTimeoutError",
        )
        if valid:
            require(
                type(record["reward"]) in (float, int) and 0 <= record["reward"] <= 1,
                f"invalid reward: {tid}/{index}",
            )
        require(
            record["valid"] is valid
            and record["solved"] is ((record["reward"] == 1) if valid else None),
            f"attempt outcome mismatch: {path}",
        )
        records.append(record)
    return records
