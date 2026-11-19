"""Capture an accepted batch using the source-bound publication helpers."""

import json
import re
import sys
import tempfile
from collections import Counter
from pathlib import Path

from run import checked, load


def stage(operators, language, roster, output, campaign, batch, prior):
    safe = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
    if not safe.fullmatch(campaign) or not safe.fullmatch(batch):
        raise ValueError("Use a single lowercase path component for campaign and batch")
    if output.exists() or output.is_symlink():
        raise ValueError("Stage output must be fresh")
    rows = json.loads(roster.read_bytes())
    if not isinstance(rows, list) or not rows:
        raise ValueError("Expected a nonempty reviewed capture roster")
    for row in rows:
        for key in ("plan_path", "terminal_proof_path"):
            if key in row:
                row[key] = str((roster.parent / row[key]).resolve(strict=True))
        plan = Path(row["plan_path"])
        checked(plan, row["plan_sha256"])
        if (
            json.loads(
                checked(plan.parent / "execution-run/report.json", row["report_sha256"])
            ).get("admitted")
            is not True
        ):
            raise ValueError(f"Gate did not admit {row['task_id']}")
    source = (
        "gate-publication-supervision-v1/fast_publish.py"
        if language == "go"
        else "python-gate-publication-v5/publish.py"
    )
    helper = load(operators / source)
    helper.PREFIX = (
        "scale800_v1/" if language == "go" else "scale800_py_v1/"
    ) + campaign
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=output.parent) as temp:
        dest = Path(temp) / "batch"
        plan = helper.capture(rows, dest, batch)
        if not (dest / "files" / plan["split_path"]).is_file():
            raise ValueError("Missing source registration index")
        counts, ids = Counter(), set()
        for index in [*prior, dest / "files" / plan["split_path"]]:
            for line in index.read_bytes().splitlines():
                row = json.loads(line)
                repo = row["upstream_repo"].casefold()
                counts[repo] += 1
                if row["task_id"] in ids or counts[repo] > 40:
                    raise ValueError(
                        f"Duplicate task or repository cap exceeded: {row['task_id']}"
                    )
                ids.add(row["task_id"])
        dest.rename(output)
    print(
        json.dumps(
            {
                "config": plan["config"],
                "split": plan["split_path"],
                "tasks": plan["summary"]["tasks"],
            }
        )
    )


if __name__ == "__main__":
    operators, language, roster, output, campaign, batch, *prior = sys.argv[1:]
    stage(
        Path(operators),
        language,
        Path(roster),
        Path(output),
        campaign,
        batch,
        list(map(Path, prior)),
    )
