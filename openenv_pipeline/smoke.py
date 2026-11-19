"""Prepare and verify one example coding-audit bundle offline."""

import hashlib
import json
import sys
from pathlib import Path

from examples.hub_validation_pipeline import cloud, demo


def smoke(output, checkout):
    output.mkdir(parents=True, exist_ok=False)
    demo.create_tasks(output / "controls")
    config = json.loads((checkout / "examples/coding_audit/config.json").read_bytes())
    cloud.prepare(output / "controls/good", config, output / "plan", repo_root=checkout)
    plan = output / "plan/plan.json"
    digest = hashlib.sha256(plan.read_bytes()).hexdigest()
    cloud._read_plan(plan, expected_sha256=digest)
    print(
        json.dumps({"plan": str(plan), "sha256": digest, "verified": True, "jobs": 0})
    )


if __name__ == "__main__":
    smoke(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve())
