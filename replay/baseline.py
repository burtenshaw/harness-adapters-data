"""Verify and materialize the two final views from the immutable recipe revision."""

import argparse
import hashlib
import json
import os
import tempfile
from collections import Counter
from pathlib import Path
from urllib.request import urlopen

REPO = "harness-hub/harness-adapters"
REVISION = "5d320e93b7832c6c66e6a5acd8403fb1a3c50bc6"
DIGESTS = {
    "views/final_v1/train.jsonl": "13aafbf59d7ae530916cde1e37f1cc6ddc691c6b1e909cf0eb9cb3d8e150c292",
    "views/final_best_v1/train.jsonl": "ea0fd9799e2265295466b91b77dbc2a76731fd4c281fd9aa35aac51834f5f172",
}


def replay(output, snapshot=None):
    output = Path(output).absolute()
    if output.exists():
        raise FileExistsError(f"Choose a fresh baseline directory: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=output.parent) as temp:
        stage = Path(temp) / "baseline"
        views = []
        for name, digest in DIGESTS.items():
            if snapshot is None:
                url = (
                    f"https://huggingface.co/datasets/{REPO}/resolve/{REVISION}/{name}"
                )
                with urlopen(url, timeout=90) as response:
                    raw = response.read()
            else:
                raw = (Path(snapshot) / name).read_bytes()
            if hashlib.sha256(raw).hexdigest() != digest:
                raise ValueError(f"{name} differs from revision {REVISION}")
            dest = stage / name
            dest.parent.mkdir(parents=True)
            dest.write_bytes(raw)
            views.append([json.loads(line) for line in raw.splitlines()])
        tasks, best = views
        scored = [t for t in tasks if t["qwen_status"] == "scored"]
        if best != [
            t for t in scored if 0 < t["qwen_solved"] < t["qwen_valid_attempts"]
        ]:
            raise ValueError("Recomputed shortlist differs from published rows")
        summary = dict(
            repo=REPO,
            revision=REVISION,
            sha256=DIGESTS,
            tasks=len(tasks),
            origins=dict(Counter(t["task_origin"] for t in tasks)),
            scored=len(scored),
            mixed=len(best),
            scored_by_protocol=dict(Counter(t["qwen_protocol"] for t in scored)),
            training_admissible=sum(t["training_admissible"] for t in tasks),
        )
        (stage / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        stage.rename(output)
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument(
        "--snapshot", type=Path, help="Read both views from a local dataset tree"
    )
    args = parser.parse_args()
    os.umask(0o077)
    print(json.dumps(replay(args.output, args.snapshot), indent=2))
