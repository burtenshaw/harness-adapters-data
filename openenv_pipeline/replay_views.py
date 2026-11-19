"""Rebuild the correction-aware scale800 views from a captured private read set."""

import json
import re
import sys
from pathlib import Path

from run import PINS, load


def replay(args):
    operators, capture_dir, snapshots, authority_path, output = map(Path, args)
    authority = json.loads(authority_path.read_bytes())
    refresh = load(operators / "refresh.py")
    pin = PINS["operator_files_sha256"][
        "production/derived-dataset-views-corrections-v1/build.py"
    ]
    capture = refresh.load_capture(capture_dir, refresh.load_builder(pin))
    if capture["accepted"]["revision"] != authority["source_revision"]:
        raise ValueError("Accepted capture differs from the reviewed source revision")
    if capture["readset"].get("corrections_index_locator") != authority.get(
        "corrections_index_locator"
    ):
        raise ValueError("Correction authority differs from the reviewed capture")

    def read(path, revision):
        if not re.fullmatch(r"[0-9a-f]{40}", revision):
            raise ValueError("Expected full Hub commit")
        return (snapshots / revision / refresh.safe_path(path)).read_bytes()

    if authority.get("sample_locators"):
        capture["sample"] = refresh.fetch_sample(
            authority["sample_locators"], token=None, read=read
        )
    if authority.get("phase_catalog_locator"):
        capture["phase_catalog"] = refresh.fetch_phase_catalog(
            authority["phase_catalog_locator"], token=None, read=read
        )
    plan = refresh.prepare(output, capture, pin)
    expected = authority.get("expected_view_sha256")
    if expected is not None and plan["files"] != expected:
        raise ValueError("Built views differ from the historical publication")
    print(
        json.dumps({"summary": plan["summary"], "files": plan["files"]}, sort_keys=True)
    )


if __name__ == "__main__":
    replay(sys.argv[1:])
