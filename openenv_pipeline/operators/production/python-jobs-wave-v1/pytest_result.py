"""Distinguish real pytest failures from missing/setup/verifier evidence."""

import argparse
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path


def matches(case, target):
    parts = target.split("::")
    module = parts[0].removesuffix(".py").replace("/", ".")
    classname = case.get("classname", "")
    name = case.get("name", "")
    if not (classname == module or classname.startswith(module + ".")):
        return False
    selector = parts[-1] if len(parts) > 1 else ""
    classes = parts[1:-1]
    if classes and classname != module + "." + ".".join(classes):
        return False
    return (
        not selector
        or name == selector
        or ("[" not in selector and name.startswith(selector + "["))
    )


def assess(root, expected, native_exit):
    all_cases = []
    actual_failure = False
    for group in ("pass-to-pass", "fail-to-pass"):
        path = Path(root) / (group + ".xml")
        if not path.exists():
            if actual_failure:
                continue
            raise ValueError("Missing preceding pytest panel")
        if actual_failure:
            raise ValueError(
                "Pytest evidence continued after the native stop-on-failure"
            )
        raw = path.read_bytes()
        if not 0 < len(raw) <= 4 * 1024**2 or re.search(
            rb"<!\s*(?:DOCTYPE|ENTITY)", raw, re.I
        ):
            raise ValueError("Unbounded or unsafe pytest XML")
        tree = ET.fromstring(raw)
        cases = list(tree.iter("testcase"))
        if len(cases) > 20000:
            raise ValueError("Too many pytest cases")
        identities = [(c.get("classname"), c.get("name")) for c in cases]
        if len(identities) != len(set(identities)):
            raise ValueError("Duplicate pytest case evidence")
        targets = expected[group]
        if any(not any(matches(case, t) for t in targets) for case in cases):
            raise ValueError("Unexpected pytest case")
        all_cases.extend(cases)
        failures = [c for c in cases if c.find("failure") is not None]
        if any(
            c.find("error") is not None or c.find("skipped") is not None for c in cases
        ):
            raise ValueError("Pytest collection/error/skip is not a completed panel")
        actual_failure = actual_failure or bool(failures)
        if not failures and any(
            not any(matches(case, t) for case in cases) for t in targets
        ):
            raise ValueError("Declared pytest target never ran")
    if actual_failure:
        if native_exit == 0:
            raise ValueError("Native verifier exit disagrees with pytest failure")
        return {"reward": 0, "valid_test_failure": True, "cases": len(all_cases)}
    if native_exit != 0:
        raise ValueError("Setup or native verifier failed without a real test failure")
    for group in ("pass-to-pass", "fail-to-pass"):
        if not (Path(root) / (group + ".xml")).is_file():
            raise ValueError("Missing completed pytest panel")
    return {"reward": 1, "valid_test_failure": False, "cases": len(all_cases)}


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--root", required=True)
    p.add_argument("--expected", required=True)
    p.add_argument("--native-exit", type=int, required=True)
    a = p.parse_args()
    result = assess(a.root, json.loads(Path(a.expected).read_text()), a.native_exit)
    reward = Path(a.root) / "reward.txt"
    if reward.read_text().strip() != str(result["reward"]):
        raise ValueError("Native raw reward disagrees with pytest evidence")
    (Path(a.root) / "pytest-evidence.json").write_text(
        json.dumps(result, sort_keys=True) + "\n"
    )
