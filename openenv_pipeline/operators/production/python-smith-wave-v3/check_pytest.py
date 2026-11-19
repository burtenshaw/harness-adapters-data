"""Preserve confirmed requested assertion failures; keep positive checks strict."""

import argparse
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

GROUPS = ("pass-to-pass", "fail-to-pass")


def split_nodeid(target):
    prefix, bracket, parameter = target.partition("[")
    parts = prefix.split("::")
    if bracket:
        parts[-1] += bracket + parameter
    return parts


def matches(case, target):
    parts = split_nodeid(target)
    module = parts[0].removesuffix(".py").replace("/", ".")
    classname, name = case.get("classname", ""), case.get("name", "")
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


def capture_panels(root):
    panels, digests = {}, {}
    for group in GROUPS:
        path = Path(root) / (group + ".xml")
        if not path.exists():
            panels[group] = None
            continue
        with path.open("rb") as stream:
            raw = stream.read(4 * 1024**2 + 1)
        if not 0 < len(raw) <= 4 * 1024**2 or re.search(
            rb"<!\s*(?:DOCTYPE|ENTITY)", raw, re.I
        ):
            raise ValueError("Unbounded or unsafe pytest XML")
        try:
            tree = ET.fromstring(raw)
        except ET.ParseError:
            raise ValueError("Malformed pytest XML") from None
        cases = list(tree.iter("testcase"))
        if len(cases) > 20000:
            raise ValueError("Too many pytest cases")
        identities = [(case.get("classname"), case.get("name")) for case in cases]
        if len(identities) != len(set(identities)):
            raise ValueError("Duplicate pytest case evidence")
        panels[group] = cases
        digests[group] = hashlib.sha256(raw).hexdigest()
    return panels, digests


def strict_assess(panels, expected, native_exit):
    """The original positive-approval conditions, applied to captured cases."""
    all_cases, actual_failure = [], False
    for group in GROUPS:
        cases = panels[group]
        if cases is None:
            if actual_failure:
                continue
            raise ValueError("Missing preceding pytest panel")
        if actual_failure:
            raise ValueError(
                "Pytest evidence continued after the native stop-on-failure"
            )
        targets = expected[group]
        if any(not any(matches(case, target) for target in targets) for case in cases):
            raise ValueError("Unexpected pytest case")
        all_cases.extend(cases)
        failures = [case for case in cases if case.find("failure") is not None]
        if any(
            case.find("error") is not None or case.find("skipped") is not None
            for case in cases
        ):
            raise ValueError("Pytest collection/error/skip is not a completed panel")
        actual_failure = actual_failure or bool(failures)
        if not failures and any(
            not any(matches(case, target) for case in cases) for target in targets
        ):
            raise ValueError("Declared pytest target never ran")
    if actual_failure:
        if native_exit == 0:
            raise ValueError("Native verifier exit disagrees with pytest failure")
        return {"reward": 0, "valid_test_failure": True, "cases": len(all_cases)}
    if native_exit != 0:
        raise ValueError("Setup or native verifier failed without a real test failure")
    if any(panels[group] is None for group in GROUPS):
        raise ValueError("Missing completed pytest panel")
    return {"reward": 1, "valid_test_failure": False, "cases": len(all_cases)}


def assess(root, expected, native_exit):
    if type(native_exit) is not int:
        raise ValueError("Native verifier exit must be an integer")
    if not isinstance(expected, dict) or any(
        not isinstance(expected.get(group), list)
        or not expected[group]
        or any(not isinstance(target, str) or not target for target in expected[group])
        for group in GROUPS
    ):
        raise ValueError("Complete exact native pytest targets required")
    panels, digests = capture_panels(root)
    counts = {
        "cases": 0,
        "matched_failures": 0,
        "unexpected_cases": 0,
        "unmatched_failures": 0,
        "skipped_cases": 0,
        "error_cases": 0,
        "missing_panels": 0,
        "missing_targets": 0,
    }
    for group in GROUPS:
        cases = panels[group]
        if cases is None:
            counts["missing_panels"] += 1
            counts["missing_targets"] += len(expected[group])
            continue
        counts["cases"] += len(cases)
        for case in cases:
            requested = any(matches(case, target) for target in expected[group])
            failure = case.find("failure") is not None
            counts["matched_failures"] += int(requested and failure)
            counts["unmatched_failures"] += int(not requested and failure)
            counts["unexpected_cases"] += int(not requested)
            counts["skipped_cases"] += int(case.find("skipped") is not None)
            counts["error_cases"] += int(case.find("error") is not None)
        counts["missing_targets"] += sum(
            not any(matches(case, target) for case in cases)
            for target in expected[group]
        )
    if counts["matched_failures"]:
        if native_exit == 0:
            raise ValueError(
                "Native verifier exit disagrees with requested pytest failure"
            )
        return {
            "reward": 0,
            "valid_test_failure": True,
            "cases": counts["cases"],
            "diagnostic_counts": counts,
            "panel_sha256": digests,
            "decision": "confirmed_requested_failure_precedence",
        }
    result = strict_assess(panels, expected, native_exit)
    result.update(diagnostic_counts=counts, panel_sha256=digests)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--expected", required=True)
    parser.add_argument("--native-exit", type=int, required=True)
    args = parser.parse_args()
    result = assess(
        args.root, json.loads(Path(args.expected).read_bytes()), args.native_exit
    )
    reward = Path(args.root) / "reward.txt"
    if reward.read_text().strip() != str(result["reward"]):
        raise ValueError("Native raw reward disagrees with pytest evidence")
    (Path(args.root) / "pytest-evidence.json").write_text(
        json.dumps(result, sort_keys=True) + "\n"
    )
