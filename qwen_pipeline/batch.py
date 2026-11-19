"""Estimate or submit one frozen target-only cohort with the recovered prepared_batch CLI."""

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def batch_output(root, submit, manifest_sha):
    name = "submitted" if submit else "estimate"
    attempt = 1
    output = root / name
    while output.exists():
        if submit:
            prior = json.loads((output / "manifest.json").read_bytes())
            if not (
                prior["prepared_manifest"]["sha256"] == manifest_sha
                and prior["stage"] == "budget"
                and prior["status"] == "failed"
                and prior["within_budget"] is False
                and prior["shared_spend"]["status"] == "not_reserved"
            ):
                raise ValueError(f"Review the existing submission evidence in {output}")
        attempt += 1
        output = root / f"{name}-{attempt}"
    return output


def batch(args):
    root = args.run.resolve()
    receipt = root / "prepared.json"
    if sha(receipt) != args.prepared_sha256:
        raise ValueError("The preparation receipt differs from the supplied digest")
    prep = json.loads(receipt.read_bytes())
    operator = Path(prep["operator"]).resolve()
    manifest = Path(prep["prepared_manifest"]).resolve()
    if not operator.is_relative_to(root / "bulk-v1") or not manifest.is_relative_to(
        root / "cycles"
    ):
        raise ValueError("The receipt must name the operator and manifest in this run")
    build = operator / prep["build_receipt"]
    if (
        build.parent != operator
        or sha(build) != prep["build_receipt_sha256"]
        or sha(manifest) != prep["manifest_sha256"]
    ):
        raise ValueError("Compiled worker or prepared manifest changed")
    # Check the actual Python imports before invoking the original batch entry point.
    files = json.loads(build.read_bytes())["files"]
    actual = {
        str(p.relative_to(operator))
        for p in operator.rglob("*")
        if p.is_file() and "__pycache__" not in p.parts
    }
    if actual != set(files) | {build.name} or any(
        sha(operator / name) != h for name, h in files.items()
    ):
        raise ValueError("Compiled operator differs from its checked inventory")
    output = batch_output(root, args.submit, prep["manifest_sha256"])
    command = [
        sys.executable,
        "-B",
        "-m",
        "examples.hub_validation_pipeline.prepared_batch",
        "--prepared-manifest",
        str(manifest),
        "--prepared-manifest-sha256",
        prep["manifest_sha256"],
        "--output",
        str(output),
        "--spend-ledger",
        str(args.ledger.resolve()),
        "--reservation-id",
        "qwen-" + prep["measurement_key"],
        "--budget-usd",
        args.budget_usd,
        "--max-parallel",
        "1",
    ]
    if args.submit:
        command.append("--submit")
    subprocess.run(
        command,
        cwd=operator,
        check=True,
        env=dict(
            os.environ,
            PYTHONPATH=os.pathsep.join(
                map(str, [operator, operator / "src", root, root / "bulk-v1"])
            ),
            PYTHONDONTWRITEBYTECODE="1",
        ),
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    parser.add_argument("--prepared-sha256", required=True)
    parser.add_argument(
        "--ledger",
        type=Path,
        required=True,
        help="New campaign ledger, initialized before submission",
    )
    parser.add_argument("--budget-usd", required=True)
    parser.add_argument(
        "--submit",
        action="store_true",
        help="Write private worker inputs and start billable HF Jobs",
    )
    os.umask(0o077)
    batch(parser.parse_args())
