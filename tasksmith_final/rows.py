"""Wire schema and Wilson interval from the original final view builder."""

import hashlib
import math

PROTOCOL = "qwen38-terminus2-hfsandbox-64k-2m-nothink-tasksmith-v1"

ORIGIN = {
    "SWE-bench/SWE-smith-go": "swe-smith-go",
    "SWE-bench/SWE-smith-py": "swe-smith-py",
    "open-thoughts/TaskTrove": "swegym-tasktrove",
}
MOD_COLUMNS = [
    "network_enabled",
    "original_network_mode",
    "users_dropped",
    "task_modified_for_hf_sandbox",
]


def wilson(k, n, z=1.959963984540054):
    p = k / n
    center = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return max(0.0, center - half), min(1.0, center + half)


def task_row(
    *, task_id, task_dir, mod, src, split, records, prefix, revision, inventory_bytes
):
    valid = [record for record in records if record["valid"]]
    n = len(valid)
    solved = sum(record["solved"] for record in valid)
    status = "scored" if n == 8 else ("incomplete" if n else "not_started")
    lo, hi = wilson(solved, n) if n else (None, None)
    owner, repo = src["source_repo"].removeprefix("https://github.com/").split("/")[:2]
    instruction = (task_dir / "instruction.md").read_text()
    return {
        "adapter_backend_path": None,
        "adapter_implementation_path": None,
        "adapter_kind": None,
        "adapter_module_hashes_path": None,
        "adapter_plan_schema": None,
        "adapter_restore_path": None,
        "adapter_seed_sha256": None,
        "cloud_launch_ready": True,
        "dependency_lock_sha256": None,
        "difficulty_status": "unmeasured",
        "evaluation_only": False,
        "execution_path": f"{prefix}/validation/{task_id}/harbor-evidence.json",
        "gate_passed": True,
        "gate_report_path": f"{prefix}/validation/{task_id}/report.json",
        "generated_alternatives_run": False,
        "generated_reference": False,
        "image_pull_qualified": True,
        "image_receipt_path": f"{prefix}/images/{task_id}.json",
        "in_stratified_sample": False,
        "instruction": instruction,
        "language": "python",
        "leak_audit_run": False,
        "provenance_path": src["provenance_path"],
        "provided_reference": True,
        "provider_image_source_attestation": False,
        "qwen_difficulty": None if not n else 1 - solved / n,
        "qwen_protocol": PROTOCOL,
        "qwen_solve_rate": None if not n else solved / n,
        "qwen_solved": solved if n else None,
        "qwen_status": status,
        "qwen_valid_attempts": n if n else None,
        "qwen_wilson95_high": hi,
        "qwen_wilson95_low": lo,
        "rfc008_complete": False,
        "semantic_nonoverlap_established": False,
        "source_commit": src["source_head_commit"],
        "source_dataset": split,
        "source_license_spdx": src["source_license_spdx"],
        "source_pr_url": src["source_pr_url"],
        "source_repo": src["source_repo"],
        "source_revision": revision,
        "source_split": src["split"],
        "target_model": "Qwen/Qwen3.8-27B",
        "target_model_calibrated": False,
        "task_bundle_license_spdx": None,
        "task_file_inventory_path": f"{prefix}/inventories/{task_id}.json",
        "task_id": task_id,
        "task_inventory_sha256": hashlib.sha256(inventory_bytes).hexdigest(),
        "task_path": mod["path"],
        "task_source_sha256": mod["original_source_digest"],
        "terminal_proof_path": None,
        "trainability_established": False,
        "training_admissible": False,
        "upstream_repo": f"{owner}/{repo}".lower(),
        "usage": "quarantine_only",
        "validation_profile": "harbor-semantic-v1-hf-sandbox",
        "verified": False,
    }
