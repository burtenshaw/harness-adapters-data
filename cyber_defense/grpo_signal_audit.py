"""Audit the type of observed reward variation in fully measured Cedar task groups."""

import argparse
import base64
from collections import Counter
import hashlib
import json
from pathlib import Path
import re

from . import score
from .diagnostics import answer_form, cedar_schema
from .grading import canonical


def failure(task, body, final):
    gold = task["answer"]["results"]
    choice = body["choices"][0]
    shape, rows = answer_form(
        choice["message"].get("content"),
        final["kind"],
        choice["finish_reason"],
        "results",
    )
    detail = {"slot": final["slot"], "form": shape}
    if rows is None:
        return {**detail, "category": "unreadable_or_truncated"}
    if not all(cedar_schema(r) for r in rows):
        return {**detail, "category": "ambiguous_schema_or_request_identity"}
    order = [r["request"] for r in rows]
    expected_order = [g["request"] for g in gold]
    if len(order) != len(set(order)) or set(order) != set(expected_order):
        return {**detail, "category": "ambiguous_schema_or_request_identity"}
    mapping = {r["request"]: r for r in rows}
    policy_ids = set(re.findall(r"(?m)^(policy[0-9]+)$", task["prompt"]))
    if len(policy_ids) != len(task["policy_sha256"]):
        raise ValueError("Could not identify all named source policies")
    for g in gold:
        if any(set(g[k]) - policy_ids for k in ("determining", "errors")):
            raise ValueError("Gold refers to a missing source policy")
    decision_diff = []
    policy_diff = []
    corrections = []
    if shape != "requested_wrapper":
        corrections.append(shape)
    if order != expected_order:
        corrections.append("request_order")
    unknown = False
    duplicates = False
    unsorted = False
    for g in gold:
        req = g["request"]
        r = mapping[req]
        if r["decision"] != g["decision"]:
            decision_diff.append(req)
        for field in ("determining", "errors"):
            supplied, target = r[field], g[field]
            duplicates |= len(supplied) != len(set(supplied))
            unsorted |= supplied != sorted(supplied)
            unknown |= bool(set(supplied) - policy_ids)
            if set(supplied) != set(target):
                policy_diff.append(f"{req}.{field}")
    if unsorted:
        corrections.append("policy_id_order")
    if duplicates:
        corrections.append("repeated_policy_id")
    if unknown:
        corrections.append("unknown_policy_id")
    if corrections:
        detail["noncanonical"] = corrections
    if decision_diff:
        detail["wrong_decision_request_ids"] = decision_diff
    if policy_diff:
        detail["wrong_policy_membership_fields"] = policy_diff

    # Require the exact wrapper and request ordering, sorted distinct ID lists and
    # only IDs that exist in the public scenario before calling a miss a clean contrast.
    if not corrections:
        if decision_diff:
            return {**detail, "category": "ordered_wrong_decision"}
        if policy_diff:
            return {
                **detail,
                "category": "ordered_correct_decisions_wrong_policy_membership",
            }
        raise ValueError(
            "Semantically and structurally exact response received reward zero"
        )
    if not decision_diff and not policy_diff and not duplicates and not unknown:
        return {**detail, "category": "only_wrapper_or_order"}
    if decision_diff or (policy_diff and not unknown):
        return {**detail, "category": "recoverable_semantic_error_with_format_issue"}
    return {**detail, "category": "ambiguous_policy_id_or_schema"}


def group_category(kinds):
    decision = "ordered_wrong_decision" in kinds
    policy = "ordered_correct_decisions_wrong_policy_membership" in kinds
    if decision and policy:
        return "clean_decision_and_separate_policy_miss"
    if decision:
        return "clean_decision_miss"
    if policy:
        return "clean_policy_membership_miss"
    if "recoverable_semantic_error_with_format_issue" in kinds:
        return "semantic_difference_only_in_noncanonical_responses"
    if kinds == {"only_wrapper_or_order"}:
        return "all_failures_proven_wrapper_or_order_only"
    if kinds <= {"only_wrapper_or_order", "unreadable_or_truncated"}:
        return "only_format_or_unreadable_observed_semantics_uncertain"
    return "ambiguous_schema_or_policy_identity"


def report(rollouts):
    manifest = score.read(rollouts / "protocol.json")
    raw = (rollouts / "sealed-tasks.jsonl").read_bytes()
    if (
        score.digest(raw) != manifest["input_sha256"]
        or score.digest(Path(score.__file__).read_bytes()) != manifest["scorer_sha256"]
        or manifest["protocol"] != score.protocol_id(8)
        or manifest["slots"] != 8
    ):
        raise ValueError("Cohort or scoring protocol mismatch")
    tasks = score.load_tasks(raw)
    if len(tasks) != manifest["task_count"]:
        raise ValueError("Cohort size mismatch")
    seen = set()
    bound = hashlib.sha256()
    groups = []
    family_tasks = complete = 0
    outcomes, memberships, failure_counts = Counter(), Counter(), Counter()
    for index, task in enumerate(tasks):
        if task["family"] != "cedar_authorization":
            continue
        family_tasks += 1
        req = canonical(score.body_for(task))
        if req != (rollouts / "requests" / f"{index:05}.json").read_bytes():
            raise ValueError("Request differs from bound prompt")
        sha = score.digest(req)
        rows = []
        for slot in range(8):
            final = score.audited_attempt(rollouts, index, task, slot, sha, 8)
            if final is None or final["reward"] is None:
                continue
            cid = final["completion_id"]
            if cid in seen:
                raise ValueError("Repeated provider completion")
            seen.add(cid)
            rows.append(final)
        if len(rows) != 8:
            continue
        complete += 1
        num_correct = sum(row["reward"] for row in rows)
        if num_correct in (0, 8):
            continue
        failures, receipts = [], []
        for row in rows:
            slot, ordinal = row["slot"], row["provider_call"]
            receipts.append([slot, ordinal, row["receipt_sha256"], row["reward"]])
            if row["reward"]:
                continue
            p = score.record_dir(rollouts, index, slot) / f"{ordinal}.response.json"
            receipt = score.read(p)
            body = score.strict_json(
                base64.b64decode(receipt["body_base64"], validate=True)
            )
            failures.append(failure(task, body, row))
        bound.update(canonical([index, task["task_sha256"], receipts]) + b"\n")
        kinds = {f["category"] for f in failures}
        category = group_category(kinds)
        failure_counts.update(f["category"] for f in failures)
        memberships.update(kinds)
        outcomes[category] += 1
        groups.append(
            {
                "task_id": task["task_id"],
                "task_sha256": task["task_sha256"],
                "input_index": index,
                "exact_pass_slots": [r["slot"] for r in rows if r["reward"] == 1],
                "classification": category,
                "failures": failures,
                "receipt_set_sha256": score.digest(canonical(receipts)),
            }
        )
    histogram = Counter(len(g["exact_pass_slots"]) for g in groups)
    decision = memberships["ordered_wrong_decision"]
    policy = memberships["ordered_correct_decisions_wrong_policy_membership"]
    overlap = outcomes["clean_decision_and_separate_policy_miss"]
    return {
        "population_sha256": manifest["input_sha256"],
        "scorer_sha256": manifest["scorer_sha256"],
        "audit_source_sha256": score.digest(Path(__file__).read_bytes()),
        "protocol": manifest["protocol"],
        "bound_mixed_group_receipts_sha256": bound.hexdigest(),
        "cedar_tasks": family_tasks,
        "fully_measured_cedar_tasks": complete,
        "mixed_tasks": len(groups),
        "mixed_group_attempts": 8 * len(groups),
        "exact_passes_in_mixed_groups": sum(k * v for k, v in histogram.items()),
        "mixed_group_solve_count_histogram": dict(sorted(histogram.items())),
        "groups_with_clean_wrong_decision": decision,
        "groups_with_clean_wrong_policy_membership_and_correct_decisions": policy,
        "groups_with_both_kinds_in_distinct_responses": overlap,
        "additional_policy_only_groups": policy - overlap,
        "groups_with_either_clean_semantic_contrast": decision + policy - overlap,
        "group_classification_disjoint": dict(outcomes),
        "attempt_failure_classes": dict(failure_counts),
        "tasks": groups,
        "interpretation": {
            "cohort": "Include only Cedar tasks with eight bound, graded responses and exact successes and failures.",
            "clean_wrong_decision": "Correct object wrapper, full row schema, correct request IDs in order, sorted distinct policy lists containing only scenario IDs, and at least one incorrect allow/deny decision.",
            "clean_policy_membership": "Same structural constraints, all authorization decisions correct, and at least one incorrect set of determining or errored named policies. This is an observable policy-answer attribution error; the model's internal reasoning is unobserved.",
            "format_only": "The expected values become exactly equal by adding a missing wrapper, removing extra top-level keys, reordering rows by their explicit IDs, or sorting policy IDs. Duplicate IDs are never removed.",
            "unknown": "Unparseable, truncated, ambiguous IDs and incomplete submissions give insufficient evidence to recover all intended policy decisions. Reward variance alone does not establish learning or benchmark transfer.",
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rollouts", type=Path)
    root = parser.parse_args().rollouts
    result = report(root)
    path = root.parent / "grpo-signal-audit.json"
    score.save(
        path,
        json.dumps(result, sort_keys=True, indent=2).encode() + b"\n",
        replace=True,
    )
    print(
        json.dumps(
            {k: v for k, v in result.items() if k not in ("tasks", "interpretation")},
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
