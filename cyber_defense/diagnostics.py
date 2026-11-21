"""Measure answer format and policy decisions separately using immutable rollout receipts."""

import argparse
import base64
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re

from . import score
from .grading import canonical, reward


KEYS = {
    "cedar_authorization": "results",
    "openfga-check": "decisions",
    "openfga-list-objects": "objects",
}


def rate(numerator, denominator):
    return {
        "numerator": numerator,
        "denominator": denominator,
        "rate": numerator / denominator if denominator else None,
    }


def answer_form(text, kind, finish, key):
    """Look inside the documented key or one bare array; do not repair invalid JSON."""
    if kind == "model_refusal":
        return "refusal", None
    text = (text or "").strip()
    fence = re.fullmatch(r"```(?:json)?\s*\n(.*?)\n```", text, flags=re.I | re.S)
    try:
        value = score.strict_json(fence.group(1) if fence else text)
        canonical(value)  # also reject numbers that overflow to infinity
    except (ValueError, TypeError, OverflowError, RecursionError, UnicodeError):
        return (
            "truncated_invalid_json" if finish == "length" else "malformed_json"
        ), None
    if isinstance(value, list):
        return "bare_array", value
    if not isinstance(value, dict):
        return "wrong_top_level_type", None
    if key not in value:
        return "wrong_object_key", None
    if not isinstance(value[key], list):
        return "wrong_field_type", None
    return (
        "requested_wrapper" if set(value) == {key} else "extra_top_level_keys"
    ), value[key]


def cedar_schema(row):
    return (
        isinstance(row, dict)
        and set(row) == {"decision", "request", "determining", "errors"}
        and row["decision"] in ("allow", "deny")
        and isinstance(row["request"], str)
        and all(
            isinstance(row[k], list) and all(isinstance(v, str) for v in row[k])
            for k in ("determining", "errors")
        )
    )


def measure(family, expected, submitted, form, exact):
    """All denominators are based on valid model attempts, including unparseable answers."""
    gold = expected[KEYS[family]]
    n = Counter(valid_attempts=1, official_exact=exact)
    if form == "bare_array" and reward(expected, {KEYS[family]: submitted}):
        n["correct_after_adding_only_wrapper"] = 1
    if family == "openfga-list-objects":
        group = "empty_gold" if not gold else "nonempty_gold"
        n[group + "_attempts"] = 1
        n[group + "_exact"] = exact
        n["required_schema"] = int(
            form == "requested_wrapper" and all(isinstance(x, str) for x in submitted)
        )
        return n
    expected_count = len(gold)
    if not expected_count:
        raise ValueError("empty decision panel")
    n["expected_decisions"] = expected_count
    if submitted is None:
        return n
    if family == "openfga-check":
        is_aligned = len(submitted) == expected_count
        n["required_schema"] = int(
            form == "requested_wrapper"
            and is_aligned
            and all(isinstance(x, bool) for x in submitted)
        )
        if is_aligned:
            for x, y in zip(submitted, gold, strict=True):
                if type(x) is bool:
                    n["recovered_decisions"] += 1
                    n["correct_decisions"] += int(x is y)
    else:
        n["required_schema"] = int(
            form == "requested_wrapper"
            and len(submitted) == expected_count
            and all(cedar_schema(row) for row in submitted)
        )
        by_id = defaultdict(list)
        for row in submitted:
            if isinstance(row, dict) and isinstance(row.get("request"), str):
                by_id[row["request"]].append(row)
        for row in gold:
            matches = by_id[row["request"]]
            if len(matches) != 1:
                continue
            answer = matches[0]
            if answer.get("decision") in ("allow", "deny"):
                n["recovered_decisions"] += 1
                n["correct_decisions"] += int(answer["decision"] == row["decision"])
            for field in ("determining", "errors"):
                ids = answer.get(field)
                if isinstance(ids, list) and all(isinstance(x, str) for x in ids):
                    n[field + "_recovered"] += 1
                    n[field + "_correct"] += int(ids == row[field])
    n["all_decisions_recovered"] = int(n["recovered_decisions"] == expected_count)
    all_correct = n["correct_decisions"] == expected_count
    n["all_decisions_correct"] = int(all_correct)
    n["all_decisions_correct_official_failed"] = int(all_correct and not exact)
    if all_correct and not exact:
        n["decisions_correct_failed_official_with_" + form] = 1
    return n


def baseline(tasks, family):
    """Compute simple predictors once per distinct task on the entire sealed cohort."""
    answers = [t["answer"][KEYS[family]] for t in tasks]
    n = len(tasks)
    if not n:
        return None
    counts = Counter(canonical(t["answer"]) for t in tasks)
    most_frequent = max(counts.values())
    result = {
        "task_count": n,
        "distinct_gold_answer_objects": len(counts),
        "empirical_most_frequent_whole_answer": rate(most_frequent, n),
        "number_of_modes": sum(v == most_frequent for v in counts.values()),
    }
    if family == "openfga-list-objects":
        result["always_empty_objects_exact_panels"] = rate(
            sum(not a for a in answers), n
        )
        return result
    if family == "openfga-check":
        for label in (False, True):
            name = "all_true" if label else "all_false"
            result[name] = {
                "exact_panels": rate(
                    sum(all(x is label for x in a) for a in answers), n
                ),
                "correct_decisions": rate(
                    sum(x is label for a in answers for x in a), sum(map(len, answers))
                ),
            }
    else:
        for label in ("allow", "deny"):

            def fixed(rows):
                return [
                    {
                        "decision": label,
                        "request": row["request"],
                        "determining": [],
                        "errors": [],
                    }
                    for row in rows
                ]

            result["all_" + label + "_empty_policy_lists"] = {
                "exact_panels": rate(sum(fixed(a) == a for a in answers), n),
                "correct_decision_panels": rate(
                    sum(all(x["decision"] == label for x in a) for a in answers), n
                ),
                "correct_decisions": rate(
                    sum(x["decision"] == label for a in answers for x in a),
                    sum(map(len, answers)),
                ),
            }
    return result


def family_report(tasks, family, counts, forms, outcomes, slots):
    valid = counts["valid_attempts"]
    result = {
        "gold_baselines": baseline(tasks, family),
        "planned_attempts": len(tasks) * slots,
        "valid_model_attempts": valid,
        "infrastructure_incomplete_slots": sum(
            v for k, v in outcomes.items() if k != "pending"
        )
        - valid,
        "pending_slots": outcomes["pending"],
        "official_outcomes": dict(outcomes),
        "answer_forms": dict(forms),
        "requested_wrapper_with_wrong_inner_types_or_length": forms["requested_wrapper"]
        - counts["required_schema"],
        "official_exact_panel_rate": rate(counts["official_exact"], valid),
        "required_wrapper_and_field_types": rate(counts["required_schema"], valid),
        "exact_after_adding_only_the_missing_wrapper": rate(
            counts["correct_after_adding_only_wrapper"], valid
        ),
    }
    if family == "openfga-list-objects":
        result["official_exact_by_gold_list"] = {
            name: rate(counts[name + "_exact"], counts[name + "_attempts"])
            for name in ("empty_gold", "nonempty_gold")
        }
        return result
    total = counts["expected_decisions"]
    recovered = counts["recovered_decisions"]
    result["decisions_only"] = {
        "decision_recovery": rate(recovered, total),
        "correct_among_all_expected": rate(counts["correct_decisions"], total),
        "correct_among_recovered": rate(counts["correct_decisions"], recovered),
        "all_expected_panel_decisions_correct": rate(
            counts["all_decisions_correct"], valid
        ),
        "all_correct_among_fully_recovered_panels": rate(
            counts["all_decisions_correct"], counts["all_decisions_recovered"]
        ),
        "all_decisions_correct_but_official_failed": rate(
            counts["all_decisions_correct_official_failed"], valid
        ),
        "forms_when_all_decisions_correct_but_official_failed": {
            k.removeprefix("decisions_correct_failed_official_with_"): v
            for k, v in counts.items()
            if k.startswith("decisions_correct_failed_official_with_")
        },
    }
    if family == "cedar_authorization":
        result["policy_id_lists_exact_per_request"] = {
            field: {
                "correct_among_all_expected": rate(counts[field + "_correct"], total),
                "correct_among_recovered": rate(
                    counts[field + "_correct"], counts[field + "_recovered"]
                ),
            }
            for field in ("determining", "errors")
        }
    return result


def report(rollouts, partial):
    manifest = score.read(rollouts / "protocol.json")
    raw = (rollouts / "sealed-tasks.jsonl").read_bytes()
    if score.digest(raw) != manifest["input_sha256"]:
        raise ValueError("sealed population hash mismatch")
    tasks = score.load_tasks(raw)
    slots = manifest["slots"]
    if (
        manifest["protocol"] != score.protocol_id(slots)
        or len(tasks) != manifest["task_count"]
        or score.digest(Path(score.__file__).read_bytes()) != manifest["scorer_sha256"]
    ):
        raise ValueError(
            "diagnostic replay requires the matching scorer and sealed cohort"
        )
    digest = hashlib.sha256()
    seen = set()
    orphaned_ids = set()
    orphaned = []
    grouped, metrics, forms, outcomes = (
        defaultdict(list),
        defaultdict(Counter),
        defaultdict(Counter),
        defaultdict(Counter),
    )
    observed_tasks = defaultdict(list)
    fully_scored_tasks = defaultdict(list)
    distributions = defaultdict(Counter)
    dispatch = defaultdict(Counter)
    mixed_ids = defaultdict(list)
    observed_counts = defaultdict(Counter)
    for index, task in enumerate(tasks):
        family, gold = task["family"], task["answer"]
        grouped[family].append(task)
        sha = score.digest(canonical(score.body_for(task)))
        if sha != score.digest(
            (rollouts / "requests" / f"{index:05d}.json").read_bytes()
        ):
            raise ValueError("saved request differs from the sealed case")
        valid_task = wins_task = claimed_task = 0
        for slot in range(slots):
            row = score.audited_attempt(rollouts, index, task, slot, sha, slots)
            outcome = "pending" if row is None else row["kind"]
            outcomes[family][outcome] += 1
            if row is None:
                directory = score.record_dir(rollouts, index, slot)
                if (directory / "1.request.json").exists():
                    claimed_task += 1
                    dispatch[family]["claimed_without_final"] += 1
                    responses = sorted(directory.glob("*.response.json"))
                    if responses:
                        dispatch[family]["has_any_response_without_final"] += 1
                    for unfinished in responses:
                        ordinal = int(unfinished.name.split(".")[0])
                        claim = score.read(directory / f"{ordinal}.request.json")
                        resp = score.read(unfinished)
                        binding = score.address(index, task, slot, ordinal, sha, slots)
                        if claim["binding"] != binding or resp["binding"] != binding:
                            raise ValueError("unfinalized response binding mismatch")
                        result = score.grade(resp, gold)
                        if result["reward"] is not None:
                            cid = result["completion_id"]
                            if cid in orphaned_ids:
                                raise ValueError("duplicate unfinalized completion")
                            orphaned_ids.add(cid)
                            orphaned.append(
                                {
                                    **binding,
                                    "completion_id": cid,
                                    "response_sha256": score.digest(
                                        unfinished.read_bytes()
                                    ),
                                    "kind": result["kind"],
                                    "reward": result["reward"],
                                }
                            )
                else:
                    dispatch[family]["no_claim"] += 1
            else:
                claimed_task += 1
            if row is None or row["reward"] is None:
                if not partial:
                    raise ValueError(
                        "unmeasured slots remain; pass --partial for a progress snapshot"
                    )
                continue
            valid_task += 1
            wins_task += row["reward"]
            observed_tasks[family].append(task)
            cid = row["completion_id"]
            if cid in seen:
                raise ValueError("reused provider completion ID")
            seen.add(cid)
            digest.update(
                canonical([index, slot, row["receipt_sha256"], row["reward"]]) + b"\n"
            )
            directory = score.record_dir(rollouts, index, slot)
            receipt = score.read(directory / f"{row['provider_call']}.response.json")
            body = score.strict_json(
                base64.b64decode(receipt["body_base64"], validate=True)
            )
            content = body["choices"][0]["message"].get("content")
            shape, answer = answer_form(
                content, outcome, row["finish_reason"], KEYS[family]
            )
            forms[family][shape] += 1
            metrics[family].update(measure(family, gold, answer, shape, row["reward"]))
        observed_counts[family]["tasks_with_any_claim"] += int(claimed_task > 0)
        if valid_task == slots:
            fully_scored_tasks[family].append(task)
            distributions[family][wins_task] += 1
            if 0 < wins_task < slots:
                mixed_ids[family].append(task["task_id"])
        elif valid_task:
            observed_counts[family]["partly_measured_tasks"] += 1
        else:
            observed_counts[family]["zero_valid_rollout_tasks"] += 1
    if seen & orphaned_ids:
        raise ValueError("completion appears as both finalized and unfinalized")
    families = {}
    for family, family_tasks in grouped.items():
        detail = family_report(
            family_tasks,
            family,
            metrics[family],
            forms[family],
            outcomes[family],
            slots,
        )
        histogram = distributions[family]
        detail["task_coverage"] = {
            "tasks_with_any_dispatch_claim": observed_counts[family][
                "tasks_with_any_claim"
            ],
            "fully_measured_tasks": len(fully_scored_tasks[family]),
            "partly_measured_tasks": observed_counts[family]["partly_measured_tasks"],
            "zero_valid_rollout_tasks": observed_counts[family][
                "zero_valid_rollout_tasks"
            ],
            "fully_measured_never_solved": histogram[0],
            "fully_measured_always_solved": histogram[slots],
            "fully_measured_mixed_success": len(mixed_ids[family]),
            "fully_measured_solve_count_histogram": {
                str(i): histogram[i] for i in range(slots + 1)
            },
            "fully_measured_mixed_task_ids": mixed_ids[family],
        }
        detail["unfinished_slot_claims"] = {
            key: dispatch[family][key]
            for key in (
                "no_claim",
                "claimed_without_final",
                "has_any_response_without_final",
            )
        }
        detail["gold_baselines_fully_measured_tasks"] = baseline(
            fully_scored_tasks[family], family
        )
        detail["gold_baselines_observed_attempt_weighting"] = baseline(
            observed_tasks[family], family
        )
        families[family] = detail
    return {
        "protocol": manifest["protocol"],
        "population_sha256": manifest["input_sha256"],
        "diagnostics_source_sha256": score.digest(Path(__file__).read_bytes()),
        "mode": "partial" if partial else "final",
        "scorer_sha256": manifest["scorer_sha256"],
        "observed_valid_attempt_receipts_sha256": digest.hexdigest(),
        "slots_per_task": slots,
        "planned_attempts": len(tasks) * slots,
        "valid_attempts_observed": len(seen),
        "bound_provider_completions_without_a_final_grade": orphaned,
        "distinct_bound_provider_completions_including_unfinalized": len(seen)
        + len(orphaned_ids),
        "interpretation": {
            "official": "Exact typed JSON score replayed from each final provider receipt. All model completions, including unusable output, enter the denominator.",
            "forms": "Accept one JSON value or one full JSON code fence; recover arrays under the requested key and bare top-level arrays. Never search prose or guess an alternative key.",
            "cedar": "Align decisions by unique matching request ID; allow only exact allow/deny strings. Ignore row order, extra IDs and policy lists only in decision diagnostics. Full policy-list metrics retain ID array order.",
            "openfga_check": "Align by position only if array length exactly matches the number of checks; accept only JSON booleans.",
            "baselines": "The full-cohort and fully measured baselines count each task once. The observed-attempt baseline repeats each task by its number of valid model attempts. The most-frequent whole answer is an empirical mode; fixed predictors use public response dimensions.",
            "partial": "A partial scan uses immutable final records visible as each slot is read. It is a progress snapshot, not a randomized sample.",
        },
        "families": families,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rollouts", type=Path)
    parser.add_argument("--partial", action="store_true")
    args = parser.parse_args()
    result = report(args.rollouts, args.partial)
    path = args.rollouts.parent / (
        "diagnostics-partial.json" if args.partial else "diagnostics.json"
    )
    score.save(
        path,
        json.dumps(result, indent=2, sort_keys=True).encode() + b"\n",
        replace=True,
    )
    print(
        f"{path}: {result['valid_attempts_observed']}/{result['planned_attempts']} valid attempts"
    )


if __name__ == "__main__":
    main()
