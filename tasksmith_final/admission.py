"""Bind a Tasksmith paid stage to a reviewed plan and an OpenEnv shared-ledger reservation."""

import argparse
import hashlib
import json
import math
from decimal import Decimal
from pathlib import Path
from types import ModuleType

from common import read, require, sha, write

HERE = Path(__file__).resolve().parent
DEFAULT_SPEND = HERE.parent / ".local/openenv/examples/hub_validation_pipeline/spend.py"
SPEND_SHA = "9ee3bbe9aaf6bf5baf39d5209c113932f77fca4ff0bf33c540dac5bbaa5bd537"


def ledger_module(path):
    raw = path.read_bytes()
    require(
        hashlib.sha256(raw).hexdigest() == SPEND_SHA,
        "use the restored OpenEnv shared-spend implementation",
    )
    module = ModuleType("tasksmith_ledger")
    module.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


def stage_plan(run, args, mods, ids):
    score = args.command == "score"
    # Historical reservations: $5 for a canary, $5 for the remaining 23
    # validation tasks, $150 for eight Qwen attempts on 24 tasks.
    amount = (
        Decimal("6.25") * len(ids)
        if score
        else Decimal(5 * (1 + math.ceil((len(ids) - 1) / 23)))
    )
    sources = [
        "pipeline.py",
        "admission.py",
        "common.py",
        "evidence.py",
        "score_trials.py",
        "capped_terminus.py",
        "runtime-constraints.txt",
    ]
    plan = {
        "stage": args.command,
        "run": str(run),
        "campaign_sha256": sha(run / "campaign.json"),
        "namespace": args.namespace,
        "concurrency": args.concurrency if score else 1,
        "tasks": {tid: mods[tid]["effective_digest"] for tid in sorted(ids)},
        "planned_slots_per_task": 8 if score else 3,
        "reservation_usd": str(amount),
        "basis": "historical campaign reservation extrapolation",
        "billed_cost_known": False,
        "operator_sha256": {n: sha(HERE / n) for n in sources},
    }
    if score:
        plan["protocol"] = "qwen38-terminus2-hfsandbox-64k-2m-nothink-tasksmith-v1"
        plan["validation_reports"] = {
            tid: sha(run / "validation/final" / f"{tid}.json") for tid in sorted(ids)
        }
    digest = hashlib.sha256(
        json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return {**plan, "plan_sha256": digest}


def reserve(run, args, plan):
    require(
        args.plan_sha256 == plan["plan_sha256"],
        "reviewed stage hash differs; estimate again",
    )
    require(
        args.ledger and args.ledger.is_file() and args.budget_usd,
        "submission needs an initialized ledger and explicit --budget-usd",
    )
    module = ledger_module(args.spend_tool)
    amount = plan["reservation_usd"]
    require(
        0 < module._amount(amount) <= module._amount(args.budget_usd),
        "stage reservation exceeds supplied budget",
    )
    key = "tasksmith-" + plan["stage"] + "-" + plan["plan_sha256"]
    ledger = args.ledger.resolve()
    path = run / f"{plan['stage']}-reservation.json"
    binding = {
        "id": key,
        "ledger": str(ledger),
        "budget_usd": args.budget_usd,
        "reserved_usd": amount,
        "plan_sha256": plan["plan_sha256"],
        "actual_cost_usd": None,
    }
    new_intent = not path.exists()
    if not new_intent:
        require(
            read(path) == binding,
            "this stage already bound a different reservation, ledger or budget",
        )
    else:
        write(
            path, binding
        )  # Durable intent before the first possible ledger mutation.
    costs = {plan["plan_sha256"]: amount}
    try:
        module.reserve(
            ledger,
            key,
            amount,
            "Tasksmith " + plan["stage"],
            evidence=str(path),
            plan_costs=costs,
        )
    except ValueError:
        # A declined reservation has no paid effects. Only unbind a newly
        # written intent after the original ledger confirms the key is absent.
        if new_intent:
            with module._ledger(ledger) as data:
                if key not in data["reservations"]:
                    path.unlink()
        raise

    def check():
        with module._ledger(ledger) as data:
            row = data["reservations"].get(key, {})
            require(
                not module._report(data)["over_budget"]
                and row.get("status") == "reserved"
                and row.get("plan_costs") == costs
                and module._amount(row["reserved_usd"]) == module._amount(amount),
                "stage no longer has its plan-bound shared reservation",
            )

    check()
    return check


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Initialize a new OpenEnv campaign ledger"
    )
    parser.add_argument("ledger", type=Path)
    parser.add_argument("--limit-usd", required=True)
    parser.add_argument("--spend-tool", type=Path, default=DEFAULT_SPEND)
    opts = parser.parse_args()
    print(json.dumps(ledger_module(opts.spend_tool).init(opts.ledger, opts.limit_usd)))
