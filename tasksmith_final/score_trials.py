"""Score modified Tasksmith tasks with Qwen3.8-27B under terminus-2 on HF Sandbox.

Start through pipeline.py score so stage admission and slot recovery are enforced.

Each attempt is one Harbor trial: the agent in one labelled HF Sandbox job and the
separate verifier in another. Attempts are never re-run; a missing reward stays null.
"""

import asyncio
import json
import os
import re
import shutil
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from functools import partial

from harbor.models.environment_type import EnvironmentType
from harbor.models.trial.config import (
    AgentConfig,
    EnvironmentConfig,
    TaskConfig,
    TrialConfig,
    VerifierConfig,
)
from harbor.trial.trial import Trial
from huggingface_hub import HfApi

from openenv.validation.harbor import _start_sandbox
from common import source_digest, write

PROTOCOL = "qwen38-terminus2-hfsandbox-64k-2m-nothink-tasksmith-v1"
ATTEMPTS = 8
AGENT_KWARGS = {
    "api_base": "https://router.huggingface.co/v1",
    "max_turns": 48,
    "temperature": 0.7,
    "reasoning_effort": "none",
    "enable_summarize": False,
    "record_terminal_session": False,
    "suppress_max_turns_warning": True,
    "model_info": {
        "max_input_tokens": 262144,
        "max_output_tokens": 65536,
        "input_cost_per_token": 0.15e-6,
        "output_cost_per_token": 1.875e-6,
    },
    "llm_call_kwargs": {"max_tokens": 65536},
}
MODEL = "openai/Qwen/Qwen3.8-27B:deepinfra"
AGENT_TIMEOUT_S = 1800


async def attempt(task_dir, out, run_id, index, semaphore, namespace, check):
    record_path = out / f"{task_dir.name}/attempt-{index}.json"
    digest = source_digest(task_dir)
    if record_path.exists():
        return json.loads(record_path.read_text())
    async with semaphore:
        work = out / f"{task_dir.name}/work-{index}"
        if work.exists():
            # Started before but never recorded: missing, not re-run.
            record = {
                "task_id": task_dir.name,
                "attempt": index,
                "protocol": PROTOCOL,
                "task_digest": digest,
                "reward": None,
                "valid": False,
                "solved": None,
                "exception": "AttemptInterrupted",
                "run_id": run_id,
            }
            write(record_path, record)
            return record
        check()
        task_copy = work / "task"
        shutil.copytree(task_dir, task_copy)
        labels = {
            "openenv-qwen-run": run_id,
            "openenv-qwen-task": task_dir.name.removeprefix("tasksmith-"),
            "openenv-qwen-attempt": str(index),
        }
        config = TrialConfig(
            task=TaskConfig(path=task_copy.resolve()),
            agent=AgentConfig(
                import_path="capped_terminus:CappedTerminus2",
                model_name=MODEL,
                override_timeout_sec=AGENT_TIMEOUT_S,
                kwargs=AGENT_KWARGS,
            ),
            environment=EnvironmentConfig(
                type=EnvironmentType.HF_SANDBOX,
                delete=True,
                kwargs={
                    "flavor": "cpu-basic",
                    "namespace": namespace,
                    "job_timeout": AGENT_TIMEOUT_S + 900,
                },
            ),
            verifier=VerifierConfig(override_timeout_sec=600),
            trial_name=f"qwen-{task_dir.name.removeprefix('tasksmith-')}-a{index}",
            trials_dir=(work / "trials").resolve(),
        )
        started = time.time()
        record = {
            "task_id": task_dir.name,
            "attempt": index,
            "protocol": PROTOCOL,
            "task_digest": digest,
            "run_id": run_id,
        }
        try:
            trial = await Trial.create(config)
            start = partial(_start_sandbox, labels=labels, namespace=namespace)
            trial.agent_environment.start = partial(start, trial.agent_environment)
            validate_policies = trial._validate_separate_verifier_env_policies

            def label_verifier(env, *, plan):
                validate_policies(env, plan=plan)
                env.start = partial(start, env)

            trial._validate_separate_verifier_env_policies = label_verifier
            result = await trial.run()
            rewards = result.verifier_result.rewards if result.verifier_result else None
            ctx = result.agent_result
            exc = result.exception_info
            budget_stop = (trial.paths.agent_dir / "budget_stop.txt").exists()
            record.update(
                reward=None if rewards is None else rewards.get("reward"),
                exception=exc.exception_type if exc else None,
                exception_message=(exc.exception_message or "")[:500] if exc else None,
                n_input_tokens=ctx.n_input_tokens if ctx else None,
                n_output_tokens=ctx.n_output_tokens if ctx else None,
                cost_usd=ctx.cost_usd if ctx else None,
                budget_stop=budget_stop,
            )
        except Exception as error:
            record.update(
                reward=None,
                exception=type(error).__name__,
                exception_message=str(error)[:500],
            )
        reward = record.get("reward")
        # Valid only when the verifier produced a reward. Agent timeouts and budget
        # stops are graded; provider, environment and verifier failures stay null.
        record["valid"] = reward is not None and record["exception"] in (
            None,
            "AgentTimeoutError",
        )
        record["solved"] = (reward == 1) if record["valid"] else None
        record["seconds"] = round(time.time() - started, 1)
        record_path.parent.mkdir(parents=True, exist_ok=True)
        write(record_path, record)
        print(
            json.dumps(
                {
                    k: record.get(k)
                    for k in (
                        "task_id",
                        "attempt",
                        "reward",
                        "valid",
                        "exception",
                        "n_input_tokens",
                        "cost_usd",
                        "seconds",
                    )
                }
            ),
            flush=True,
        )
        return record


def cleanup(run_id, namespace):
    api = HfApi()
    deadline = time.time() + 120
    while True:
        jobs = list(
            api.list_jobs(labels={"openenv-qwen-run": run_id}, namespace=namespace)
        )
        live = [
            j
            for j in jobs
            if j.status.stage not in ("COMPLETED", "CANCELED", "ERROR", "DELETED")
        ]
        for job in live:
            known = api.inspect_job(job_id=job.id, namespace=namespace)
            if (
                known.owner.name != namespace
                or (known.labels or {}).get("openenv-qwen-run") != run_id
            ):
                raise ValueError("unbound Job in cleanup inventory")
            api.cancel_job(job_id=job.id, namespace=namespace)
        if not live or time.time() > deadline:
            return {"jobs": len(jobs), "still_running": [j.id for j in live]}
        time.sleep(5)


async def score(root, out, concurrency, ids, namespace, check):
    out.mkdir(parents=True, exist_ok=True)
    run_file = out / "run_id.txt"
    if run_file.exists():
        run_id = run_file.read_text().strip()
        if not re.fullmatch(r"[0-9a-f]{16}", run_id):
            raise ValueError("invalid persisted scoring run ID")
        recovered = cleanup(run_id, namespace)
        if recovered["still_running"]:
            raise RuntimeError("old scoring jobs are still running")
    else:
        if any(out.iterdir()):
            raise ValueError("scoring state without its run ID needs reconciliation")
        run_id = uuid.uuid4().hex[:16]
        with run_file.open("x") as stream:
            stream.write(run_id + "\n")
            stream.flush()
            os.fsync(stream.fileno())
    semaphore = asyncio.Semaphore(concurrency)
    # Each sandbox command blocks a worker thread for its whole duration.
    asyncio.get_running_loop().set_default_executor(
        ThreadPoolExecutor(max_workers=4 * concurrency + 8)
    )
    try:
        async with asyncio.TaskGroup() as group:
            for tid in ids:
                for index in range(ATTEMPTS):
                    group.create_task(
                        attempt(
                            root / tid, out, run_id, index, semaphore, namespace, check
                        )
                    )
    finally:
        receipt = {**cleanup(run_id, namespace), "run_id": run_id}
        write(out / "cleanup.json", receipt)
        if receipt["still_running"]:
            raise RuntimeError("HF Jobs cleanup incomplete, inspect the run-owned jobs")


if __name__ == "__main__":
    raise SystemExit(
        "Start scoring through pipeline.py score with a reviewed plan and reservation"
    )
