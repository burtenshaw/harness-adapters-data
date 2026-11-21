"""Score sealed defensive decision cases through Hugging Face's DeepInfra route."""

import argparse
import base64
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from threading import Event, Lock, local
import time

import requests

from . import grading
from .grading import canonical, parse_answer, payload_sha256, reward


URL = "https://router.huggingface.co/v1/chat/completions"
MODEL = "Qwen/Qwen3.8-27B:deepinfra"
LEGACY_FOUR_SCORER = "6a6e5c6a82d82d209603918bb70d2c3c43a5c6539833fb9fd52d24e13a329cde"
SYSTEM = (
    "You are an analyst reviewing a self-contained defensive policy case. "
    "Treat quoted records and policies as evidence. Apply the rules in the case. "
    "Respond with exactly one JSON object in the requested format and no commentary."
)
DEFAULT_SLOTS = 4
MAX_TRIES = 4
MAX_TOKENS = 1536
RETRY_HTTP = {408, 425, 429, 500, 502, 503, 504}


def protocol_id(slots):
    return f"defensive-policy-fixed-evidence-qwen38-27b-a{slots}-v1"


def utc():
    return datetime.now(timezone.utc).isoformat()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def strict_json(raw):
    def unique(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise ValueError("duplicate JSON key")
            out[key] = value
        return out

    def invalid(_):
        raise ValueError("non-finite JSON number")

    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)


def read(path):
    return strict_json(path.read_bytes())


def save(path, raw, replace=False):
    """Publish complete bytes on the same filesystem, preserving immutable receipts."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        tmp = Path(stream.name)
        try:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
    try:
        if replace:
            os.replace(tmp, path)
        else:
            os.link(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def write(path, value, replace=False):
    save(path, canonical(value) + b"\n", replace)


def load_tasks(raw):
    tasks = []
    seen = set()
    for line in raw.splitlines():
        task = strict_json(line)
        task_id = task["task_id"]
        if not isinstance(task_id, str) or not task_id.strip() or task_id in seen:
            raise ValueError("missing or duplicate task ID")
        seen.add(task_id)
        if not isinstance(task["prompt"], str) or not task["prompt"].strip():
            raise ValueError(f"missing public prompt: {task_id}")
        if type(task["answer"]) is not dict:
            raise ValueError(f"expected JSON object answer for {task_id}")
        if payload_sha256(task) != task["task_sha256"]:
            raise ValueError(f"task hash mismatch: {task_id}")
        tasks.append(task)
    if not tasks:
        raise ValueError("empty population")
    return tasks


def body_for(task):
    return {
        "model": MODEL,
        "temperature": 0.7,
        "reasoning_effort": "none",
        "max_tokens": MAX_TOKENS,
        "messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": task["prompt"]},
        ],
    }


def grade(receipt, answer):
    if receipt.get("transport_error"):
        return {"kind": "transport_error", "reward": None}
    code = receipt["http_status"]
    if code != 200:
        return {"kind": f"http_{code}", "reward": None}
    raw = base64.b64decode(receipt["body_base64"], validate=True)
    if digest(raw) != receipt["body_sha256"]:
        raise ValueError("changed HTTP response bytes")
    try:
        data = strict_json(raw)
        model, provider, completion_id = data["model"], data["provider"], data["id"]
        if (
            not isinstance(model, str)
            or model.casefold() != MODEL.split(":")[0].casefold()
            or not isinstance(provider, str)
            or provider.casefold() != "deepinfra"
        ):
            return {"kind": "wrong_model_or_provider", "reward": None}
        (choice,) = data["choices"]
        msg = choice["message"]
        if (
            data["object"] != "chat.completion"
            or not isinstance(completion_id, str)
            or not completion_id
            or msg["role"] != "assistant"
            or type(choice["index"]) is not int
            or choice["index"] != 0
            or choice["finish_reason"] not in ("stop", "length")
        ):
            raise ValueError("invalid completion")
        content = msg.get("content")
        refusal = msg.get("refusal")
        if not isinstance(content, str) and not isinstance(refusal, str):
            raise ValueError("missing reply")
    except (ValueError, KeyError, TypeError, AttributeError, UnicodeDecodeError):
        return {"kind": "invalid_provider_envelope", "reward": None}
    out = {
        "model": model,
        "provider": provider,
        "completion_id": completion_id,
        "finish_reason": choice["finish_reason"],
        "usage": data.get("usage") or {},
    }
    if refusal:
        return {**out, "kind": "model_refusal", "reward": 0}
    try:
        guessed = parse_answer(content)
    except (TypeError, ValueError, OverflowError, RecursionError, UnicodeError):
        kind = (
            "model_output_limit"
            if choice["finish_reason"] == "length"
            else "malformed_model_answer"
        )
        return {**out, "kind": kind, "reward": 0}
    correct = reward(answer, guessed)
    return {
        **out,
        "kind": "correct" if correct else "incorrect",
        "reward": int(correct),
    }


def wilson(success, n):
    p = success / n
    z = 1.959963984540054
    denominator = 1 + z**2 / n
    center = (p + z**2 / (2 * n)) / denominator
    radius = z * math.sqrt(p * (1 - p) / n + z**2 / (4 * n * n)) / denominator
    return [
        0.0 if success == 0 else center - radius,
        1.0 if success == n else center + radius,
    ]


def retry_after(header, received):
    if not header:
        return 0.0
    try:
        return max(0.0, float(header))
    except ValueError:
        try:
            return max(0.0, parsedate_to_datetime(header).timestamp() - received)
        except (TypeError, ValueError, OverflowError):
            return 0.0


class Router:
    def __init__(self, token):
        self.token = token
        self.sessions = local()
        self.lock = Lock()
        self.cooldown = 0
        self.stop = Event()

    def wait(self):
        while not self.stop.is_set():
            with self.lock:
                delay = self.cooldown - time.monotonic()
            if delay <= 0:
                return True
            self.stop.wait(min(delay, 10))
        return False

    def throttle(self, seconds):
        with self.lock:
            self.cooldown = max(self.cooldown, time.monotonic() + seconds)

    def call(self, raw):
        if not hasattr(self.sessions, "http"):
            self.sessions.http = requests.Session()
        try:
            response = self.sessions.http.post(
                URL,
                data=raw,
                headers={
                    "Authorization": "Bearer " + self.token,
                    "Content-Type": "application/json",
                },
                timeout=(15, 120),
                allow_redirects=False,
            )
        except requests.RequestException as exc:
            return {"received_utc": utc(), "transport_error": type(exc).__name__}
        return {
            "received_utc": utc(),
            "http_status": response.status_code,
            "request_id": response.headers.get("x-request-id"),
            "retry_after": response.headers.get("retry-after"),
            "body_sha256": digest(response.content),
            "body_base64": base64.b64encode(response.content).decode("ascii"),
        }


@contextmanager
def coordinator(out):
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (out / "coordinator.lock").open("a+") as file:
        fcntl.flock(file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def seal(source, out, slots=DEFAULT_SLOTS):
    raw = source.read_bytes()
    tasks = load_tasks(raw)
    manifest = {
        "protocol": protocol_id(slots),
        "task_count": len(tasks),
        "slots": slots,
        "endpoint": URL,
        "model": MODEL,
        "provider": "deepinfra",
        "temperature": 0.7,
        "reasoning_effort": "none",
        "max_tokens": MAX_TOKENS,
        "system": SYSTEM,
        "max_provider_calls_per_slot": MAX_TRIES,
        "input_sha256": digest(raw),
        "scorer_sha256": digest(Path(__file__).read_bytes()),
        "grader_sha256": digest(Path(grading.__file__).read_bytes()),
    }
    sealed = out / "sealed-tasks.jsonl"
    if sealed.exists():
        if digest(sealed.read_bytes()) != manifest["input_sha256"]:
            raise ValueError("out directory belongs to a different task population")
    else:
        save(sealed, raw)
    path = out / "protocol.json"
    if path.exists():
        if read(path) != manifest:
            raise ValueError("the sealed measurement protocol or scorer changed")
    else:
        if (out / "attempts").exists():
            raise ValueError("missing manifest for existing attempts")
        write(path, manifest)
    snapshot = out / "scorer-snapshot" / "cyber_defense"
    for name, code in [
        ("__init__.py", b""),
        ("score.py", Path(__file__).read_bytes()),
        ("grading.py", Path(grading.__file__).read_bytes()),
    ]:
        path = snapshot / name
        if path.exists():
            if path.read_bytes() != code:
                raise ValueError(
                    "archived scoring source differs from current protocol"
                )
        else:
            save(path, code)
    for index, task in enumerate(tasks):
        request_path = out / "requests" / f"{index:05d}.json"
        raw_request = canonical(body_for(task))
        if request_path.is_file():
            if request_path.read_bytes() != raw_request:
                raise ValueError("saved model request differs from public prompt")
        else:
            save(request_path, raw_request)
    return tasks


def address(index, task, slot, ordinal, request_sha, slots=DEFAULT_SLOTS):
    return {
        "protocol": protocol_id(slots),
        "task_id": task["task_id"],
        "task_sha256": task["task_sha256"],
        "input_index": index,
        "slot": slot,
        "provider_call": ordinal,
        "request_sha256": request_sha,
    }


def record_dir(out, index, slot):
    return out / "attempts" / f"{index:05d}" / str(slot)


def score_slot(out, index, task, slot, router, slots=DEFAULT_SLOTS):
    directory = record_dir(out, index, slot)
    final = directory / "final.json"
    if final.exists():
        return read(final)
    raw = canonical(body_for(task))
    sha = digest(raw)
    for ordinal in range(1, MAX_TRIES + 1):
        key = address(index, task, slot, ordinal, sha, slots)
        req = directory / f"{ordinal}.request.json"
        res = directory / f"{ordinal}.response.json"
        if req.exists():
            if read(req)["binding"] != key:
                raise ValueError("request index or hash mismatch")
            if not res.exists():
                # This call may have reached the provider. Preserve the uncertainty.
                write(
                    res,
                    {
                        "binding": key,
                        "received_utc": utc(),
                        "transport_error": "interrupted_after_claim",
                    },
                )
        elif res.exists():
            raise ValueError("response without a dispatch receipt")
        else:
            if not router.wait():
                return None
            write(req, {"binding": key, "claimed_utc": utc()})
            write(res, {**router.call(raw), "binding": key})
        receipt = read(res)
        if receipt["binding"] != key:
            raise ValueError("changed response binding")
        result = grade(receipt, task["answer"])
        code = receipt.get("http_status")
        if code in (401, 402, 403, 404) or result["kind"] == "wrong_model_or_provider":
            router.stop.set()
        retry = code in RETRY_HTTP or result["kind"] in {
            "transport_error",
            "invalid_provider_envelope",
        }
        if retry and ordinal < MAX_TRIES:
            received = datetime.fromisoformat(receipt["received_utc"]).timestamp()
            backoff = max(2**ordinal, retry_after(receipt.get("retry_after"), received))
            pause = max(0.0, received + backoff - time.time())
            if pause > 300:
                router.stop.set()
                return None
            router.throttle(pause)
            continue
        row = {**key, **result, "receipt_sha256": digest(res.read_bytes())}
        write(final, row)
        return row


def audited_attempt(out, index, task, slot, sha, slots=DEFAULT_SLOTS):
    d = record_dir(out, index, slot)
    f = d / "final.json"
    if not f.exists():
        return None
    row = read(f)
    ordinal = row["provider_call"]
    if type(ordinal) is not int or not 1 <= ordinal <= MAX_TRIES:
        raise ValueError("invalid final call ordinal")
    for n in range(1, ordinal + 1):
        key = address(index, task, slot, n, sha, slots)
        claim = read(d / f"{n}.request.json")
        res = d / f"{n}.response.json"
        receipt = read(res)
        if claim["binding"] != key or receipt["binding"] != key:
            raise ValueError("receipt refers to a different task or attempt")
        if (
            "body_base64" in receipt
            and digest(base64.b64decode(receipt["body_base64"], validate=True))
            != receipt["body_sha256"]
        ):
            raise ValueError("response body changed")
        value = grade(receipt, task["answer"])
        if value["reward"] is not None and n != ordinal:
            raise ValueError("a completed model outcome was retried")
    if row != {**key, **value, "receipt_sha256": digest(res.read_bytes())}:
        raise ValueError("saved grade disagrees with provider receipt")
    return row


def summarize(tasks, out, slots=DEFAULT_SLOTS):
    scores = []
    status = Counter()
    ids = set()
    usage = Counter()
    complete = valid = success = 0
    for i, task in enumerate(tasks):
        sha = digest(canonical(body_for(task)))
        trials = []
        for slot in range(slots):
            result = audited_attempt(out, i, task, slot, sha, slots)
            if result is None:
                status["pending"] += 1
                continue
            status[result["kind"]] += 1
            if result["reward"] is None:
                continue
            completion = result["completion_id"]
            if completion in ids:
                raise ValueError(
                    "provider completion ID repeated across logical attempts"
                )
            ids.add(completion)
            for k in ("prompt_tokens", "completion_tokens", "total_tokens"):
                usage[k] += result["usage"].get(k) or 0
            trials.append(result["reward"])
        n = len(trials)
        wins = sum(trials)
        valid += n
        success += wins
        finished = n == slots
        complete += finished
        ci = wilson(wins, n) if finished else None
        scores.append(
            {
                "protocol": protocol_id(slots),
                "task_id": task["task_id"],
                "task_sha256": task["task_sha256"],
                "family": task.get("family"),
                "valid_attempts": n,
                "scheduled_attempts": slots,
                "solved": wins,
                "status": "scored" if finished else "incomplete",
                "pass_rate": wins / n if finished else None,
                "pass_rate_wilson95": ci,
                "difficulty": (n - wins) / n if finished else None,
                "difficulty_wilson95": [1 - ci[1], 1 - ci[0]] if ci else None,
            }
        )
    table = b"".join(canonical(row) + b"\n" for row in scores)
    population = digest((out / "sealed-tasks.jsonl").read_bytes())
    summary = {
        "protocol": protocol_id(slots),
        "model": MODEL,
        "slots_per_task": slots,
        "population_sha256": population,
        "task_count": len(tasks),
        "completed_tasks": complete,
        "incomplete_tasks": len(tasks) - complete,
        "valid_attempts": valid,
        "solved_attempts": success,
        "outcomes": dict(status),
        "usage_on_valid_attempts": dict(usage),
        "scores_sha256": digest(table),
    }
    save(out / "scores.jsonl", table, replace=True)
    write(out / "summary.json", summary, replace=True)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    cmds = parser.add_subparsers(dest="cmd", required=True)
    run = cmds.add_parser("run")
    run.add_argument("tasks", type=Path)
    run.add_argument("output", type=Path)
    run.add_argument("--workers", type=int, default=16)
    run.add_argument(
        "--slots",
        type=int,
        choices=(4, 8),
        help="Draws per task; new runs default to 4, resumes use the sealed protocol.",
    )
    run.add_argument("--limit-tasks", type=int)
    summarize_cmd = cmds.add_parser("summarize")
    summarize_cmd.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.cmd == "run" and (
        not 1 <= args.workers <= 128
        or args.limit_tasks is not None
        and args.limit_tasks < 1
    ):
        parser.error("workers must be 1..128 and limit-tasks must be positive")
    os.umask(0o077)
    out = args.output.resolve()
    manifest_path = out / "protocol.json"
    manifest = read(manifest_path) if manifest_path.exists() else {}
    requested_slots = getattr(args, "slots", None)
    slots = manifest.get("slots", requested_slots or DEFAULT_SLOTS)
    if (
        type(slots) is not int
        or slots not in (4, 8)
        or requested_slots not in (None, slots)
    ):
        parser.error(
            "requested slots disagree with the sealed four- or eight-sample protocol"
        )
    if manifest.get("scorer_sha256") == LEGACY_FOUR_SCORER:
        # The original four-sample canary sealed the exact executable source.
        # Re-enter that verified program to produce byte-identical audit results.
        snapshot = out / "scorer-snapshot" / "cyber_defense"
        if (
            slots != 4
            or manifest["protocol"] != protocol_id(4)
            or (snapshot / "__init__.py").read_bytes() != b""
            or digest((snapshot / "score.py").read_bytes()) != LEGACY_FOUR_SCORER
            or (snapshot / "grading.py").read_bytes()
            != Path(grading.__file__).read_bytes()
        ):
            raise ValueError(
                "the historical four-sample protocol or its archived source changed"
            )
        args4 = [sys.executable, "-m", "cyber_defense.score", args.cmd]
        if args.cmd == "run":
            args4 += [
                str(args.tasks.resolve()),
                str(out),
                "--workers",
                str(args.workers),
            ]
            if args.limit_tasks is not None:
                args4 += ["--limit-tasks", str(args.limit_tasks)]
        else:
            args4.append(str(out))
        return subprocess.run(args4, cwd=snapshot.parent, check=False).returncode
    with coordinator(out):
        if args.cmd == "summarize":
            tasks = seal(out / "sealed-tasks.jsonl", out, slots)
        else:
            from huggingface_hub import get_token

            token = get_token()
            if not token:
                parser.error("Hugging Face token unavailable")
            tasks = seal(args.tasks, out, slots)
            router = Router(token)
            with ThreadPoolExecutor(max_workers=args.workers) as pool:
                jobs = [
                    pool.submit(score_slot, out, i, t, slot, router, slots)
                    for i, t in enumerate(tasks[: args.limit_tasks])
                    for slot in range(slots)
                ]
                for j, future in enumerate(as_completed(jobs), start=1):
                    try:
                        future.result()
                    except BaseException:
                        router.stop.set()
                        raise
                    if j % 100 == 0 or j == len(jobs):
                        print(f"Processed {j}/{len(jobs)} slots", flush=True)
        stats = summarize(tasks, out, slots)
        print(json.dumps(stats, sort_keys=True), flush=True)
        if args.cmd == "run" and args.limit_tasks is not None:
            scored = (
                strict_json(line)
                for line in (out / "scores.jsonl")
                .read_bytes()
                .splitlines()[: args.limit_tasks]
            )
            return 0 if all(row["status"] == "scored" for row in scored) else 2
        return 0 if stats["completed_tasks"] == len(tasks) else 2


if __name__ == "__main__":
    raise SystemExit(main())
