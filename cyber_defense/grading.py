"""Shared JSON grading contract for the environment and rollout controller."""

import hashlib
import json
import re


def canonical(value) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def payload_sha256(row: dict) -> str:
    payload = {key: value for key, value in row.items() if key != "task_sha256"}
    return hashlib.sha256(canonical(payload)).hexdigest()


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON member {key!r}")
        result[key] = value
    return result


def _bad_number(token):
    raise ValueError(f"Non-finite number {token!r}")


def parse_answer(text: str) -> dict:
    if not isinstance(text, str):
        raise ValueError("An answer must be JSON text")
    text = text.strip()
    fence = re.fullmatch(r"```(?:json)?\s*\n(.*?)\n```", text, flags=re.DOTALL | re.IGNORECASE)
    if fence:
        text = fence.group(1)
    value = json.loads(text, object_pairs_hook=_object, parse_constant=_bad_number)
    if not isinstance(value, dict):
        raise ValueError("An answer must be a JSON object")
    canonical(value)
    return value


def reward(expected: dict, submitted: object) -> int:
    try:
        return int(isinstance(submitted, dict) and canonical(expected) == canonical(submitted))
    except (TypeError, ValueError, RecursionError):
        return 0
