"""Pinned public data intake; never executes downloaded repository code."""

import hashlib
import json
import os
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent
CACHE_ROOT = ROOT.parent / "additional-repositories-v1"
CAP = 1024**3
LOCK = threading.RLock()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def dump(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(data, sort_keys=True, indent=2) + "\n")
    os.replace(temp, path)


class Fetch:
    def __init__(self):
        self.path = ROOT / "network.json"
        self.state = (
            json.loads(self.path.read_text())
            if self.path.exists()
            else {
                "cap_bytes": CAP,
                "received_bytes": 0,
                "uncertain_bytes": 0,
                "requests": [],
            }
        )

    def get(self, url, *, limit, expected_sha=None, github=False):
        # Immutable old cache is read-only; new transfers retain a fresh1GiB envelope.
        previous = CACHE_ROOT
        ledger = json.loads((previous / "network.json").read_text())
        for cached in ledger["requests"]:
            if cached["url"] == url and cached["status"] == "verified":
                raw = (previous / cached["path"]).read_bytes()
                if (
                    len(raw) != cached["bytes"]
                    or sha(raw) != cached["sha256"]
                    or (expected_sha and sha(raw) != expected_sha)
                ):
                    raise ValueError("Reused immutable public cache drifted")
                return raw
        with LOCK:
            for item in self.state["requests"]:
                if item["url"] == url and item["status"] == "verified":
                    raw = (ROOT / item["path"]).read_bytes()
                    if len(raw) != item["bytes"] or sha(raw) != item["sha256"]:
                        raise ValueError("Cached public bytes drifted")
                    if expected_sha and sha(raw) != expected_sha:
                        raise ValueError("Cached bytes differ from pin")
                    return raw
            if (
                self.state["received_bytes"] + self.state["uncertain_bytes"] + limit
                > CAP
            ):
                raise ValueError("Aggregate public read allowance exhausted")
            item = {
                "url": url,
                "allowance": limit,
                "status": "pending",
                "path": "cache/" + sha(url.encode()),
            }
            self.state["requests"].append(item)
            self.state["uncertain_bytes"] += limit
            dump(self.path, self.state)
        raw = bytearray()
        try:
            if github:
                if not url.startswith("https://api.github.com/repos/"):
                    raise ValueError("Unexpected public GitHub endpoint")
                process = subprocess.Popen(
                    ["gh", "api", url.removeprefix("https://api.github.com/")],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                )
                timer = threading.Timer(75, process.kill)
                timer.start()
                try:
                    while chunk := process.stdout.read(
                        min(65536, limit - len(raw) + 1)
                    ):
                        raw.extend(chunk)
                        if len(raw) > limit:
                            raise ValueError("Public response exceeded allowance")
                    if process.wait() != 0:
                        raise ValueError("Public GitHub request failed")
                finally:
                    if process.poll() is None:
                        process.kill()
                    process.wait()
                    process.stdout.close()
                    timer.cancel()
            else:
                with requests.Session() as session:
                    session.trust_env = False
                    with session.get(url, stream=True, timeout=(15, 120)) as response:
                        response.raise_for_status()
                        length = response.headers.get("content-length")
                        if length and int(length) > limit:
                            raise ValueError(
                                "Advertised public response exceeded allowance"
                            )
                        for chunk in response.iter_content(65536):
                            raw.extend(chunk)
                            if len(raw) > limit:
                                raise ValueError("Public response exceeded allowance")
            if expected_sha and sha(raw) != expected_sha:
                raise ValueError("Public source differs from immutable SHA256")
            path = ROOT / item["path"]
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(raw)
            with LOCK:
                item.update(status="verified", bytes=len(raw), sha256=sha(raw))
                self.state["received_bytes"] += len(raw)
                self.state["uncertain_bytes"] -= limit
                dump(self.path, self.state)
            return bytes(raw)
        except BaseException:
            with LOCK:
                item.update(status="failed_or_partial", bytes=len(raw), sha256=sha(raw))
                self.state["received_bytes"] += len(raw)
                dump(self.path, self.state)
            raise

    def api(self, repo, suffix):
        return json.loads(
            self.get(
                "https://api.github.com/repos/" + repo + "/" + suffix,
                github=True,
                limit=4 * 1024**2,
            )
        )


def shards(fetch):
    pin = json.loads((ROOT / "python-source-pin.json").read_text())

    def one(item):
        url = f"https://huggingface.co/datasets/{pin['repo']}/resolve/{pin['revision']}/{item['path']}"
        raw = fetch.get(url, limit=item["size"], expected_sha=item["sha256"])
        if len(raw) != item["size"]:
            raise ValueError("Pinned shard size differs")
        dest = ROOT / "parquet" / Path(item["path"]).name
        dest.parent.mkdir(exist_ok=True)
        if dest.exists() and dest.read_bytes() != raw:
            raise ValueError("Existing shard differs")
        dest.write_bytes(raw)
        print(
            json.dumps({"shard": dest.name, "bytes": len(raw), "verified": True}),
            flush=True,
        )

    with ThreadPoolExecutor(max_workers=3) as pool:
        list(pool.map(one, pin["files"]))


if __name__ == "__main__":
    shards(Fetch())
