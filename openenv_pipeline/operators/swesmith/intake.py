"""Bounded anonymous SWE-smith data intake; never executes task/repository code."""

import argparse
import hashlib
import json
import re
import shlex
import subprocess
from pathlib import Path, PurePosixPath

import requests

ROOT = Path(__file__).resolve().parent
LANGUAGES = ("go", "ts", "rs")
LIMIT = 63 * 1024 * 1024  # Leaves 1 MiB for preliminary metadata probes.
DUCKDB = "/opt/homebrew/bin/duckdb"
SHA = re.compile(r"[0-9a-f]{40}\Z")


def dump(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


class PublicFetch:
    def __init__(self):
        self.session = requests.Session()
        self.session.trust_env = False  # No ambient tokens, .netrc or proxies.
        prior = ROOT / "download-receipts.json"
        state = json.loads(prior.read_text()) if prior.exists() else {}
        self.receipts = state.get("requests", [])
        self.bytes = state.get("received_bytes", 0)
        self.reserved_bytes = state.get("reserved_bytes", self.bytes)

    def save(self):
        dump(
            ROOT / "download-receipts.json",
            {
                "cap_bytes": LIMIT,
                "received_bytes": self.bytes,
                "reserved_bytes": self.reserved_bytes,
                "requests": self.receipts,
            },
        )

    def get(self, url, path, *, expected_size=None, expected_sha=None, headers=None):
        allowance = expected_size if expected_size is not None else 512 * 1024
        if allowance > LIMIT - self.reserved_bytes:
            raise ValueError("Aggregate download budget would be exceeded")
        # Hold the full response allowance before dispatch. Failed/partial reads
        # never release this bound, including bytes hidden in transport buffers.
        self.reserved_bytes += allowance
        receipt = {
            "url": url,
            "path": str(path.relative_to(ROOT)),
            "allowance": allowance,
            "status": "pending",
        }
        self.receipts.append(receipt)
        self.save()
        data = bytearray()
        try:
            with self.session.get(
                url, stream=True, timeout=(15, 90), headers=headers
            ) as response:
                response.raise_for_status()
                advertised = response.headers.get("content-length")
                if advertised and int(advertised) > allowance:
                    raise ValueError("Advertised response exceeds request allowance")
                for chunk in response.iter_content(64 * 1024):
                    self.bytes += len(chunk)
                    if len(data) + len(chunk) > allowance:
                        raise ValueError("Response exceeds request allowance")
                    data.extend(chunk)
            digest = hashlib.sha256(data).hexdigest()
            if expected_size is not None and len(data) != expected_size:
                raise ValueError("Downloaded file size differs from pinned inventory")
            if expected_sha is not None and digest != expected_sha:
                raise ValueError("Downloaded file differs from pinned LFS SHA256")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            receipt["status"] = "verified"
            return bytes(data)
        finally:
            receipt.update(size=len(data), sha256=hashlib.sha256(data).hexdigest())
            if receipt["status"] == "pending":
                receipt["status"] = "failed_or_partial"
            self.save()


def query(path, sql):
    literal = "'" + str(path).replace("'", "''") + "'"
    result = subprocess.run(
        [DUCKDB, "-json", "-c", sql.replace("$FILE", literal)],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout or "[]")


def patch_path(name, prefix):
    if name == "/dev/null":
        return None
    if not name.startswith(prefix):
        raise ValueError("Noncanonical patch path prefix")
    name = name[2:]
    path = PurePosixPath(name)
    if (
        not name
        or path.is_absolute()
        or ".." in path.parts
        or str(path) != name
        or "\\" in name
    ):
        raise ValueError("Unsafe or ambiguous patch path")
    return name


def patch_inventory(patch):
    if not isinstance(patch, str) or not patch.strip() or "\x00" in patch:
        raise ValueError("Missing or malformed patch")
    files, lines = [], patch.splitlines()
    for line in lines:
        if line.startswith("diff --git "):
            tokens = shlex.split(line)
            if len(tokens) != 4:
                raise ValueError("Unsupported patch header")
            files.append(
                {"old": patch_path(tokens[2], "a/"), "new": patch_path(tokens[3], "b/")}
            )
    plain = not files
    if plain:
        # Consume hunk bodies by declared counts: content resembling a file
        # header must never become a second file/path outside its hunk.
        index = 0
        while index < len(lines):
            if (
                index + 1 >= len(lines)
                or not lines[index].startswith("--- ")
                or not lines[index + 1].startswith("+++ ")
            ):
                raise ValueError("Unsupported unified patch header")
            old = patch_path(lines[index][4:], "a/")
            new = patch_path(lines[index + 1][4:], "b/")
            if old is None and new is None:
                raise ValueError("Patch must name at least one file")
            files.append({"old": old, "new": new})
            index += 2
            hunks = 0
            while index < len(lines) and lines[index].startswith("@@ "):
                match = re.match(
                    r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", lines[index]
                )
                if not match:
                    raise ValueError("Malformed unified patch hunk")
                old_left = int(match[2] or 1)
                new_left = int(match[4] or 1)
                index += 1
                while old_left or new_left:
                    if (
                        index >= len(lines)
                        or not lines[index]
                        or lines[index][0] not in " +-\\"
                    ):
                        raise ValueError("Truncated unified patch hunk")
                    line = lines[index]
                    old_left -= line[0] in " -"
                    new_left -= line[0] in " +"
                    if old_left < 0 or new_left < 0:
                        raise ValueError("Unified patch hunk count underflow")
                    index += 1
                while index < len(lines) and lines[index].startswith("\\ No newline"):
                    index += 1
                hunks += 1
            if not hunks:
                raise ValueError("Unified patch lacks hunks")
    if (
        not 1 <= len(files) <= 64
        or "GIT binary patch" in patch
        or "Binary files " in patch
    ):
        raise ValueError("Unsupported patch shape")
    return {
        "format": "unified" if plain else "git",
        "files": files,
        "multifile": len(files) > 1,
        "adds_files": "new file mode " in patch or any(x["old"] is None for x in files),
        "deletes_files": "deleted file mode " in patch
        or any(x["new"] is None for x in files),
        "mode_change": "old mode " in patch,
    }


def candidate(row, lang, revision):
    required = (
        "instance_id",
        "repo",
        "image_name",
        "problem_statement",
        "patch",
        "FAIL_TO_PASS",
        "PASS_TO_PASS",
    )
    if any(key not in row for key in required):
        raise ValueError("Missing source columns")
    if (
        not isinstance(row["problem_statement"], str)
        or len(row["problem_statement"].strip()) < 80
    ):
        raise ValueError("Missing substantive issue text")
    if len(row["patch"].encode()) > 262144:
        raise ValueError("Patch exceeds pilot bound")
    for key in ("FAIL_TO_PASS", "PASS_TO_PASS"):
        if (
            not isinstance(row[key], list)
            or not row[key]
            or any(not isinstance(item, str) or not item for item in row[key])
        ):
            raise ValueError("Missing exact native test identities")
    if any(
        term in row["repo"].lower()
        for term in ("terminal-bench", "swe-bench", "deepswe")
    ):
        raise ValueError("Benchmark alias excluded")
    inventory = patch_inventory(row["patch"])
    patch_hash = hashlib.sha256(row["patch"].encode()).hexdigest()
    tests_hash = hashlib.sha256(
        json.dumps(
            {k: row[k] for k in ("FAIL_TO_PASS", "PASS_TO_PASS")},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    return {
        "task_id": row["instance_id"],
        "language": lang,
        "dataset": "SWE-bench/SWE-smith-" + lang,
        "dataset_revision": revision,
        "source_split": "train",
        "repo": row["repo"],
        "image_name": row["image_name"],
        "instruction_sha256": hashlib.sha256(
            row["problem_statement"].encode()
        ).hexdigest(),
        "instruction_bytes": len(row["problem_statement"].encode()),
        "patch_sha256": patch_hash,
        "patch_bytes": len(row["patch"].encode()),
        "test_identity_sha256": tests_hash,
        "fail_to_pass_count": len(row["FAIL_TO_PASS"]),
        "pass_to_pass_count": len(row["PASS_TO_PASS"]),
        "patch_inventory": inventory,
        "holdout_review": "pending_parent_policy",
        "source_license_review": "pending",
        "runtime_qualified": False,
        "qwen_calibrated": False,
    }


def self_check():
    good = "diff --git a/pkg/value.go b/pkg/value.go\n--- a/pkg/value.go\n+++ b/pkg/value.go\n@@ -1 +1 @@\n-old\n+new\n"
    assert patch_inventory(good)["files"] == [
        {"old": "pkg/value.go", "new": "pkg/value.go"}
    ]
    plain = good[good.index("--- a/") :]
    assert patch_inventory(plain)["format"] == "unified"
    deceptive = "--- a/source.ts\n+++ b/source.ts\n@@ -1 +1 @@\n--- a/not-a-header\n++++ b/not-a-header\n"
    assert len(patch_inventory(deceptive)["files"]) == 1
    for bad in (
        plain.replace("@@ -1 +1 @@", "@@ -2,2 +2,2 @@"),
        good.replace("a/pkg/value.go", "a/../escape"),
        good.replace("b/pkg/value.go", "b//absolute"),
        good + "GIT binary patch\n",
    ):
        try:
            patch_inventory(bad)
        except ValueError:
            continue
        raise AssertionError("Unsafe patch accepted")
    row = {
        "instance_id": "example",
        "repo": "swesmith/example__repo.abcdef12",
        "image_name": "swebench/example:base",
        "problem_statement": "A valid behavior specification. " * 5,
        "patch": good,
        "FAIL_TO_PASS": ["test_fix"],
        "PASS_TO_PASS": ["test_ok"],
    }
    value = candidate(row, "go", "a" * 40)
    assert value["fail_to_pass_count"] == 1 and not value["runtime_qualified"]
    row["FAIL_TO_PASS"] = []
    try:
        candidate(row, "go", "a" * 40)
    except ValueError:
        pass
    else:
        raise AssertionError("Missing native failing test accepted")
    cached = ROOT / "parquet/go.parquet"
    if cached.exists():
        parsed = query(
            cached,
            "SELECT to_json(t) AS row FROM (SELECT FAIL_TO_PASS FROM read_parquet($FILE) LIMIT 1) AS t",
        )[0]["row"]
        assert isinstance(parsed["FAIL_TO_PASS"], list) and parsed["FAIL_TO_PASS"]
    print(
        "Nine intake parser/inventory controls passed, including hunk-aware plain diffs and native Parquet lists"
    )


def acquire():
    fetch = PublicFetch()
    if (ROOT / "pins.json").is_file():
        return enumerate_local(json.loads((ROOT / "pins.json").read_text()), fetch)
    pins = {}
    # Capture every immutable source inventory before downloading/enumerating rows.
    for lang in LANGUAGES:
        repo = "SWE-bench/SWE-smith-" + lang
        info = json.loads(
            fetch.get(
                "https://huggingface.co/api/datasets/" + repo + "/revision/main",
                ROOT / "metadata" / (lang + "-info.json"),
            )
        )
        revision = info["sha"]
        if not SHA.fullmatch(revision):
            raise ValueError("Mutable/noncanonical source revision")
        tree = json.loads(
            fetch.get(
                "https://huggingface.co/api/datasets/"
                + repo
                + "/tree/"
                + revision
                + "/data",
                ROOT / "metadata" / (lang + "-tree.json"),
            )
        )
        files = [
            item
            for item in tree
            if item.get("type") == "file" and item["path"].endswith(".parquet")
        ]
        if len(files) != 1 or not re.fullmatch(r"[0-9a-f]{64}", files[0]["lfs"]["oid"]):
            raise ValueError("Unexpected shard inventory")
        file = files[0]
        pins[lang] = {
            "repo": repo,
            "revision": revision,
            "file": file["path"],
            "size": file["size"],
            "lfs_sha256": file["lfs"]["oid"],
        }
    dump(ROOT / "pins.json", pins)
    for lang, pin in pins.items():
        path = ROOT / "parquet" / (lang + ".parquet")
        fetch.get(
            "https://huggingface.co/datasets/"
            + pin["repo"]
            + "/resolve/"
            + pin["revision"]
            + "/"
            + pin["file"]
            + "?download=true",
            path,
            expected_size=pin["size"],
            expected_sha=pin["lfs_sha256"],
        )
    return enumerate_local(pins, fetch)


def enumerate_local(pins, fetch):
    all_meta, raw = [], {}
    summaries = {}
    for lang, pin in pins.items():
        path = ROOT / "parquet" / (lang + ".parquet")
        if (
            not SHA.fullmatch(pin["revision"])
            or path.stat().st_size != pin["size"]
            or hashlib.sha256(path.read_bytes()).hexdigest() != pin["lfs_sha256"]
        ):
            raise ValueError("Cached pinned Parquet source changed")
        summaries[lang] = query(
            path,
            "SELECT count(*) AS rows, count(DISTINCT repo) AS repositories, count(*) FILTER (WHERE length(trim(coalesce(problem_statement,'')))>=80) AS substantial_issue_rows FROM read_parquet($FILE)",
        )[0]
        rows = [
            item["row"]
            for item in query(
                path,
                "SELECT to_json(t) AS row FROM (SELECT * EXCLUDE(rn) FROM (SELECT *, row_number() OVER (PARTITION BY repo ORDER BY instance_id) AS rn FROM read_parquet($FILE) WHERE length(trim(coalesce(problem_statement,'')))>=80 AND len(FAIL_TO_PASS)>0 AND len(PASS_TO_PASS)>0 AND octet_length(encode(patch))<=262144) ORDER BY rn,repo,instance_id LIMIT 200) AS t",
            )
        ]
        reasons = {}
        for row in rows:
            try:
                item = candidate(row, lang, pin["revision"])
            except ValueError as error:
                reasons[str(error)] = reasons.get(str(error), 0) + 1
                continue
            all_meta.append(item)
            raw[item["task_id"]] = row
        summaries[lang].update(
            captured_candidates=sum(item["language"] == lang for item in all_meta),
            exclusion_reasons=reasons,
        )
    # Interleave languages, preserve source test identities and limit repeated projects.
    selected, counts = [], {}
    buckets = {
        lang: [x for x in all_meta if x["language"] == lang] for lang in LANGUAGES
    }
    while len(selected) < 50 and any(buckets.values()):
        for lang in LANGUAGES:
            if not buckets[lang] or len(selected) >= 50:
                continue
            item = buckets[lang].pop(0)
            if counts.get(item["repo"], 0) >= 5 or any(
                x["patch_sha256"] == item["patch_sha256"] for x in selected
            ):
                continue
            counts[item["repo"]] = counts.get(item["repo"], 0) + 1
            selected.append(item)
    (ROOT / "inventory.jsonl").write_text(
        "".join(json.dumps(x, sort_keys=True) + "\n" for x in all_meta)
    )
    (ROOT / "selected50.jsonl").write_text(
        "".join(json.dumps(x, sort_keys=True) + "\n" for x in selected)
    )
    (ROOT / "selected-raw.jsonl").write_text(
        "".join(json.dumps(raw[x["task_id"]], sort_keys=True) + "\n" for x in selected)
    )
    dump(
        ROOT / "summary.json",
        {
            "source_summaries": summaries,
            "captured_candidates": len(all_meta),
            "selected_candidates": len(selected),
            "selected_repositories": len(counts),
            "downloaded_bytes": fetch.bytes,
            "runtime_qualified": 0,
            "license_and_holdout_review": "pending",
        },
    )
    print(
        json.dumps(
            {
                "captured_candidates": len(all_meta),
                "selected_candidates": len(selected),
                "selected_repositories": len(counts),
                "source_summaries": summaries,
                "downloaded_bytes": fetch.bytes,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    self_check() if args.check else acquire()
