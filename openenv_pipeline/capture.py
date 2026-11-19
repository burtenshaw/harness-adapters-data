"""Capture named train tasks using the original Go, Python and SWE-Gym source readers."""

import argparse
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import quote

from convert import below
from run import PINS, checked, load, sha


def add_arguments(parser):
    parser.add_argument("family", choices=PINS["parquet"])
    parser.add_argument(
        "--task",
        action="append",
        required=True,
        help="Exact upstream instance_id or swegym-NNNN",
    )
    parser.add_argument(
        "--shards",
        type=Path,
        required=True,
        help="Directory of pinned source Parquet files",
    )
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--existing", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--offline-cache",
        type=Path,
        action="append",
        default=[],
        help="Replay historical public response caches only",
    )


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def read_rows(args):
    ids = set(args.task)
    if len(ids) != len(args.task) or any(
        not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", k) for k in ids
    ):
        raise ValueError("Expected distinct canonical source task IDs")
    tool = shutil.which("duckdb")
    if not tool:
        raise ValueError("Install the DuckDB CLI to read the native Parquet source")
    sql_ids = ", ".join("'" + k + "'" for k in sorted(ids))
    gym = args.family == "swegym"
    key = "path" if gym else "instance_id"
    columns = "path,to_base64(task_binary) AS archive_base64" if gym else "*"
    rows = {}
    # Query the very bytes whose hash was checked, including for a local cache.
    with tempfile.TemporaryDirectory() as temp:
        path = Path(temp) / "shard.parquet"
        for spec in PINS["parquet"][args.family]["files"]:
            source = args.shards / spec["path"]
            if not source.is_file():
                source = args.shards / spec["local"]
            path.write_bytes(checked(source, spec["sha256"]))
            sql = f"SELECT to_json(t) AS row FROM (SELECT {columns} FROM read_parquet('shard.parquet') WHERE {key} IN ({sql_ids})) t"
            result = subprocess.run(
                [tool, "-json", "-c", sql], cwd=temp, check=True, capture_output=True
            )
            for item in json.loads(result.stdout or "[]"):
                row = item["row"]
                if row[key] in rows:
                    raise ValueError(f"Duplicate source row: {row[key]}")
                rows[row[key]] = row
    if rows.keys() != ids:
        raise ValueError(f"Missing source task IDs: {sorted(ids - rows.keys())}")
    return [rows[k] for k in args.task]


class RecordedReads:
    def __init__(self, directories):
        self.by_url = {}
        for cache in directories:
            cache = cache.resolve(strict=True)
            for item in json.loads((cache / "network.json").read_bytes())["requests"]:
                if item.get("status") == "verified":
                    path = below(cache, item["path"])
                elif item.get("status") == "complete":
                    path = (
                        cache / "license-cache" / (sha(item["url"].encode()) + ".data")
                    )
                else:
                    continue
                self.by_url[item["url"]] = (item, path)

    def response(self, url):
        if url not in self.by_url:
            raise ValueError(f"Missing recorded public response: {url}")
        item, path = self.by_url[url]
        return item.get("http_status", 200), checked(path, item["sha256"])

    def get(self, url, *, limit, **kwargs):
        code, raw = self.response(url)
        if code != 200 or len(raw) > limit:
            raise ValueError("Recorded response exceeds the approved input envelope")
        return raw

    def api(self, repo, suffix):
        return json.loads(
            self.get(
                "https://api.github.com/repos/" + repo + "/" + suffix, limit=4 * 1024**2
            )
        )


def gym_reader(pilot, args, policy, existing, replay):
    m = load(pilot / "expanded-python-intake/expand.py")
    inputs = {
        name: checked(pilot / name, digest)
        for name, digest in m.INPUTS.items()
        if name != m.SHARD
    }
    screen, extractor, _ = m.tools(inputs)
    index = {
        r["task_id"]: r
        for r in map(
            json.loads,
            inputs["expanded-python-intake/metadata-index.jsonl"].splitlines(),
        )
    }
    licenses = m.Licenses(args.output, inputs, pilot)
    if replay:
        licenses.get = replay.response
    (args.output / "staging").mkdir()

    def one(row):
        record = m.archive_record(row, index, screen, extractor)
        allowed, excluded = m.select([record], policy, existing)
        if not allowed:
            raise ValueError(excluded[0]["reason"])
        lic, proof = licenses.resolve(record)
        candidate = m.candidate(record, proof, inputs["harbor/TaskTrove.README.md"])
        return candidate, lambda: m.materialize(args.output, record, candidate, lic)

    return one


def smith_reader(pilot, args, policy, replay):
    go = args.family == "swesmith-go"
    if go:
        m = load(pilot / "pilot50/go/materialize.py")
        intake, _ = m.helpers()
        profiles = {
            k.casefold(): v
            for k, v in json.loads(
                (pilot / "swesmith/profiles.json").read_bytes()
            ).items()
        }
        assets = pilot / "pilot50/go"
    else:
        m_py = load(pilot / "additional-repositories-v2/materialize.py")
        m, intake, _, _, _, _ = m_py.tools()
        assets = pilot / "additional-repositories-v2"
        profiles = m_py.parse_profiles(
            checked(assets / "python-profiles.py", m_py.PROFILE_SHA)
        )
        shutil.copyfile(
            assets / "python-profiles.py", args.output / "python-profiles.py"
        )
    shutil.copyfile(
        assets / "bundle-license-evidence.json",
        args.output / "bundle-license-evidence.json",
    )
    m.ROOT = args.output
    m.SQUIRREL = (
        None  # Named runs read the chosen task through the same public-source fetcher.
    )
    if not go:
        m.CAP = 1024**3
    fetch = replay or m.Fetch()

    def one(row):
        profile = profiles[row["repo"].casefold()]
        if (
            profile["eval_sets"]
            or profile["upstream_repo"].casefold() in policy["quarantined_repositories"]
        ):
            raise ValueError(
                "Published evaluation profile or benchmark repository overlap"
            )
        record = m.prepare_task(row, profile, fetch, intake)
        root = args.output / Path(record["provenance_path"]).parent
        if go:
            (root / "instruction.md").write_bytes(
                (row["problem_statement"] + "\n").encode()
            )
        else:
            mirror_license = (root / "LICENSE.source").read_bytes()
            tree = json.loads((root / "learner-tree.json").read_bytes())
            names = [
                x["path"]
                for x in tree["tree"]
                if x["path"].casefold()
                in {"license", "license.txt", "license.md", "copying", "copying.md"}
            ]
            if len(names) != 1:
                raise ValueError("Ambiguous upstream source license")
            url = f"https://raw.githubusercontent.com/{profile['upstream_repo']}/{profile['upstream_commit']}/{quote(names[0])}"
            if fetch.get(url, limit=65536) != mirror_license:
                raise ValueError("Upstream and mirror license bytes differ")
            (root / "LICENSE.upstream").write_bytes(mirror_license)
            record["license_evidence"]["source_code"].update(
                actual_upstream_url=url,
                actual_upstream_commit=profile["upstream_commit"],
            )

        def store():
            write(root / "candidate.json", record)
            write(
                root / "completion.json",
                {
                    "files": {
                        p.relative_to(root).as_posix(): sha(p.read_bytes())
                        for p in sorted(root.rglob("*"))
                        if p.is_file() and p.name != "completion.json"
                    }
                },
            )

        return record, store

    return one


def capture(args):
    rows = read_rows(args)
    policy = json.loads(args.policy.read_bytes())
    existing = json.loads(args.existing.read_bytes())
    pilot = args.operators
    assessor = load(pilot / "eligibility/eligibility.py")
    args.output.mkdir(parents=True, mode=0o700, exist_ok=False)
    replay = RecordedReads(args.offline_cache) if args.offline_cache else None
    gym = args.family == "swegym"
    one = (
        gym_reader(pilot, args, policy, existing, replay)
        if gym
        else smith_reader(pilot, args, policy, replay)
    )
    decisions, materialized = [], []
    for identifier, row in zip(args.task, rows, strict=True):
        try:
            materialized.append(one(row))
        except (ValueError, KeyError, OSError, UnicodeError) as error:
            decisions.append(
                {
                    "task_id": identifier,
                    "status": "source_blocked",
                    "reason": str(error),
                }
            )
    kept = []
    families = set()
    for (record, store), decision in zip(
        materialized,
        assessor.assess_many((item[0] for item in materialized), policy, existing),
        strict=True,
    ):
        if not gym:
            proof = json.loads((args.output / record["provenance_path"]).read_bytes())
            family = (
                record["upstream_repo"].casefold(),
                tuple(sorted(proof["source_paths"])),
                tuple(sorted(proof["FAIL_TO_PASS"])),
            )
            if family in families:
                decision.update(
                    status="quarantine",
                    reasons=decision["reasons"] + ["duplicate bug family"],
                )
            families.add(family)
        decisions.append({"task_id": record["task_id"], **decision})
        if decision["status"] == "eligible_for_controls":
            record["intake_assessment" if gym else "eligibility"] = decision
            store()
            kept.append(record)
    index = args.output / "candidates.jsonl"
    index.write_bytes(
        b"".join((json.dumps(row, sort_keys=True) + "\n").encode() for row in kept)
    )
    write(args.output / "decisions.json", decisions)
    if args.family == "swesmith-go":
        for rel in ("materialize.py", "inputs/upstream/swesmith/profiles/golang.py"):
            dst = args.output / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(pilot / "pilot50/go" / rel, dst)
        members = sorted(
            p
            for p in args.output.rglob("*")
            if p.is_file() and "cache" not in p.relative_to(args.output).parts
        )
        write(
            args.output / "artifact-modes.json",
            {
                str(p.relative_to(args.output)): oct(p.stat().st_mode & 0o777)
                for p in members
            },
        )
        manifest = args.output / "SHA256SUMS"
        manifest.write_text(
            "".join(
                f"{sha(p.read_bytes())}  {p.relative_to(args.output)}\n"
                for p in [*members, args.output / "artifact-modes.json"]
            )
        )
    elif args.family == "swesmith-py":
        receipts = {
            str(Path(r["provenance_path"]).parent / "completion.json") for r in kept
        }
        write(
            args.output / "source-receipts.json",
            {
                "completion_receipts_sha256": {
                    k: sha((args.output / k).read_bytes()) for k in sorted(receipts)
                }
            },
        )
        manifest = args.output / "source-manifest.json"
        write(
            manifest,
            {
                "schema": "additional-python-frozen-source-v2",
                "index_path": "candidates.jsonl",
                "index_sha256": sha(index.read_bytes()),
                "receipts_path": "source-receipts.json",
                "receipts_sha256": sha(
                    (args.output / "source-receipts.json").read_bytes()
                ),
            },
        )
    else:
        manifest = index
    summary = {
        "attempted": len(rows),
        "eligible_for_controls": len(kept),
        "manifest": manifest.name,
        "manifest_sha256": sha(manifest.read_bytes()),
        "index_sha256": sha(index.read_bytes()),
        "source_revision": PINS["parquet"][args.family]["revision"],
        "policy_sha256": sha(args.policy.read_bytes()),
        "existing_sha256": sha(args.existing.read_bytes()),
    }
    write(args.output / "capture.json", summary)
    print(json.dumps(summary))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    add_arguments(parser)
    parser.add_argument("--operators", type=Path, required=True)
    capture(parser.parse_args())
