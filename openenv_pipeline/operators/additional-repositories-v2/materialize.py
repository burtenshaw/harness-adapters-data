"""Additional Python source proofs using the frozen data-only delta verifier."""

import argparse
import ast
import hashlib
import json
import re
import subprocess
import sys
import time
import types
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parent
PILOT = ROOT.parent
CACHE_ROOT = PILOT / "additional-repositories-v1"
PROFILE_COMMIT = "9b74ac08118a85c39c356802f7961893af73e07f"
PROFILE_SHA = "eadf29551ca2e706950d3f2311b47a3d08c2ccee3c8dd217fa299014a08e4286"
DATA_COMMIT = "77cab9055d42ab4a5c25c89a8f937096db13558e"
HELPER_SHA = "eecbcbafdd30472b8a3c576f2a30d7cf0bfbbe9f34a958067d18759cabb5c4f7"
REPOS = [
    "lepture/mistune",
    "kayak/pypika",
    "python-hyper/h11",
    "life4/textdistance",
    "Suor/funcy",
    "cloudpipe/cloudpickle",
    "agronholm/exceptiongroup",
    "facelessuser/soupsieve",
]
EXISTING = {
    "project-monai/monai",
    "bokeh/bokeh",
    "conan-io/conan",
    "dask/dask",
    "facebookresearch/hydra",
    "getmoto/moto",
    "iterative/dvc",
    "modin-project/modin",
    "pandas-dev/pandas",
    "pydantic/pydantic",
    "python/mypy",
}

EXISTING |= {
    "marshmallow-code/marshmallow",
    "msiemens/tinydb",
    "arrow-py/arrow",
    "mahmoud/glom",
    "andialbrecht/sqlparse",
    "marshmallow-code/apispec",
    "pallets/click",
    "oauthlib/oauthlib",
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def captured(path, expected, read=None):
    if path.is_symlink() or not path.is_file():
        raise ValueError("Captured input is not a regular real file")
    raw = (read or Path.read_bytes)(path)
    if sha(raw) != expected:
        raise ValueError("Captured input differs from original pin: " + path.name)
    return raw


def module(name, raw, filename):
    result = types.ModuleType(name)
    result.__file__ = str(filename)
    sys.modules[name] = result
    exec(compile(raw, str(filename), "exec"), result.__dict__)
    return result


def tools():
    source = PILOT / "pilot50/go/materialize.py"
    raw = captured(source, HELPER_SHA)
    text = raw.decode().replace(
        'intake.candidate(row, "go", SOURCE_REVISION)',
        'intake.candidate(row, "py", SOURCE_REVISION)',
    )
    text = text.replace(
        'not new.endswith(".go") or new.endswith("_test.go")',
        'not new.endswith(".py") or new.split("/")[-1].startswith("test_")',
    )
    text = text.replace(
        'not x["filename"].endswith("_test.go")', 'not x["filename"].endswith(".py")'
    )
    start = text.index(
        "    functions = defaultdict(list)\n", text.index("def prepare_task")
    )
    end = text.index("    licenses = [\n", start)
    text = (
        text[:start]
        + """    tests = row["FAIL_TO_PASS"] + row["PASS_TO_PASS"]
    if len(tests) != len(set(tests)):
        raise ValueError("Duplicate or overlapping native test identities")
    for test in tests:
        name = source_path(test.split("::", 1)[0]).as_posix()
        if name not in bug_files:
            raise ValueError("Native test path missing in exact source tree")
    if any(t.split("::", 1)[0] not in private_paths for t in row["FAIL_TO_PASS"]):
        raise ValueError("F2P test remains learner-visible")
"""
        + text[end:]
    )
    text = text.replace("swesmith-go:", "swesmith-py:").replace(
        "SWE-smith-go", "SWE-smith-py"
    )
    text = text.replace("official Go profile AST", "official Python profile AST")
    m = module("additional_python_delta", text.encode(), source)
    m.ROOT, m.PROJECT_CAP, m.FILE_CAP, m.SOURCE_REVISION = (
        ROOT,
        32 * 1024**2,
        4 * 1024**2,
        DATA_COMMIT,
    )
    intake, assessor = m.helpers()
    policy, existing = m.eligibility_inputs()
    fetchmod = module(
        "additional_public_fetch", (ROOT / "intake.py").read_bytes(), ROOT / "intake.py"
    )
    return m, intake, assessor, policy, existing, fetchmod


def parse_profiles(raw):
    result = {}
    for node in ast.parse(raw).body:
        if not isinstance(node, ast.ClassDef):
            continue
        fields = {}
        for statement in node.body:
            if isinstance(statement, ast.AnnAssign) and isinstance(
                statement.target, ast.Name
            ):
                name = statement.target.id
                try:
                    fields[name] = ast.literal_eval(statement.value)
                except (ValueError, TypeError):
                    if name == "eval_sets":
                        fields[name] = ["nonempty declaration requires exclusion"]
        if not all(name in fields for name in ("owner", "repo", "commit")):
            continue
        if not re.fullmatch(r"[a-f0-9]{40}", fields["commit"]):
            raise ValueError("Profile lacks full immutable source commit")
        repo = fields["owner"] + "/" + fields["repo"]
        key = "swesmith/" + repo.replace("/", "__") + "." + fields["commit"][:8]
        result[key.casefold()] = {
            "upstream_repo": repo,
            "upstream_commit": fields["commit"],
            "profile_class": node.name,
            "profile_lines": [node.lineno, node.end_lineno],
            "profile_source_commit": PROFILE_COMMIT,
            "profile_source_sha256": PROFILE_SHA,
            "profile_source_path": "swesmith/profiles/python.py",
            "eval_sets": fields.get("eval_sets", []),
        }
    return result


def pool():
    m, intake, _, policy, existing, _ = tools()
    pin = json.loads((ROOT / "python-source-pin.json").read_text())
    for item in pin["files"]:
        raw = captured(CACHE_ROOT / "parquet" / Path(item["path"]).name, item["sha256"])
        if len(raw) != item["size"]:
            raise ValueError("Pinned shard size differs")
    profiles = parse_profiles(captured(ROOT / "python-profiles.py", PROFILE_SHA))
    m.dump(ROOT / "profiles.json", profiles)
    wanted = {
        key: value for key, value in profiles.items() if value["upstream_repo"] in REPOS
    }
    for profile in wanted.values():
        upstream = profile["upstream_repo"].casefold()
        if (
            upstream in EXISTING
            or upstream in policy["quarantined_repositories"]
            or profile["eval_sets"]
        ):
            raise ValueError(
                "Selected repository has existing/benchmark/profile overlap"
            )
    sql = (
        "SELECT to_json(t) AS row FROM (SELECT * FROM read_parquet("
        + repr(str(CACHE_ROOT / "parquet/*.parquet"))
        + ") WHERE lower(repo) IN ("
        + ",".join(repr(k) for k in wanted)
        + ") AND length(trim(coalesce(problem_statement,'')))>=80 AND len(FAIL_TO_PASS)>0 AND len(PASS_TO_PASS)>0 AND octet_length(encode(patch))<=262144 ORDER BY repo,instance_id)t"
    )
    rows = json.loads(
        subprocess.run(
            ["/opt/homebrew/bin/duckdb", "-json", "-c", sql],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    )
    seen, buckets, excluded = set(), defaultdict(list), []
    for value in rows:
        row = value["row"]
        try:
            profile = wanted[row["repo"].casefold()]
            item = intake.candidate(row, "py", DATA_COMMIT)
            m.patch_sections(row["patch"], item["patch_inventory"])
            if row["instance_id"] in existing["task_ids"] + existing["seen_source_ids"]:
                raise ValueError("Previously seen task identity")
            if item["patch_sha256"] in existing["patch_sha256s"]:
                raise ValueError("Previously seen patch digest")
            if item["instruction_sha256"] in policy["benchmark_instruction_sha256"]:
                raise ValueError("Benchmark instruction identity")
            if m.CANARY.search(row["problem_statement"].encode()):
                raise ValueError("Anti-training marker in instruction")
            family = (
                profile["upstream_repo"].casefold(),
                tuple(sorted(x["new"] for x in item["patch_inventory"]["files"])),
                tuple(sorted(row["FAIL_TO_PASS"])),
            )
            if family in seen:
                raise ValueError("Duplicate source family")
            seen.add(family)
            buckets[profile["upstream_repo"]].append(
                {"row": row, "profile": profile, "family": family}
            )
        except (ValueError, KeyError, TypeError) as error:
            excluded.append({"task_id": row["instance_id"], "reason": str(error)})
    counts = {repo: len(values) for repo, values in buckets.items()}
    selected = [value for repo in REPOS for value in buckets[repo][:120]]
    raw = "".join(
        json.dumps(value, sort_keys=True) + "\n" for value in selected
    ).encode()
    (ROOT / "pool.jsonl").write_bytes(raw)
    m.dump(ROOT / "pool-exclusions.json", excluded)
    summary = {
        "source_rows": 50908,
        "source_repos": 131,
        "selected_candidates": len(selected),
        "deduplicated_repo_counts": counts,
        "selected_per_repo": dict(
            Counter(x["profile"]["upstream_repo"] for x in selected)
        ),
        "pool_sha256": sha(raw),
        "runtime_qualified": False,
        "training_admissible": False,
        "accepted_per_repo_limit": 40,
        "reasons": dict(Counter(x["reason"] for x in excluded)),
    }
    m.dump(ROOT / "pool-checkpoint.json", summary)
    print(json.dumps(summary), flush=True)


def materialize(target):
    m, intake, assessor, policy, existing, fm = tools()
    fetch = fm.Fetch()
    card = fetch.get(
        "https://huggingface.co/datasets/SWE-bench/SWE-smith-py/raw/"
        + DATA_COMMIT
        + "/README.md",
        limit=65536,
    )
    if not re.search(rb"(?mi)^license: mit\s*$", card):
        raise ValueError("Pinned task bundle lacks MIT declaration")
    (ROOT / "README.source.md").write_bytes(card)
    m.dump(
        ROOT / "bundle-license-evidence.json",
        {
            "spdx": "MIT",
            "sha256": sha(card),
            "url": "https://huggingface.co/datasets/SWE-bench/SWE-smith-py/raw/"
            + DATA_COMMIT
            + "/README.md",
            "reviewed": True,
            "training_allowed": True,
        },
    )
    checkpoint = json.loads((ROOT / "pool-checkpoint.json").read_text())
    raw = captured(ROOT / "pool.jsonl", checkpoint["pool_sha256"])
    buckets = defaultdict(list)
    for line in raw.splitlines():
        value = json.loads(line)
        buckets[value["profile"]["upstream_repo"]].append(value)
    lock = __import__("threading").RLock()
    successes, failures = [], []
    started = time.monotonic()

    def save():
        m.dump(
            ROOT / "progress.json",
            {
                "materialized": len(successes),
                "repo_counts": dict(Counter(x["upstream_repo"] for x in successes)),
                "failures": len(failures),
                "failure_reasons": dict(Counter(x["reason"] for x in failures)),
                "elapsed_seconds": time.monotonic() - started,
                "runtime_qualified": False,
                "training_admissible": False,
            },
        )

    def one_repo(repo):
        completed = 0
        for value in buckets[repo]:
            if completed >= target:
                break
            row, profile = value["row"], value["profile"]
            try:
                candidate = m.prepare_task(row, profile, fetch, intake)
                out = ROOT / Path(candidate["provenance_path"]).parent
                license_raw = (out / "LICENSE.source").read_bytes()
                tree = json.loads((out / "learner-tree.json").read_text())
                names = [
                    x["path"]
                    for x in tree["tree"]
                    if x["path"].casefold()
                    in {"license", "license.txt", "license.md", "copying", "copying.md"}
                ]
                if len(names) != 1:
                    raise ValueError("Ambiguous license")
                url = (
                    "https://raw.githubusercontent.com/"
                    + profile["upstream_repo"]
                    + "/"
                    + profile["upstream_commit"]
                    + "/"
                    + quote(names[0])
                )
                upstream_raw = fetch.get(
                    url, limit=65536, expected_sha=sha(license_raw)
                )
                (out / "LICENSE.upstream").write_bytes(upstream_raw)
                candidate["license_evidence"]["source_code"].update(
                    actual_upstream_url=url,
                    actual_upstream_commit=profile["upstream_commit"],
                )
                candidate["eligibility"] = assessor.assess(candidate, policy, existing)
                if candidate["eligibility"]["status"] != "eligible_for_controls":
                    raise ValueError(
                        "Eligibility gate: " + repr(candidate["eligibility"])
                    )
                if (out / "failure.json").exists():
                    (out / "failure.json").rename(out / "prior-intake-error.json")
                m.dump(out / "candidate.json", candidate)
                m.dump(
                    out / "completion.json",
                    {
                        "files": {
                            p.relative_to(out).as_posix(): sha(p.read_bytes())
                            for p in sorted(out.rglob("*"))
                            if p.is_file() and p.name != "completion.json"
                        }
                    },
                )
                with lock:
                    successes.append(candidate)
                    with (ROOT / "candidates.jsonl").open("a") as stream:
                        stream.write(json.dumps(candidate, sort_keys=True) + "\n")
                    save()
                completed += 1
                print(
                    json.dumps(
                        {
                            "repo": repo,
                            "materialized": completed,
                            "task_id": row["instance_id"],
                        }
                    ),
                    flush=True,
                )
            except (ValueError, KeyError, TypeError, OSError) as error:
                failure = {
                    "task_id": row["instance_id"],
                    "upstream_repo": repo,
                    "reason": str(error),
                }
                out = ROOT / "tasks" / sha(row["instance_id"].encode())[:24]
                out.mkdir(exist_ok=True, parents=True)
                m.dump(out / "failure.json", failure)
                with lock:
                    failures.append(failure)
                    with (ROOT / "failures.jsonl").open("a") as stream:
                        stream.write(json.dumps(failure, sort_keys=True) + "\n")
                    save()
                print(json.dumps(failure), flush=True)
        return completed

    with ThreadPoolExecutor(max_workers=2) as pool:
        counts = dict(zip(REPOS, pool.map(one_repo, REPOS)))
    m.dump(
        ROOT / "summary.json",
        {
            "materialized": len(successes),
            "repo_counts": counts,
            "repos_at_least_60": sum(x >= 60 for x in counts.values()),
            "failure_reasons": dict(Counter(x["reason"] for x in failures)),
            "received_bytes": fetch.state["received_bytes"],
            "uncertain_bytes": fetch.state["uncertain_bytes"],
            "runtime_qualified": False,
            "training_admissible": False,
            "cloud_launch_ready": False,
            "qwen_calibrated": False,
            "accepted_per_repo_limit": 40,
        },
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["pool", "materialize"])
    parser.add_argument("--per-repo", type=int, default=60)
    args = parser.parse_args()
    pool() if args.action == "pool" else materialize(args.per_repo)
