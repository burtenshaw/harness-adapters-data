"""Derive fresh views, allowing a separate bound results repository."""

import json
import re
import sys
from pathlib import Path
from types import ModuleType

from run import PINS, checked, load

ORIGINAL = "harness-hub/agentic-coding-envs"


def fresh_builder(path, repository, source_repo=ORIGINAL):
    if repository == source_repo == ORIGINAL:
        return load(path)
    if any(
        not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*", r)
        for r in (repository, source_repo)
    ):
        raise ValueError("Expected a repository ID in owner/name form")
    # Bind worker manifests and logical claims to the results repository.
    # Source, sample and phase-catalog objects use the source repository.
    name = "production/derived-dataset-views-corrections-v1/build.py"
    source = checked(path, PINS["operator_files_sha256"][name]).decode()
    substitutions = {
        "def _published(raw, locator):": "def _published(raw, locator, *, repo=SOURCE_REPO):",
        f'locator.get("repo_id") == "{ORIGINAL}"': 'locator.get("repo_id") == repo',
        'record["worker_manifest_bytes"], record["worker_manifest_locator"]': 'record["worker_manifest_bytes"], record["worker_manifest_locator"], repo=RESULTS_REPO',
        '_published(record["claim_bytes"], record["claim_locator"])': '_published(record["claim_bytes"], record["claim_locator"], repo=RESULTS_REPO)',
    }
    if source.count(f'source.get("repo_id") == "{ORIGINAL}"') != 2:
        raise ValueError("Task and claim source bindings changed in pinned builder")
    source = source.replace(
        f'source.get("repo_id") == "{ORIGINAL}"', 'source.get("repo_id") == SOURCE_REPO'
    )
    substitutions[f'accepted.get("repo_id") != "{ORIGINAL}"'] = (
        'accepted.get("repo_id") != SOURCE_REPO'
    )
    if source_repo != ORIGINAL:
        substitutions['len(accepted["configs"]) != 2'] = (
            'len(accepted["configs"]) != len(CONFIGS)'
        )
    for old, new in substitutions.items():
        if source.count(old) != 1:
            raise ValueError("Result-locator binding changed in pinned builder source")
        source = source.replace(old, new)
    builder = ModuleType("fresh_scale800_views")
    builder.__file__ = str(path)
    builder.SOURCE_REPO = source_repo
    builder.RESULTS_REPO = repository
    exec(compile(source, str(path), "exec"), vars(builder))  # noqa: S102 -- digest-bound local operator
    return builder


if __name__ == "__main__":
    code, repo, source_repo, accepted, manifest, output, *sample = sys.argv[1:]
    b = fresh_builder(Path(code), repo, source_repo)
    records, claims = b.read_result_manifest(Path(manifest))
    source = b.parsed(Path(accepted).read_bytes())
    if source_repo != ORIGINAL:
        configs = source.get("configs")
        if (
            not isinstance(configs, list)
            or not configs
            or set(configs) - b.CONFIGS.keys()
        ):
            raise ValueError("Fresh views need the immutable registered source capture")
        b.CONFIGS = {key: b.CONFIGS[key] for key in configs}
    result = b.derive(
        source,
        records,
        claims,
        b.read_sample_manifest(Path(sample[0])) if sample else None,
    )
    result["proof"]["results_repository"] = repo
    result["proof"]["source_repository"] = source_repo
    result["proof"]["files"] = {
        name: b.sha(raw) for name, raw in result["files"].items()
    }
    b.write_local(Path(output), result)
    print(json.dumps(result["summary"], sort_keys=True))
