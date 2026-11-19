"""Read the registered accepted indexes at an immutable dataset revision."""

import re
import sys
from pathlib import Path

from huggingface_hub import hf_hub_download
from run import load


def capture(module, repo, revision, output, snapshot=None):
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("Supply the immutable source dataset commit")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*", repo):
        raise ValueError("Expected a source dataset ID in owner/name form")
    if snapshot and (
        snapshot.name != revision
        or snapshot.parent.name != "snapshots"
        or snapshot.parent.parent.name != "datasets--" + repo.replace("/", "--")
    ):
        raise ValueError("Expected the corresponding Hub cache repo/snapshots/REVISION")

    def read(name):
        path = (
            snapshot / name
            if snapshot
            else Path(
                hf_hub_download(repo, name, repo_type="dataset", revision=revision)
            )
        )
        if path.stat().st_size > module.MAX_FILE_BYTES:
            raise ValueError(
                "Registered source metadata exceeds the historical size limit"
            )
        return path.read_bytes()

    card = read("README.md")
    if repo != module.REPO:
        metadata, _ = module.metadata(card)
        declared = {c["config_name"] for c in metadata.get("configs", [])}
        module.ACCEPTED_CONFIGS = tuple(
            c for c in module.ACCEPTED_CONFIGS if c in declared
        )
        if not module.ACCEPTED_CONFIGS:
            raise ValueError("Source dataset has no registered Scale800 accepted split")
    indexes = module.accepted_paths(card)
    rows, hashes, by_path = [], {}, {}
    for config, paths in indexes.items():
        for path in paths:
            raw = read(path)
            hashes[path] = module.sha(raw)
            for line in raw.splitlines():
                row = module.parsed(line)
                if (
                    row.get("language") != module.LANGUAGES[config]
                    or by_path.setdefault(row["task_path"], row) != row
                ):
                    raise ValueError("Split identity or task-path conflict")
                rows.append(row)
    payload = {
        "repo_id": repo,
        "revision": revision,
        "configs": list(module.ACCEPTED_CONFIGS),
        "rows": rows,
        "index_sha256": hashes,
    }
    with output.open("xb") as stream:
        stream.write(module.encode(payload))
    print(f"{len(rows)} accepted source records at {revision}")


if __name__ == "__main__":
    code, repo, revision, output, *snapshot = sys.argv[1:]
    capture(
        load(Path(code)),
        repo,
        revision,
        Path(output),
        Path(snapshot[0]) if snapshot else None,
    )
