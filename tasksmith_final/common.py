"""Read and bind local Tasksmith inputs using the historical OpenEnv tree digest."""

import hashlib
import json
import re
import os
import stat
import tempfile
from pathlib import Path


def require(ok, message):
    if not ok:
        raise ValueError(message)


def read(path):
    return json.loads(path.read_text())


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(json.dumps(value, indent=1) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        except BaseException:
            temporary.unlink()
            raise
    temporary.replace(path)


def jsonl(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inside(root, relative):
    path = Path(relative)
    require(
        path.parts and not path.is_absolute() and ".." not in path.parts,
        f"unsafe path {path}",
    )
    dest = root / path
    require(dest.resolve() == root.resolve() / path, f"symlink in path {path}")
    return dest


def source_digest(root):
    excluded = {".git", "__pycache__", ".venv", ".worktrees", "outputs"}
    digest = hashlib.sha256()
    for rel in sorted(p.relative_to(root).as_posix() for p in root.rglob("*")):
        if excluded.intersection(Path(rel).parts):
            continue
        path = root / rel
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        require(stat.S_ISREG(mode), f"non-regular task file {rel}")
        digest.update(rel.encode() + b"\0")
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
        digest.update(b"\0")
    return digest.hexdigest()


def candidates(paths):
    result = {}
    for path in paths:
        seen = set()
        for row in jsonl(path):
            if row.get("tasksmith_verified") is not True:
                continue
            tid = row["task_id"]
            require(
                re.fullmatch(r"tasksmith-[0-9a-f]{12}", tid), f"invalid task ID {tid}"
            )
            require(tid not in seen, f"repeated verified task in {path}: {tid}")
            require(Path(row["task_path"]).name == tid, f"task path differs for {tid}")
            seen.add(tid)
            result[tid] = [path.stem, row]
    return result


def scan_credentials(data):
    tokens = (
        os.environ.get(name, "")
        for name in (
            "HF_TOKEN",
            "HF_SANDBOX_TOKEN",
            "HF_INFERENCE_TOKEN",
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
        )
    )
    if re.search(rb"hf_[a-zA-Z0-9]{20,}", data) or any(
        len(token) >= 12 and token.encode() in data for token in tokens
    ):
        raise ValueError("credential detected in publication payload")
