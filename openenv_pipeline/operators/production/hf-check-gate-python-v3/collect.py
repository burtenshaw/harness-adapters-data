"""Controller-installed worktree collector. Runs inside a dedicated Job only."""

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from pathlib import Path, PurePosixPath

TRANSIENT = {
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".hypothesis",
    ".venv",
    "venv",
    ".tox",
    ".cache",
}
MAX_FILES, MAX_FILE, MAX_TREE, MAX_PATCH = (
    20000,
    32 * 1024**2,
    256 * 1024**2,
    16 * 1024**2,
)


def safe(name):
    path = PurePosixPath(name)
    if (
        not name
        or any(ord(c) < 32 or ord(c) > 126 or c in '\\"' for c in name)
        or path.is_absolute()
        or path.as_posix() != name
        or any(p in {".", "..", ".git"} for p in path.parts)
    ):
        raise ValueError("Unsupported repository path")
    return path


def git(gitdir, worktree, index, *args):
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": "/nonexistent",
        "GIT_DIR": str(gitdir),
        "GIT_WORK_TREE": str(worktree),
        "GIT_INDEX_FILE": str(index),
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
    }
    return subprocess.run(
        [
            "/usr/bin/git",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.autocrlf=false",
            "-c",
            "core.fileMode=true",
            "-c",
            "core.ignoreCase=false",
            *args,
        ],
        env=env,
        cwd=worktree,
        capture_output=True,
        check=True,
        timeout=120,
    ).stdout


def copy_surface(workspace, destination, tracked):
    files = {}
    total = 0
    for directory, dirs, names in os.walk(workspace, followlinks=False):
        rel = Path(directory).relative_to(workspace)
        for name in list(dirs):
            path = Path(directory) / name
            relative = (rel / name).as_posix()
            if path.is_symlink():
                raise ValueError("Submitted directory symlinks unsupported")
            if name in TRANSIENT and not any(
                p == relative or p.startswith(relative + "/") for p in tracked
            ):
                dirs.remove(name)
        for name in sorted(names):
            path = Path(directory) / name
            relative = (rel / name).as_posix()
            if relative == ".git":
                continue
            safe(relative)
            info = path.lstat()
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_mode & 0o7000
                or info.st_size > MAX_FILE
            ):
                raise ValueError("Unsupported submitted file")
            mode = stat.S_IMODE(info.st_mode)
            if mode not in {0o644, 0o755}:
                raise ValueError("Unsupported submitted mode")
            raw = path.read_bytes()
            total += len(raw)
            if len(raw) != info.st_size or total > MAX_TREE or len(files) >= MAX_FILES:
                raise ValueError("Submitted worktree envelope exceeded")
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
            target.chmod(mode)
            files[relative] = {
                "sha256": hashlib.sha256(raw).hexdigest(),
                "mode": oct(mode),
                "bytes": len(raw),
            }
    return files


def collect(workspace, gitdir, base, output):
    if not re.fullmatch(r"[0-9a-f]{40}", base):
        raise ValueError("Immutable base commit required")
    workspace, gitdir, output = Path(workspace), Path(gitdir), Path(output)
    with tempfile.TemporaryDirectory(prefix="openenv-patch-") as directory:
        root = Path(directory)
        tree = root / "tree"
        tree.mkdir()
        index = root / "index"
        if git(gitdir, tree, index, "cat-file", "-t", base).strip() != b"commit":
            raise ValueError("Expected base commit unavailable")
        git(gitdir, tree, index, "fsck", "--full", "--no-reflogs")
        entries = {}
        for raw_entry in git(gitdir, tree, index, "ls-tree", "-r", "-z", base).split(
            b"\0"
        ):
            if not raw_entry:
                continue
            metadata, raw_name = raw_entry.split(b"\t", 1)
            mode, kind, oid = metadata.decode("ascii").split(" ")
            name = raw_name.decode("utf-8")
            safe(name)
            entries[name] = {"mode": mode, "kind": kind, "oid": oid}
        tracked = set(entries)
        gitlinks = {
            name: entry["oid"]
            for name, entry in entries.items()
            if entry["mode"] == "160000"
        }
        for name in gitlinks:
            parent = workspace
            for part in safe(name).parts[:-1]:
                parent = parent / part
                if parent.is_symlink() or not parent.is_dir():
                    raise ValueError("Changed baseline gitlink ancestor unsupported")
            path = workspace / name
            if path.is_symlink() or not path.is_dir() or any(path.iterdir()):
                raise ValueError("Changed baseline gitlink unsupported")
        for path in tracked:
            safe(path)
        # A fresh index prevents assume-unchanged, skip-worktree, agent commits,
        # ignored paths or staged-only edits from hiding actual working files.
        git(gitdir, tree, index, "read-tree", base)
        info = gitdir / "info"
        info.mkdir(exist_ok=True)
        (info / "attributes").write_text("* -text -filter -ident\n")
        files = copy_surface(workspace, tree, tracked)
        git(gitdir, tree, index, "add", "--all", "--force")
        for name, oid in gitlinks.items():
            git(
                gitdir,
                tree,
                index,
                "update-index",
                "--add",
                "--cacheinfo",
                "160000," + oid + "," + name,
            )
        raw = git(
            gitdir,
            tree,
            index,
            "diff",
            "--cached",
            "--binary",
            "--full-index",
            "--no-renames",
            "--no-ext-diff",
            "--no-textconv",
            base,
        )
        if len(raw) > MAX_PATCH:
            raise ValueError("Patch exceeds transfer envelope")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(raw)
        output.with_suffix(".inventory.json").write_text(
            json.dumps(
                {
                    "base_commit": base,
                    "patch_sha256": hashlib.sha256(raw).hexdigest(),
                    "files": files,
                    "new_deleted_files_and_executable_modes_supported": True,
                    "hostile_code_isolation_established": False,
                },
                sort_keys=True,
            )
            + "\n"
        )
        return raw


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--workspace", required=True)
    p.add_argument("--git-dir", required=True)
    p.add_argument("--base", required=True)
    p.add_argument("--output", required=True)
    a = p.parse_args()
    collect(a.workspace, a.git_dir, a.base, a.output)
