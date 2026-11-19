"""Restore a fresh trusted grader BASE before replaying its complete solver delta."""

import argparse
import json
import re
import stat
import subprocess
from pathlib import Path, PurePosixPath


def canonical(value):
    if not isinstance(value, str):
        raise ValueError("Regular canonical repository paths required")
    path = PurePosixPath(value)
    if (
        not re.fullmatch(r"[A-Za-z0-9_+./@-]+", value)
        or path.is_absolute()
        or path.as_posix() != value
        or any(p in {".", "..", ".git"} for p in path.parts)
    ):
        raise ValueError("Regular canonical repository paths required")
    return path


def destination(workspace, value):
    relative = canonical(value)
    parent = workspace
    for part in relative.parts[:-1]:
        parent = parent / part
        try:
            mode = parent.lstat().st_mode
        except FileNotFoundError:
            break
        if not stat.S_ISDIR(mode):
            raise ValueError("Patch destination ancestor is not an ordinary directory")
    path = workspace / str(relative)
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return path, False
    if (
        not stat.S_ISREG(mode)
        or mode & 0o7000
        or stat.S_IMODE(mode) not in {0o644, 0o755}
    ):
        raise ValueError(
            "Existing new-file destination is not an ordinary regular file"
        )
    return path, True


def git(workspace, *args):
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
        cwd=workspace,
        env={
            "PATH": "/usr/bin:/bin",
            "HOME": "/nonexistent",
            "GIT_DIR": str(workspace / ".git"),
            "GIT_WORK_TREE": str(workspace),
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
        },
        check=True,
        capture_output=True,
        timeout=120,
    ).stdout


def names(raw):
    return {value.decode("utf-8") for value in raw.split(b"\0") if value}


def restore(workspace, base, new_files):
    workspace = Path(workspace)
    if (
        not workspace.is_absolute()
        or workspace.resolve() != workspace
        or not workspace.is_dir()
        or workspace.is_symlink()
        or not (workspace / ".git").is_dir()
        or (workspace / ".git").is_symlink()
    ):
        raise ValueError("Fresh canonical worktree and Git database required")
    if (
        not re.fullmatch(r"[0-9a-f]{40}", base)
        or not isinstance(new_files, list)
        or len(new_files) > 512
        or len(set(new_files)) != len(new_files)
    ):
        raise ValueError("Pinned BASE and unique bounded new-file paths required")
    # Validate every destination before any reset or deletion; links, directories,
    # special files and index-tracked conflicts are not cleanup candidates.
    targets = [destination(workspace, value)[0] for value in new_files]
    if git(workspace, "cat-file", "-t", base).strip() != b"commit":
        raise ValueError("Pinned BASE commit is unavailable")
    tracked_base = names(git(workspace, "ls-tree", "-r", "--name-only", "-z", base))
    tracked_index = names(git(workspace, "ls-files", "-z"))
    if any(value in tracked_base or value in tracked_index for value in new_files):
        raise ValueError("New-file patch conflicts with a tracked destination")
    info = workspace / ".git/info"
    if info.is_symlink() or not info.is_dir():
        raise ValueError("Ordinary Git info directory required")
    attrs = info / "attributes"
    if attrs.is_symlink() or (attrs.exists() and not attrs.is_file()):
        raise ValueError("Ordinary Git attribute override required")
    attrs.write_text("* -text -filter -ident\n")
    git(workspace, "reset", "--hard", base)
    for value, path in zip(new_files, targets, strict=True):
        _, exists = destination(workspace, value)
        if exists:
            path.unlink()
    return {
        "base_commit": base,
        "new_file_paths": new_files,
        "unsubmitted_untracked_files_retained": True,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--new-files-json", required=True)
    args = parser.parse_args()
    restore(args.workspace, args.base, json.loads(args.new_files_json))
