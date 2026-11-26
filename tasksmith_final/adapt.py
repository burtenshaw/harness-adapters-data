"""HF Sandbox transform from the historical Tasksmith final run."""

import hashlib
import json
import re
import shutil
import tomllib

from common import source_digest

ORIGINAL_TEST_SH = (
    "#!/bin/sh\nset -eu\nexec /usr/local/bin/python -B -I -S /tests/grade.py\n"
)
NEW_TEST_SH = """#!/bin/sh
set -eu
# HF Sandbox variant: the verifier starts from the task image, not tests/Dockerfile.
# Recreate that image's grader user and hidden source tree without replacing the
# submitted artifacts that Harbor has already copied into /workspace.
id -u grader >/dev/null 2>&1 || useradd -m -u 1001 grader
tar -C /tests/source -cf - . | tar -C /workspace -xf - --skip-old-files --no-same-owner
exec /usr/local/bin/python -B -I -S /tests/grade.py
"""
TESTS_DOCKERFILE_TAIL = [
    "RUN useradd -m -u 1001 grader",
    "COPY grade.py test_driver.py test_results.py contract.json test.sh /tests/",
    "RUN chmod 755 /tests && chmod 644 /tests/*",
]
ENV_DOCKERFILE_TAIL = [
    "RUN apt-get update && apt-get install -y --no-install-recommends tmux && rm -rf /var/lib/apt/lists/*",
    "RUN useradd -m learner && chown -R learner:learner /workspace",
]
CHANGES = [
    "network_mode no-network -> public for environment, agent, verifier and verifier.environment",
    "removed agent.user (learner) and verifier.user (root); every phase runs as the image default user (root)",
    "environment.docker_image pinned to the public starter image built from environment/ only",
    "removed tests/Dockerfile; the separate verifier starts from the task image and Harbor uploads tests/ at grading time",
    "tests/test.sh recreates the grader user (uid 1001) and unpacks tests/source into /workspace without overwriting submitted files",
    "added validation/openenv.json (harbor-semantic-v1 contract)",
    "task.name gains the suffix -hfsandbox",
]


def lines(path):
    return [line for line in path.read_text().splitlines() if line.strip()]


def modify(original, receipt, out, relative, revision):
    task_id = original.name
    toml_text = (original / "task.toml").read_text()
    config = tomllib.loads(toml_text)
    # Every original must have exactly the shape the changes assume.
    assert config["task"]["name"] == f"repo2rlenv/{task_id}"
    assert [
        config["environment"]["network_mode"],
        config["agent"]["network_mode"],
        config["verifier"]["network_mode"],
        config["verifier"]["environment"]["network_mode"],
    ] == ["no-network"] * 4
    assert (config["agent"]["user"], config["verifier"]["user"]) == ("learner", "root")
    assert config["verifier"]["environment_mode"] == "separate"
    assert (
        "docker_image" not in config["environment"]
        and "workdir" not in config["environment"]
    )
    assert (original / "tests/test.sh").read_text() == ORIGINAL_TEST_SH
    env_lines, test_lines = (
        lines(original / "environment/Dockerfile"),
        lines(original / "tests/Dockerfile"),
    )
    assert (
        env_lines[-2:] == ENV_DOCKERFILE_TAIL
        and test_lines[-3:] == TESTS_DOCKERFILE_TAIL
    )
    assert env_lines[:-2] == test_lines[:-3], (
        "verifier image base differs from the task image"
    )
    assert "COPY source /workspace" in env_lines and not any(
        p.is_symlink() for p in (original / "tests/source").rglob("*")
    )
    assert receipt["status"] == "resolved" and re.fullmatch(
        r"[^\s@]+@sha256:[0-9a-f]{64}", receipt["image"]
    )

    shutil.copytree(original, out, ignore=shutil.ignore_patterns(".complete"))
    (out / "tests/Dockerfile").unlink()
    (out / "tests/test.sh").write_text(NEW_TEST_SH)

    text = toml_text.replace('network_mode = "no-network"', 'network_mode = "public"')
    assert text.count('network_mode = "public"') == 4
    for old in ('\nuser = "learner"\n', '\nuser = "root"\n'):
        assert text.count(old) == 1
        text = text.replace(old, "\n")
    text = text.replace(
        f'name = "repo2rlenv/{task_id}"', f'name = "repo2rlenv/{task_id}-hfsandbox"', 1
    )
    text = text.replace(
        "\n[environment]\n",
        f'\n[environment]\ndocker_image = "{receipt["image"]}"\n',
        1,
    )
    provenance = {
        "variant": "hf-sandbox-v1",
        "task_modified_for_hf_sandbox": True,
        "network_enabled": True,
        "original_network_mode": "no-network",
        "users_dropped": True,
        "original_agent_user": "learner",
        "original_verifier_user": "root",
        "original_path": relative,
        "original_dataset_revision": revision,
        "original_task_toml_sha256": hashlib.sha256(toml_text.encode()).hexdigest(),
        "original_bundle_hash": config["metadata"]["repo2env"]["bundle_hash"],
        "original_source_digest": source_digest(original),
        "changes": CHANGES,
    }
    if receipt.get("space_id") is not None:
        provenance["starter_space"] = receipt["space_id"]
        provenance["starter_space_commit"] = receipt["space_commit"]
    else:
        provenance["image_builder"] = receipt.get("builder", "oci")
        provenance["image_registry_digest"] = receipt["registry_digest"]
        if receipt.get("tag"):
            provenance["image_tag"] = receipt["tag"]
        if receipt.get("job_id"):
            provenance["image_build_job_id"] = receipt["job_id"]
        if receipt.get("extra_dockerfile_sha256"):
            provenance["extra_dockerfile_sha256"] = receipt["extra_dockerfile_sha256"]
    text += "\n[metadata.openenv_hf_sandbox]\n" + "".join(
        f"{key} = {json.dumps(value)}\n" for key, value in provenance.items()
    )
    (out / "task.toml").write_text(text)

    new = tomllib.loads(text)
    assert new["environment"]["docker_image"] == receipt["image"]
    assert "user" not in new["agent"] and "user" not in new["verifier"]
    assert {
        new["environment"]["network_mode"],
        new["agent"]["network_mode"],
        new["verifier"]["network_mode"],
        new["verifier"]["environment"]["network_mode"],
    } == {"public"}
    contract = {
        "profile": "harbor-semantic-v1",
        "reward_key": "reward",
        "reward": {"range": [0, 1], "oracle_tolerance": 0, "floor_margin": 0.1},
        "resources": {
            "cpu": config["environment"]["cpus"],
            "memory_mb": config["environment"]["memory_mb"],
            "disk_mb": 10240,
            "episode_timeout_s": 600,
        },
        "types": {"tags": ["swe"]},
        "original_source_digest": provenance["original_source_digest"],
        "requires_credentials": False,
    }
    (out / "validation").mkdir()
    (out / "validation/openenv.json").write_text(json.dumps(contract, indent=1) + "\n")
    # Everything not named in CHANGES is byte-identical to the original.
    before = {
        p.relative_to(original).as_posix(): p.read_bytes()
        for p in original.rglob("*")
        if p.is_file() and p.name != ".complete"
    }
    after = {
        p.relative_to(out).as_posix(): p.read_bytes()
        for p in out.rglob("*")
        if p.is_file()
    }
    changed = {k for k in before.keys() & after.keys() if before[k] != after[k]}
    assert changed == {"task.toml", "tests/test.sh"}, changed
    assert before.keys() - after.keys() == {"tests/Dockerfile"}
    assert after.keys() - before.keys() == {"validation/openenv.json"}
    return provenance
