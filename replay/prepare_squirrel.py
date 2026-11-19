"""Replay the published selection and prepare one Harbor task for OpenEnv."""
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from huggingface_hub import HfApi, hf_hub_download

DATASET = "harness-hub/harness-adapters"
REVISION = "5d320e93b7832c6c66e6a5acd8403fb1a3c50bc6"
EXAMPLE = "Masterminds__squirrel.1ded5784.func_pm_ctrl_invert_if__coeoegdw"
IMAGE = "ghcr.io/younesbelkada/scale800@sha256:cd0de0ae59370446f702c6afe6fddc72105cc8f4ec2285520dff1c571c2f4b03"


def download(name):
    return Path(hf_hub_download(DATASET, name, repo_type="dataset", revision=REVISION, token=False))


def rows(view):
    return [json.loads(line) for line in download(f"views/{view}/train.jsonl").read_text().splitlines()]


def main():
    tasks = rows("final_v1")
    scored = [r for r in tasks if r["qwen_status"] == "scored"]
    mixed = [r for r in scored if 0 < r["qwen_solved"] < r["qwen_valid_attempts"]]
    assert sorted(r["task_path"] for r in mixed) == sorted(r["task_path"] for r in rows("final_best_v1"))
    print(f"{len(tasks)} tasks, {len(scored)} scored, {len(mixed)} with mixed rewards")

    row = next(r for r in mixed if r["task_id"] == EXAMPLE)
    print(f"Squirrel: {row['qwen_solved']} solved in {row['qwen_valid_attempts']} attempts")
    report = json.loads(download(row["gate_report_path"]).read_text())
    for role, scores in report["exact_reward_maps"].items():
        print(role, scores["reward"])

    task = Path("squirrel-task")
    task.mkdir(exist_ok=False)
    prefix = row["task_path"]
    files = HfApi(token=False).list_repo_tree(
        DATASET, path_in_repo=prefix, repo_type="dataset", revision=REVISION, recursive=True
    )

    def copy_file(name):
        dest = task / Path(name).relative_to(prefix)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(download(name).read_bytes())

    with ThreadPoolExecutor(max_workers=6) as pool:
        list(pool.map(copy_file, [f.path for f in files if hasattr(f, "blob_id")]))

    manifest = task / "task.toml"
    text = manifest.read_text()
    assert text.count("[environment]\n") == 1 and "docker_image" not in text
    manifest.write_text(text.replace("[environment]\n", f'[environment]\ndocker_image = "{IMAGE}"\n'))
    print(f"Prepared {task.resolve()}")


if __name__ == "__main__":
    main()
