"""Build the historical JSONL views and retain every row in the supplied base."""

import json
import shutil
import tempfile
import stat
from pathlib import Path

from common import inside, jsonl, read, require, sha, source_digest, write
from evidence import attempts, gate
from rows import MOD_COLUMNS, ORIGIN, PROTOCOL, task_row


def write_jsonl(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))


def copy_input(root, relative, destination):
    source = inside(root, relative)
    require(
        source.is_dir()
        and all(
            stat.S_ISREG(p.lstat().st_mode) or stat.S_ISDIR(p.lstat().st_mode)
            for p in source.rglob("*")
        ),
        f"invalid private input tree: {relative}",
    )
    shutil.copytree(source, inside(destination, relative))


def stage(run, out, cfg, *, historical=False):
    require(not out.exists(), f"output already exists: {out}")
    base_path = Path(cfg["base"])
    require(sha(base_path) == cfg["base_sha256"], "base bytes changed")
    base = jsonl(base_path)
    require(
        len({row["task_id"] for row in base}) == len(base), "duplicate task IDs in base"
    )
    src_rows = cfg["selected"]
    require(
        not {r["task_id"] for r in base}.intersection(src_rows),
        "base/expansion ID collision",
    )
    mods = read(run / "modified/modifications.json")
    require(
        set(mods) == set(src_rows), "prepared task IDs differ from the input manifest"
    )
    prefix, tag = cfg["prefix"], cfg["tag"]
    out.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=out.parent) as tmp:
        pub = Path(tmp) / "export"
        final, rejected = [], []
        for row in base:
            if "task_origin" in row:
                require(set(MOD_COLUMNS) <= row.keys(), "incomplete prior-final schema")
                final.append(row)
            else:
                final.append(
                    {
                        **row,
                        "task_origin": ORIGIN.get(
                            row["source_dataset"], row["source_dataset"]
                        ),
                        **dict.fromkeys(MOD_COLUMNS),
                    }
                )
        for tid in sorted(src_rows):
            split, src = src_rows[tid]
            mod = mods[tid]
            require(
                mod["path"] == f"{prefix}/tasks/{tid}"
                and mod["original_path"] == src["task_path"],
                f"modified source mismatch for {tid}",
            )
            require(
                mod["original_dataset_revision"] == cfg["revision"],
                f"source revision mismatch for {tid}",
            )
            if "tasksmith_bundle_hash" in src:
                require(
                    mod["original_bundle_hash"] == src["tasksmith_bundle_hash"],
                    f"source bundle mismatch for {tid}",
                )
            if not historical:
                inputs = Path(cfg["sources"])
                require(
                    source_digest(inside(inputs, src["task_path"]))
                    == mod["original_source_digest"],
                    f"original task changed since preparation: {tid}",
                )
                require(
                    source_digest(inside(inputs, src["provenance_path"]))
                    == cfg["provenance_digests"][tid],
                    f"original provenance changed for {tid}",
                )
                copy_input(inputs, src["task_path"], pub)
                copy_input(inputs, src["provenance_path"], pub)
            task = inside(run / "modified", mod["path"])
            report, rewards, reasons = gate(run, tid, mod)
            image = read(run / "images" / f"{tid}.json")
            require(
                image["task_id"] == tid
                and image["status"] == "resolved"
                and image["image"] == mod["image"]
                and image["space_commit"] == mod["starter_space_commit"],
                f"starter receipt mismatch for {tid}",
            )
            shutil.copytree(task, pub / mod["path"])
            inventory = {
                p.relative_to(task).as_posix(): sha(p)
                for p in sorted(task.rglob("*"))
                if p.is_file()
            }
            inventory_bytes = (
                json.dumps(
                    {"task_path": mod["path"], "files": inventory},
                    indent=1,
                    sort_keys=True,
                )
                + "\n"
            ).encode()
            path = pub / prefix / "inventories" / f"{tid}.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(inventory_bytes)
            image_dir = pub / prefix / "images"
            image_dir.mkdir(exist_ok=True)
            shutil.copyfile(run / "images" / f"{tid}.json", image_dir / f"{tid}.json")
            vdir = pub / prefix / "validation" / tid
            evidence = run / "validation" / "final" / f"{tid}.artifacts"
            if evidence.is_dir():
                shutil.copytree(evidence, vdir)
            else:
                vdir.mkdir(parents=True)
                shutil.copyfile(
                    run / "validation" / "final" / f"{tid}.json", vdir / "report.json"
                )
            if reasons:
                rejected.append(
                    {
                        "task_id": tid,
                        "task_path": mod["path"],
                        "original_task_path": src["task_path"],
                        "original_split": split,
                        "validation_report_path": f"{prefix}/validation/{tid}/report.json",
                        "validation_verdict": report["verdict"],
                        "nop_reward": rewards.get("nop"),
                        "oracle_reward": rewards.get("oracle"),
                        "oracle_replay_reward": rewards.get("oracle-replay"),
                        "network_enabled": True,
                        "original_network_mode": "no-network",
                        "users_dropped": True,
                        "task_modified_for_hf_sandbox": True,
                        "stage": "validation",
                        "reason": "; ".join(reasons),
                    }
                )
                continue
            records = attempts(run, tid, report["source_digest"], historical=historical)
            for index, record in enumerate(records):
                write(
                    pub / "results" / PROTOCOL / tid / f"attempt-{index}.json", record
                )
            row = task_row(
                task_id=tid,
                task_dir=task,
                mod=mod,
                src=src,
                split=split,
                records=records,
                prefix=prefix,
                revision=cfg["revision"],
                inventory_bytes=inventory_bytes,
            )
            final.append(
                {
                    **row,
                    "task_origin": "tasksmith",
                    "network_enabled": True,
                    "original_network_mode": "no-network",
                    "users_dropped": True,
                    "task_modified_for_hf_sandbox": True,
                }
            )
        require(
            all(set(row) == set(final[0]) and len(row) == 62 for row in final),
            "expected common final 62-column schema",
        )
        best = [
            r
            for r in final
            if r["qwen_solved"] is not None
            and r["qwen_valid_attempts"]
            and 0 < r["qwen_solved"] < r["qwen_valid_attempts"]
        ]
        write_jsonl(pub / f"views/final_{tag}/train.jsonl", final)
        write_jsonl(pub / f"views/final_best_{tag}/train.jsonl", best)
        if rejected:
            import pyarrow as pa
            import pyarrow.parquet as pq

            schema = pa.schema(
                [
                    (
                        k,
                        pa.float64()
                        if k.endswith("_reward")
                        else (
                            pa.bool_()
                            if k
                            in (
                                "network_enabled",
                                "users_dropped",
                                "task_modified_for_hf_sandbox",
                            )
                            else pa.string()
                        ),
                    )
                    for k in rejected[0]
                ]
            )
            path = pub / f"views/tasksmith_final_rejected_{tag}/train.parquet"
            path.parent.mkdir(parents=True)
            pq.write_table(pa.Table.from_pylist(rejected, schema=schema), path)
        additions = final[len(base) :]
        summary = {
            "tasksmith_candidates": len(src_rows),
            "validation_passed": len(additions),
            "validation_rejected": len(rejected),
            "qwen_scored": sum(r["qwen_status"] == "scored" for r in additions),
            "qwen_incomplete": sum(r["qwen_status"] != "scored" for r in additions),
            f"final_{tag}_rows": len(final),
            f"final_best_{tag}_rows": len(best),
            f"final_best_{tag}_tasksmith_rows": sum(
                r["task_origin"] == "tasksmith" for r in best
            ),
        }
        write(pub / "publish-summary.json", summary)
        if not historical:
            write_jsonl(
                pub / prefix / "inputs.jsonl",
                [src_rows[k][1] for k in sorted(src_rows)],
            )
            write(pub / prefix / "summary.json", summary)
        pub.rename(out)
    return summary
