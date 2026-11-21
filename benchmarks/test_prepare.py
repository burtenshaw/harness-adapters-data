import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from benchmarks import prepare, sec_bench_pro_inventory


class IntakeTest(unittest.TestCase):
    def test_sec_bench_pro_panel_and_holdout_aliases(self):
        profile_path = sec_bench_pro_inventory.PROFILE
        profile = prepare.read(profile_path)
        counts = sec_bench_pro_inventory.verify(profile)
        self.assertEqual(counts, {"v8": 103, "sm": 104, "linux": 137})
        panel = prepare.read(profile_path.with_name("sec-bench-pro-panel.json"))

        # Give copies of the same eligible PR different provenance, in separate intakes.
        probes = [
            ({"repository_lineage": [repo]}, "benchmark repository overlap")
            for repo in ("v8/v8", "mozilla-firefox/firefox", "torvalds/linux")
        ]
        for project in counts:
            qualified = next(
                value
                for value in profile["holdout_task_ids"]
                if value.startswith(project + "__")
            )
            for alias in (qualified, qualified.split("__")[1]):
                probes.append(
                    (
                        {"source_task_ids": [alias]},
                        "benchmark identity or evaluation-only source",
                    )
                )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            baseline = root / "baseline.jsonl"
            baseline.write_bytes(b"")
            with patch.dict(prepare.DIGESTS, {prepare.BASELINE_VIEW: prepare.sha(b"")}):
                report = prepare.setup(
                    profile_path,
                    profile_path.with_name("sec-bench-pro-panel.json"),
                    root / "eligible",
                    baseline,
                )
                self.assertEqual(report["eligible_candidates"], len(panel))
                self.assertEqual(
                    prepare.read(root / "eligible/generation-spec.json")["candidates"],
                    panel,
                )
                for i, (fields, reason) in enumerate(probes):
                    with self.subTest(fields=fields):
                        path, output = root / "panel.json", root / str(i)
                        path.write_text(json.dumps([{**panel[0], **fields}]))
                        report = prepare.setup(profile_path, path, output, baseline)
                        self.assertEqual(report["decisions"][0]["reasons"], [reason])
                        self.assertFalse((output / "generation-spec.json").exists())

    def test_panel_routing_and_holdouts(self):
        profile = prepare.read(prepare.ROOT / "benchmarks/original-benchmarks.json")
        example = prepare.read(prepare.ROOT / "benchmarks/example-panel.json")[0]
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            baseline = root / "baseline.jsonl"
            baseline.write_text(
                '{"task_id":"accepted","source_pr_url":"https://github.com/bench-example/toy/pull/7"}\n'
            )
            profile["holdout_prs"] = ["https://github.com/bench-example/toy/pull/8"]
            profile["holdout_task_ids"] = ["held-out-case"]
            profile_file, panel_file = root / "profile.json", root / "panel.json"
            profile_file.write_text(json.dumps(profile))
            panel = []
            # Give each candidate distinct source pins so each exclusion stands on its own.
            for i in range(1, 9):
                panel.append(
                    {
                        **example,
                        "url": f"https://github.com/bench-example/toy/pull/{i}",
                        "expected": {
                            "id": f"{i:012x}",
                            "base": "b" * 40,
                            "head": f"{i:040x}",
                            "full_diff_sha256": f"{i:064x}",
                        },
                    }
                )
            panel[1]["repository_lineage"] = ["datacurve-ai/deep-swe"]
            panel[2]["source_task_id"] = "held-out-case"
            panel[3]["url"] = panel[0]["url"].replace("toy", "TOY") + "/"
            panel[4]["capability_tags"] = ["unrequested"]
            panel[5]["evaluation_only"] = True
            panel_file.write_text(json.dumps(panel))
            with patch.dict(
                prepare.DIGESTS,
                {prepare.BASELINE_VIEW: prepare.sha(baseline.read_bytes())},
            ):
                report = prepare.setup(profile_file, panel_file, root / "new", baseline)
                self.assertEqual(report["eligible_candidates"], 1)
                self.assertEqual(
                    [row["reasons"] for row in report["decisions"]],
                    [
                        [],
                        ["benchmark repository overlap"],
                        ["benchmark identity or evaluation-only source"],
                        ["duplicate within panel"],
                        ["no requested capability"],
                        ["benchmark identity or evaluation-only source"],
                        ["previously seen source"],
                        ["benchmark identity or evaluation-only source"],
                    ],
                )
                self.assertEqual(
                    prepare.read(root / "new/generation-spec.json")["candidates"],
                    [panel[0]],
                )
                with self.assertRaises(FileExistsError):
                    prepare.setup(profile_file, panel_file, root / "new", baseline)
                accepted = root / "accepted.jsonl"
                accepted.write_text(
                    json.dumps({"task_id": "added", "source_pr_url": panel[0]["url"]})
                    + "\n"
                )
                second = prepare.setup(
                    profile_file, panel_file, root / "next", baseline, [accepted]
                )
                self.assertEqual(second["eligible_candidates"], 0)
                self.assertFalse((root / "next/generation-spec.json").exists())
            with self.assertRaisesRegex(ValueError, "Baseline differs"):
                prepare.setup(profile_file, panel_file, root / "bad", baseline)


if __name__ == "__main__":
    unittest.main()
