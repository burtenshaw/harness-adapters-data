import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from benchmarks import prepare


class IntakeTest(unittest.TestCase):
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
