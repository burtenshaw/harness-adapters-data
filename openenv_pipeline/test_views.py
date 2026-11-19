"""Exercise fresh registration across distinct source and worker repositories."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from accepted import capture
from run import OPERATORS, load
from views import fresh_builder


class RegisteredViews(unittest.TestCase):
    def test_python_only_private_source_with_distinct_results_repo(self):
        ops = OPERATORS / "production/derived-dataset-views-corrections-v1"
        revision = "a" * 40
        source_repo, results_repo = "example/source", "example/results"
        row = {
            "task_id": "sample-task",
            "language": "python",
            "gate_passed": True,
            "task_path": "tasks/example",
            "task_source_sha256": "f" * 64,
            "task_inventory_sha256": "e" * 64,
        }
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            snapshot = root / "datasets--example--source/snapshots" / revision
            (snapshot / "splits").mkdir(parents=True)
            (snapshot / "README.md").write_text(
                "---\nconfigs:\n- config_name: scale800_py_gate_v1\n  data_files:\n  - split: accepted\n    path: splits/one.jsonl\n---\n"
            )
            (snapshot / "splits/one.jsonl").write_text(json.dumps(row) + "\n")
            capture(
                load(ops / "refresh.py"),
                source_repo,
                revision,
                root / "accepted",
                snapshot,
            )
            (root / "results").write_text('{"records":[],"claims":[]}')
            subprocess.run(
                [
                    sys.executable,
                    str(Path(__file__).with_name("views.py")),
                    str(ops / "build.py"),
                    results_repo,
                    source_repo,
                    str(root / "accepted"),
                    str(root / "results"),
                    str(root / "output"),
                ],
                check=True,
                capture_output=True,
            )
            summary = json.loads((root / "output/summary.json").read_bytes())
            self.assertEqual(summary["tasks"], 1)
            self.assertEqual(summary["qwen_status_counts"]["not_started"], 1)
        builder = fresh_builder(ops / "build.py", results_repo, source_repo)
        raw = b"{}"
        locator = {
            "repo_id": results_repo,
            "path": "results/file",
            "revision": revision,
            "sha256": builder.sha(raw),
        }
        builder._published(raw, locator, repo=builder.RESULTS_REPO)
        with self.assertRaises(ValueError):
            builder._published(raw, locator)


if __name__ == "__main__":
    unittest.main()
