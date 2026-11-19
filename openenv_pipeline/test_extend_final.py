"""Exercise append-only joins and failures for reused Scale800 identities."""

import copy
import unittest

from extend_final import register


class Scale800Append(unittest.TestCase):
    def test_preserves_overlap_and_appends_new_task(self):
        source = {
            "task_id": "known",
            "source_dataset": "SWE-bench/SWE-smith-go",
            "gate_passed": True,
            "training_admissible": False,
            "task_path": "corpus/tasks/known",
            "task_inventory_sha256": "d" * 64,
            "task_source_sha256": "e" * 64,
            "qwen_solve_rate": 0.25,
            "in_stratified_sample": True,
        }
        schema = [
            *source,
            "task_origin",
            "network_enabled",
            "original_network_mode",
            "users_dropped",
            "task_modified_for_hf_sandbox",
        ]
        rows, lines = {}, {}
        self.assertEqual(register([source], rows, schema, lines), 0)
        before = copy.deepcopy((rows, lines))
        repeated = {**source, "qwen_solve_rate": None, "in_stratified_sample": None}
        addition = {**source, "task_id": "new", "task_path": "corpus/tasks/new"}
        self.assertEqual(register([repeated, addition], rows, schema, lines), 1)
        self.assertEqual(
            (rows["known"], lines["known"]), (before[0]["known"], before[1]["known"])
        )
        self.assertEqual(rows["new"]["task_origin"], "swe-smith-go")
        for key in ("task_path", "task_inventory_sha256", "task_source_sha256"):
            with self.assertRaisesRegex(ValueError, "Conflicting source identity"):
                register([{**source, key: "a" * 64}], rows, schema, lines)


if __name__ == "__main__":
    unittest.main()
