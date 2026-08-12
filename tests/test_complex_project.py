import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class ComplexProjectTests(unittest.TestCase):
    def test_multifile_cpp_project_runs_bounded_overlay_repair(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "complex-project"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(root / "examples" / "complex_project_demo.py"),
                    "--output-dir",
                    str(output),
                ],
                cwd=str(root),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=180,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout)
            summary = json.loads(
                (output / "complex-project-summary.json").read_text(encoding="utf-8")
            )
            self.assertTrue(summary["success"])
            self.assertEqual(summary["rounds"], 2)
            self.assertEqual(summary["reverser_calls"], 2)
            self.assertEqual(summary["checker_calls"], 2)
            self.assertTrue(summary["feedback_observed_by_reverser"])
            self.assertIn("std::vector<int>", summary["target_signature"])
            self.assertTrue(summary["address_map_used"].endswith("address-map.json"))
            self.assertEqual(
                summary["strict_ghidra_artifacts"],
                ["assembly", "cfg", "context", "decompile", "pcode", "xrefs_from", "xrefs_to"],
            )
            self.assertTrue(summary["knowledge_graph_persisted"])

            self.assertEqual(summary["round_1_checker"], "FAIL")
            self.assertEqual(summary["round_1_objective"], "FAIL")
            self.assertEqual(summary["round_1_build"], "PASS")
            self.assertEqual(summary["round_1_test"], "PASS")
            self.assertEqual(summary["round_1_runtime"], "FAIL")

            self.assertEqual(summary["round_2_checker"], "PASS")
            self.assertEqual(summary["round_2_objective"], "PASS")
            self.assertEqual(summary["round_2_build"], "PASS")
            self.assertEqual(summary["round_2_test"], "PASS")
            self.assertEqual(summary["round_2_runtime"], "PASS")
            self.assertTrue(summary["source_project_unchanged"])
            self.assertTrue(summary["scalar_overload_preserved"])
            self.assertTrue(summary["vector_overload_recovered"])
            self.assertTrue(summary["full_project_overlay"])

            round_2 = json.loads(
                (output / "reports" / "logs" / "round-02.json").read_text(encoding="utf-8")
            )
            prompt = round_2["reverser"]["prompt"]
            self.assertIn("Previous candidate to repair", prompt)
            self.assertIn("vector traversal loop is missing", prompt)
            self.assertIn("binary evidence contains a loop", prompt)
            self.assertIn("clamped vector score mismatch", prompt)
            self.assertEqual(
                [gate["kind"] for gate in round_2["validation"]["gates"]],
                ["build", "test", "runtime"],
            )


if __name__ == "__main__":
    unittest.main()
