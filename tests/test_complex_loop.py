import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class ComplexLoopDemoTests(unittest.TestCase):
    def test_complex_object_runs_fail_feedback_fix_pass_loop(self):
        project_root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "demo"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(project_root / "examples" / "complex_loop_demo.py"),
                    "--output-dir",
                    str(output),
                ],
                cwd=str(project_root),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=60,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout)
            summary = json.loads((output / "loop-test-summary.json").read_text(encoding="utf-8"))
            self.assertTrue(summary["success"])
            self.assertEqual(summary["rounds"], 2)
            self.assertEqual(summary["reverser_calls"], 2)
            self.assertEqual(summary["checker_calls"], 2)
            self.assertTrue(summary["feedback_observed_by_reverser"])
            self.assertEqual(summary["round_1_checker_verdict"], "FAIL")
            self.assertEqual(summary["round_1_objective_verdict"], "FAIL")
            self.assertTrue(summary["round_1_overlay_build"])
            self.assertTrue(summary["round_1_overlay_test"])
            self.assertFalse(summary["round_1_overlay_runtime"])
            self.assertFalse(summary["round_1_validation"])
            self.assertEqual(summary["round_2_checker_verdict"], "PASS")
            self.assertEqual(summary["round_2_objective_verdict"], "PASS")
            self.assertTrue(summary["round_2_overlay_build"])
            self.assertTrue(summary["round_2_overlay_test"])
            self.assertTrue(summary["round_2_overlay_runtime"])
            self.assertTrue(summary["round_2_validation"])
            self.assertEqual(summary["round_2_gate_kinds"], ["build", "test", "runtime"])
            self.assertEqual(
                summary["strict_ghidra_artifacts"],
                [
                    "assembly",
                    "cfg",
                    "context",
                    "decompile",
                    "pcode",
                    "xrefs_from",
                    "xrefs_to",
                ],
            )
            self.assertTrue(summary["knowledge_graph_persisted"])
            self.assertTrue(summary["project_source_unchanged"])
            self.assertTrue(summary["global_symbols_preserved"])
            self.assertTrue((output / "complex.o").is_file())
            self.assertTrue((output / "complex.recovered.o").is_file())

            round_1 = json.loads(
                (output / "reports" / "logs" / "round-01.json").read_text(encoding="utf-8")
            )
            round_2 = json.loads(
                (output / "reports" / "logs" / "round-02.json").read_text(encoding="utf-8")
            )
            self.assertEqual(round_1["checker"]["verdict"], "FAIL")
            self.assertEqual(round_1["objective"]["verdict"], "FAIL")
            self.assertFalse(round_1["validation"]["ok"])
            self.assertIn("cc -O2 -c complex.c -o rebuilt.o", round_1["validation"]["output"])
            self.assertIn("Previous candidate to repair", round_2["reverser"]["prompt"])
            self.assertIn("sample traversal is missing", round_2["reverser"]["prompt"])
            self.assertIn("project overlay build/test/runtime gate failed", round_2["reverser"]["prompt"])
            self.assertEqual(round_2["checker"]["verdict"], "PASS")
            self.assertEqual(round_2["objective"]["verdict"], "PASS")
            self.assertTrue(round_2["validation"]["ok"])
            self.assertEqual(
                [gate["kind"] for gate in round_2["validation"]["gates"]],
                ["build", "test", "runtime"],
            )


if __name__ == "__main__":
    unittest.main()
