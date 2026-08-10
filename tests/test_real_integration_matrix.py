import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class RealIntegrationMatrixTests(unittest.TestCase):
    def test_example_matrix_covers_elf_coff_cpp_and_three_gate_types(self):
        root = Path(__file__).resolve().parents[1]
        payload = json.loads(
            (root / "examples" / "real-matrix.example.json").read_text(encoding="utf-8")
        )
        self.assertNotEqual(payload["defaults"]["model"], payload["defaults"]["checker_model"])
        self.assertEqual({case["format"] for case in payload["cases"]}, {"ELF", "COFF"})
        for case in payload["cases"]:
            self.assertTrue(case["object_file"].endswith((".o", ".obj")))
            self.assertTrue(case["build_commands"])
            self.assertTrue(case["test_commands"])
            self.assertTrue(case["runtime_commands"])

    @unittest.skipUnless(
        os.getenv("MINI_RE_REAL_MATRIX_CONFIG"),
        "set MINI_RE_REAL_MATRIX_CONFIG to run real Ghidra + dual-model cases",
    )
    def test_real_ghidra_dual_model_matrix(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as tmp:
            proc = subprocess.run(
                [
                    sys.executable,
                    str(root / "integration_matrix.py"),
                    "--config",
                    os.environ["MINI_RE_REAL_MATRIX_CONFIG"],
                    "--output-dir",
                    str(Path(tmp) / "matrix"),
                ],
                cwd=str(root),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=int(os.getenv("MINI_RE_REAL_MATRIX_TIMEOUT", "7200")),
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout)


if __name__ == "__main__":
    unittest.main()
