import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import mini_re


class DecompileDemoTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(__file__).resolve().parents[1]
        self.demo = self.root / "examples" / "decompile_demo"

    def test_checked_in_elf_object_has_expected_symbol_and_evidence(self):
        object_file = self.demo / "score_bytes.o"
        self.assertTrue(object_file.is_file())
        evidence = mini_re.collect_evidence(object_file)
        self.assertIn("ELF", evidence.metadata)
        self.assertIn("score_bytes", evidence.symbols)
        self.assertIn("score_bytes", evidence.disassembly)
        self.assertTrue(
            any("score_bytes" in symbol for symbol in mini_re.object_global_symbols(object_file))
        )

    @unittest.skipUnless(shutil.which("cc"), "cc is required for semantic demo verification")
    def test_decompiled_reconstruction_compiles_and_matches_source(self):
        source = self.demo / "score_bytes_source.c"
        recovered = (self.demo / "score_bytes.decompiled.c").read_text(encoding="utf-8")
        recovered = recovered.replace(
            "int score_bytes(", "int score_bytes_recovered(", 1
        )
        harness = r"""
int score_bytes(const unsigned char *, unsigned long, int);
int score_bytes_recovered(unsigned char *, unsigned long, int);

int main(void) {
    unsigned char cases[][8] = {
        {0, 0, 0, 0, 0, 0, 0, 0},
        {1, 2, 3, 4, 5, 6, 7, 8},
        {255, 0, 127, 128, 3, 3, 9, 42}
    };
    int seeds[] = {0, 1, -7, 0x12345678};
    for (unsigned long c = 0; c < 3; ++c) {
        for (unsigned long n = 1; n <= 8; ++n) {
            for (unsigned long s = 0; s < 4; ++s) {
                int expected = score_bytes(cases[c], n, seeds[s]);
                int actual = score_bytes_recovered(cases[c], n, seeds[s]);
                if (expected != actual) {
                    return 1;
                }
            }
        }
    }
    return 0;
}
"""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            recovered_path = tmp_path / "recovered.c"
            harness_path = tmp_path / "harness.c"
            executable = tmp_path / "compare"
            recovered_path.write_text(recovered, encoding="utf-8")
            harness_path.write_text(harness, encoding="utf-8")
            proc = subprocess.run(
                ["cc", "-std=c11", "-O2", str(source), str(recovered_path), str(harness_path), "-o", str(executable)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout)
            run = subprocess.run(
                [str(executable)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
            )
            self.assertEqual(run.returncode, 0, run.stdout)


if __name__ == "__main__":
    unittest.main()
