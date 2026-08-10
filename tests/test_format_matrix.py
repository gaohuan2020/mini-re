import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import mini_re


class ObjectFormatMatrixTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("clang++"), "clang++ is required for cross-format objects")
    def test_real_cpp_objects_cover_native_elf_and_coff(self):
        root = Path(__file__).resolve().parents[1]
        source = root / "examples" / "matrix_target.cpp"
        cases = [
            ("native.o", [], None),
            ("elf.o", ["--target=x86_64-unknown-linux-gnu"], "ELF"),
            ("coff.obj", ["--target=x86_64-pc-windows-msvc"], "COFF"),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            output_root = Path(tmp)
            observed = set()
            for name, target_flags, expected_format in cases:
                output = output_root / name
                proc = subprocess.run(
                    ["clang++", "-std=c++17", *target_flags, "-c", str(source), "-o", str(output)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    check=False,
                )
                self.assertEqual(proc.returncode, 0, proc.stdout)
                evidence = mini_re.collect_evidence(output)
                self.assertEqual(evidence.language, "c++")
                self.assertIn("matrix_entry", evidence.symbols)
                self.assertIn("matrix_entry", evidence.disassembly)
                symbols = mini_re.object_global_symbols(output)
                self.assertTrue(any("matrix_entry" in symbol for symbol in symbols))
                if expected_format:
                    self.assertIn(expected_format, evidence.metadata)
                    observed.add(expected_format)
                elif "Mach-O" in evidence.metadata:
                    observed.add("Mach-O")
                elif "ELF" in evidence.metadata:
                    observed.add("ELF-native")
            self.assertIn("ELF", observed)
            self.assertIn("COFF", observed)


if __name__ == "__main__":
    unittest.main()
