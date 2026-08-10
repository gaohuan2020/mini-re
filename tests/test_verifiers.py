import unittest

from verifiers import run_parity_engine, verify_objective


class VerifierTests(unittest.TestCase):
    def test_objective_verifier_detects_missing_loop_switch_and_flow(self):
        artifacts = {
            "decompile": "int target(int n) { for (int i=0;i<n;i++) { if (i) use(i); } return n; }",
            "assembly": "cmp w0, #0\nb.eq done\nbl use\nb.ne loop\nret",
            "pcode": "CBRANCH; CALL use; CBRANCH; BRANCHIND; RETURN",
            "cfg": '{"blocks":["entry","loop","switch","exit"],"edges":[[0,1],[1,2],[2,1],[1,3]]}',
        }
        bad = verify_objective("int target(int n) { return n; }", artifacts)
        self.assertEqual(bad.verdict, "FAIL")
        self.assertTrue(any("loop" in finding for finding in bad.findings))
        self.assertTrue(any("switch" in finding for finding in bad.findings))

        good = verify_objective(
            "int target(int n) { for (int i=0;i<n;i++) { if (i) use(i); "
            "switch (i & 1) { case 0: break; default: break; } } return n; }",
            artifacts,
        )
        self.assertEqual(good.verdict, "PASS", good.findings)

    def test_parity_engine_always_reports_exactly_eleven_signals(self):
        report = run_parity_engine(
            "int target(void) { return 0; }",
            {"decompile": "int target(void) { if (flag) return helper(); return 1; }"},
        )
        self.assertEqual(len(report.signals), 11)
        self.assertEqual(
            [item.signal for item in report.signals],
            [
                "missing_source",
                "stub_markers",
                "trivial_stub",
                "large_asm_tiny_source",
                "plugin_call_heavy",
                "short_body",
                "low_call_count",
                "fp_sensitivity",
                "call_count_mismatch",
                "nan_logic",
                "inline_wrapper",
            ],
        )
        self.assertEqual(report.status, "RED")
        self.assertTrue(next(item for item in report.signals if item.signal == "trivial_stub").triggered)

    def test_parity_fp_and_nan_signals_are_deterministic(self):
        report = run_parity_engine(
            "double target(long bits) { return (double)bits; }",
            {
                "decompile": "double target(long bits) { if (isnan(value)) return value; return value; }",
                "assembly": "ucomisd %xmm0, %xmm1\nfadd %d0, %d1, %d0\nret",
            },
        )
        by_name = {item.signal: item for item in report.signals}
        self.assertTrue(by_name["nan_logic"].triggered)
        self.assertFalse(by_name["fp_sensitivity"].triggered)
        self.assertEqual(report.status, "YELLOW")


if __name__ == "__main__":
    unittest.main()
