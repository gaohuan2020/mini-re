import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import advanced
import mini_re


def make_object(source: Path, output: Path) -> None:
    subprocess.run(["cc", "-c", str(source), "-o", str(output)], check=True)


def make_fake_ghidra(root: Path) -> Path:
    bridge = root / "fake-ghidra"
    bridge.write_text(
        """#!/usr/bin/env python3
import json
import sys

command = sys.argv[1]
target = sys.argv[2]
if command == "decompile":
    print("int target(int x) { if (x < 0) return 0; return x + 1; }")
elif command == "context":
    print(json.dumps({
        "kind": "function-context",
        "function": {
            "address": target,
            "name": "target",
            "callees": [{"addr": "0x2000", "name": "helper"}],
        },
        "strings": [{"address": "0x3000", "value": "hello"}],
        "globals": [{"address": "0x4000", "name": "counter"}],
    }))
elif command == "xrefs-from":
    print("0x2000 helper")
elif command == "xrefs-to":
    print("0x0800 caller")
elif command == "asm":
    print("cmp w0, #0\\nb.lt 0x10\\nadd w0, w0, #1\\nret")
elif command == "pcode":
    print("CBRANCH x < 0; RETURN 0; INT_ADD x, 1")
elif command == "cfg":
    print(json.dumps({"blocks": ["entry", "negative", "positive"], "edges": [[0, 1], [0, 2]]}))
else:
    sys.exit(2)
""",
        encoding="utf-8",
    )
    bridge.chmod(0o755)
    return bridge


class AdvancedTests(unittest.TestCase):
    def test_cli_rejects_runs_that_skip_mandatory_pipeline(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "target.c"
            object_file = root / "target.o"
            source.write_text("int target(void) { return 1; }\n", encoding="utf-8")
            make_object(source, object_file)
            self.assertEqual(mini_re.main([str(object_file)]), 1)

    def test_strict_ghidra_rejects_missing_evidence_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bridge_path = root / "incomplete-ghidra"
            bridge_path.write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = decompile ]; then echo 'int target(void) { return 1; }'; exit 0; fi\n"
                "exit 2\n",
                encoding="utf-8",
            )
            bridge_path.chmod(0o755)
            bridge = advanced.GhidraBridge(str(bridge_path), root, strict=True)
            with self.assertRaisesRegex(advanced.MiniREError, "Ghidra command failed: asm"):
                bridge.collect("0x1000")

    def test_strict_ghidra_full_evidence_and_graph_persists(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bridge = advanced.GhidraBridge(str(make_fake_ghidra(root)), root, strict=True)
            evidence = bridge.collect("0x1000")
            self.assertIn("decompile", evidence.artifacts)
            self.assertIn("context", evidence.artifacts)
            self.assertIn("pcode", evidence.artifacts)
            self.assertIn("cfg", evidence.artifacts)

            graph_path = root / "knowledge.json"
            graph = advanced.KnowledgeGraph(graph_path)
            graph.ingest_ghidra(evidence)
            payload = json.loads(graph_path.read_text(encoding="utf-8"))
            self.assertIn("function:0x1000", payload["nodes"])
            self.assertIn("function:0x2000", payload["nodes"])
            self.assertTrue(any(edge["relation"] == "calls" for edge in payload["edges"]))
            self.assertIn("helper", graph.neighborhood("0x1000"))

    def test_project_overlay_replaces_only_target_and_builds(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            project.mkdir()
            source = project / "source.c"
            original = "int helper(void) { return 7; }\nint target(int x) { return 0; }\n"
            source.write_text(original, encoding="utf-8")
            location = advanced.find_function(source, "target")
            result = advanced.validate_project_overlay(
                project,
                source,
                location,
                "int target(int x) { return x + 1; }",
                root / "reports",
                ["cc -c source.c -o target.o && test -f target.o"],
                timeout=30,
                keep_overlay=True,
                test_commands=["nm target.o | grep target"],
                runtime_commands=["test -f target.o"],
                require_tests=True,
                require_runtime=True,
            )
            self.assertTrue(result.ok, result.output)
            self.assertEqual([gate.kind for gate in result.gates], ["build", "test", "runtime"])
            self.assertTrue(all(gate.status == "PASS" for gate in result.gates))
            self.assertEqual(source.read_text(encoding="utf-8"), original)
            self.assertIsNotNone(result.overlay_root)
            overlay_source = result.overlay_root / "source.c"
            self.assertIn("return x + 1", overlay_source.read_text(encoding="utf-8"))
            self.assertIn("return 7", overlay_source.read_text(encoding="utf-8"))
            shutil.rmtree(result.overlay_root)

    def test_ambiguous_function_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "overloads.cpp"
            source.write_text(
                "int target(int x) { return x; }\n"
                "double target(double x) { return x; }\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(advanced.MiniREError, "ambiguous"):
                advanced.find_function(source, "target")

    def test_complete_signature_disambiguates_overload(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "overloads.cpp"
            source.write_text(
                "int target(int x) { return x; }\n"
                "double target(double x) { return x; }\n",
                encoding="utf-8",
            )
            location = advanced.find_function(source, "target", "double target(double x)")
            self.assertEqual(advanced.canonical_signature(location.signature), "double target(double x)")
            self.assertIn("return x", location.context)

    def test_address_map_resolves_signature_and_rejects_conflicts(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            source = project / "overloads.cpp"
            source.write_text(
                "int target(int x) { return x; }\n"
                "double target(double x) { return x; }\n",
                encoding="utf-8",
            )
            address_map = project / "addresses.json"
            address_map.write_text(
                json.dumps(
                    {
                        "functions": {
                            "0x1000": {
                                "source_file": "overloads.cpp",
                                "function": "target",
                                "signature": "double target(double x)",
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            spec = advanced.resolve_target_source(
                project, "1000", None, None, None, address_map
            )
            self.assertEqual(spec.source_file, source)
            location = advanced.find_function(spec.source_file, spec.function_name, spec.signature)
            self.assertTrue(location.signature.startswith("double"))
            with self.assertRaisesRegex(advanced.MiniREError, "conflicts"):
                advanced.resolve_target_source(
                    project, "0x1000", None, "other", None, address_map
                )

    def test_dual_model_pipeline_uses_ghidra_graph_and_overlay(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            project.mkdir()
            source = project / "source.c"
            source.write_text("int target(int x) { return 0; }\n", encoding="utf-8")
            original_object = root / "target.o"
            make_object(source, original_object)
            bridge = advanced.GhidraBridge(str(make_fake_ghidra(root)), project)
            reverser_prompts = []
            checker_prompts = []

            candidates = iter(
                [
                    "```c\nint target(int x) { return 0; }\n```",
                    "```c\nint target(int x) { if (x < 0) return 0; return x + 1; }\n```",
                ]
            )
            verdicts = iter(
                [
                    json.dumps(
                        {
                            "verdict": "FAIL",
                            "summary": "missing branch and addition",
                            "issues": ["negative branch is absent"],
                            "fix_instructions": ["add the branch and x + 1"],
                        }
                    ),
                    json.dumps(
                        {
                            "verdict": "PASS",
                            "summary": "matches evidence",
                            "issues": [],
                            "fix_instructions": [],
                        }
                    ),
                ]
            )

            def reverser(prompt):
                reverser_prompts.append(prompt)
                return next(candidates)

            def checker(prompt):
                checker_prompts.append(prompt)
                return next(verdicts)

            reports = root / "reports"
            rounds = advanced.run_review_pipeline(
                original_object,
                root / "candidate.c",
                root / "unused.o",
                reverser,
                checker,
                reports,
                review_rounds=2,
                ghidra_bridge=bridge,
                address="0x1000",
                project_root=project,
                source_file=Path("source.c"),
                function_name="target",
                build_commands=["cc -c source.c -o rebuilt.o"],
                keep_overlay=True,
            )
            self.assertEqual(rounds, 2)
            self.assertEqual(len(reverser_prompts), 2)
            self.assertEqual(len(checker_prompts), 2)
            self.assertIn("Ghidra decompile", reverser_prompts[0])
            self.assertIn("negative branch is absent", reverser_prompts[1])
            self.assertIn("Previous candidate to repair", reverser_prompts[1])
            self.assertIn("return 0", reverser_prompts[1])
            self.assertIn("function:0x2000", reverser_prompts[0])
            self.assertEqual(source.read_text(encoding="utf-8"), "int target(int x) { return 0; }\n")
            result = json.loads((reports / "result.json").read_text(encoding="utf-8"))
            self.assertTrue(result["success"])
            overlay = Path(result["overlay_root"])
            self.assertTrue((overlay / "rebuilt.o").is_file())
            self.assertIn("return x + 1", (overlay / "source.c").read_text(encoding="utf-8"))
            self.assertTrue((reports / "knowledge-graph.json").is_file())
            self.assertTrue((reports / "logs" / "round-01.json").is_file())
            self.assertTrue((reports / "logs" / "round-02.json").is_file())
            round_1 = json.loads(
                (reports / "logs" / "round-01.json").read_text(encoding="utf-8")
            )
            self.assertEqual(round_1["checker"]["verdict"], "FAIL")
            self.assertEqual(round_1["objective"]["verdict"], "FAIL")
            self.assertEqual(len(round_1["parity"]["signals"]), 11)
            self.assertTrue(round_1["validation"]["ok"])
            self.assertIn("cc -c source.c -o rebuilt.o", round_1["validation"]["output"])

    def test_checker_rejects_non_json(self):
        verdict = advanced.parse_checker_verdict("looks good")
        self.assertEqual(verdict.verdict, "UNKNOWN")

    def test_cli_dispatches_dual_review_and_overlay(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            project.mkdir()
            source = project / "target.c"
            source.write_text("int target(int x) { return 0; }\n", encoding="utf-8")
            object_file = root / "target.o"
            make_object(source, object_file)
            reports = project / "reports" / "mini-re"

            def reverser(_prompt):
                return "```c\nint target(int x) { if (x < 0) return 0; return x + 1; }\n```"

            def checker(_prompt):
                return json.dumps(
                    {
                        "verdict": "PASS",
                        "summary": "matches",
                        "issues": [],
                        "fix_instructions": [],
                    }
                )

            with mock.patch("mini_re._provider_from_args", side_effect=[reverser, checker]):
                status = mini_re.main(
                    [
                        str(object_file),
                        "-o",
                        str(root / "candidate.c"),
                        "--model",
                        "reverser-model",
                        "--checker-model",
                        "checker-model",
                        "--ghidra-cli",
                        str(make_fake_ghidra(root)),
                        "--address",
                        "0x1000",
                        "--project-root",
                        str(project),
                        "--source-file",
                        "target.c",
                        "--function",
                        "target",
                        "--build-command",
                        "cc -c target.c -o rebuilt.o",
                        "--reports-dir",
                        str(reports),
                    ]
                )
            self.assertEqual(status, 0)
            self.assertTrue((reports / "result.json").is_file())
            self.assertEqual(source.read_text(encoding="utf-8"), "int target(int x) { return 0; }\n")

    def test_cli_address_map_selects_exact_cpp_overload(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            project.mkdir()
            source = project / "target.cpp"
            original = (
                "int target(int x) { return x; }\n"
                "double target(double x) { return 0; }\n"
            )
            source.write_text(original, encoding="utf-8")
            object_file = root / "target.o"
            subprocess.run(["c++", "-c", str(source), "-o", str(object_file)], check=True)
            address_map = project / "address-map.json"
            address_map.write_text(
                json.dumps(
                    {
                        "functions": {
                            "0x1000": {
                                "source_file": "target.cpp",
                                "function": "target",
                                "signature": "double target(double x)",
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            reports = project / "reports" / "mini-re"

            def reverser(_prompt):
                return "```cpp\ndouble target(double x) { if (x < 0) return 0; return x + 1; }\n```"

            def checker(_prompt):
                return json.dumps(
                    {
                        "verdict": "PASS",
                        "summary": "matches",
                        "issues": [],
                        "fix_instructions": [],
                    }
                )

            with mock.patch("mini_re._provider_from_args", side_effect=[reverser, checker]):
                status = mini_re.main(
                    [
                        str(object_file),
                        "-o",
                        str(root / "candidate.cpp"),
                        "--model",
                        "reverser-model",
                        "--checker-model",
                        "checker-model",
                        "--ghidra-cli",
                        str(make_fake_ghidra(root)),
                        "--address",
                        "0x1000",
                        "--project-root",
                        str(project),
                        "--address-map",
                        str(address_map),
                        "--build-command",
                        "c++ -c target.cpp -o rebuilt.o",
                        "--reports-dir",
                        str(reports),
                        "--keep-overlay",
                    ]
                )
            self.assertEqual(status, 0)
            result = json.loads((reports / "result.json").read_text(encoding="utf-8"))
            self.assertEqual(result["target_signature"], "double target(double x)")
            overlay_source = Path(result["overlay_root"]) / "target.cpp"
            overlaid = overlay_source.read_text(encoding="utf-8")
            self.assertIn("int target(int x) { return x; }", overlaid)
            self.assertIn("double target(double x) { if (x < 0)", overlaid)
            self.assertEqual(source.read_text(encoding="utf-8"), original)


if __name__ == "__main__":
    unittest.main()
