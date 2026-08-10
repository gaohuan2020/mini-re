import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import mini_re


class FakeHTTPResponse:
    def __init__(self, payload):
        self.payload = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return self.payload


class MiniRETests(unittest.TestCase):
    def test_openai_responses_wire_format_and_typed_output(self):
        captured = {}

        def fake_urlopen(request, timeout):
            captured["url"] = request.full_url
            captured["timeout"] = timeout
            captured["authorization"] = request.get_header("Authorization")
            captured["body"] = json.loads(request.data.decode("utf-8"))
            return FakeHTTPResponse(
                {
                    "id": "resp_test",
                    "object": "response",
                    "output": [
                        {"type": "reasoning", "content": []},
                        {
                            "type": "message",
                            "role": "assistant",
                            "content": [
                                {"type": "output_text", "text": "```c\nint f(void) { return 1; }\n```"}
                            ],
                        },
                    ],
                }
            )

        provider = mini_re.openai_compat_provider(
            "test-model", 17, "https://example.test/v1", "secret", api_mode="responses"
        )
        with mock.patch("mini_re.urllib.request.urlopen", side_effect=fake_urlopen):
            result = provider("reverse this")
        self.assertIn("int f", result)
        self.assertEqual(captured["url"], "https://example.test/v1/responses")
        self.assertEqual(captured["timeout"], 17)
        self.assertEqual(captured["authorization"], "Bearer secret")
        self.assertEqual(
            captured["body"],
            {"model": "test-model", "input": "reverse this", "store": False},
        )

    def test_openai_chat_completions_remains_explicit_compatibility_mode(self):
        captured = {}

        def fake_urlopen(request, timeout=None):
            captured["url"] = request.full_url
            captured["timeout"] = timeout
            captured["body"] = json.loads(request.data.decode("utf-8"))
            return FakeHTTPResponse(
                {"choices": [{"message": {"role": "assistant", "content": "legacy text"}}]}
            )

        provider = mini_re.openai_compat_provider(
            "legacy-model",
            10,
            "http://localhost:1234/v1",
            None,
            api_mode="chat-completions",
        )
        with mock.patch("mini_re.urllib.request.urlopen", side_effect=fake_urlopen):
            self.assertEqual(provider("hello"), "legacy text")
        self.assertEqual(captured["url"], "http://localhost:1234/v1/chat/completions")
        self.assertEqual(captured["body"]["messages"], [{"role": "user", "content": "hello"}])
        self.assertFalse(captured["body"]["store"])

    def test_responses_helper_output_and_refusal(self):
        self.assertEqual(
            mini_re.extract_openai_text({"output_text": "helper text"}), "helper text"
        )
        refusal = {
            "output": [
                {
                    "type": "message",
                    "content": [{"type": "refusal", "refusal": "not allowed"}],
                }
            ]
        }
        with self.assertRaisesRegex(mini_re.MiniREError, "refused"):
            mini_re.extract_openai_text(refusal)

    def test_extract_code_prefers_longest_fenced_block(self):
        response = "note\n```c\nint f(void) { return 7; }\n```"
        self.assertEqual(mini_re.extract_code(response), "int f(void) { return 7; }\n")

    def test_defined_global_symbols_excludes_locals_and_undefined(self):
        output = "0000 T public_fn\n0004 t local_fn\n     U external_fn\n"
        self.assertEqual(mini_re.defined_global_symbols(output), {"public_fn"})

    def test_rejects_non_object_extension(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "x.c"
            source.write_text("int x;", encoding="utf-8")
            with self.assertRaisesRegex(mini_re.MiniREError, "single .o"):
                mini_re.collect_evidence(source)

    def test_compile_language_does_not_depend_on_output_suffix(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "candidate.c"
            output = root / "candidate.o"
            source.write_text("extern \"C\" int answer() { return 42; }\n", encoding="utf-8")
            result = mini_re.compile_source(source, output, "c++")
            self.assertTrue(result.ok, result.output)
            self.assertTrue(output.is_file())

    def test_real_object_evidence_and_compile_repair_loop(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original_source = root / "original.c"
            original_object = root / "original.o"
            recovered_source = root / "recovered.c"
            recovered_object = root / "recovered.o"
            original_source.write_text("int add_one(int x) { return x + 1; }\n", encoding="utf-8")
            subprocess.run(
                ["cc", "-c", str(original_source), "-o", str(original_object)],
                check=True,
                capture_output=True,
                text=True,
            )

            evidence = mini_re.collect_evidence(original_object)
            self.assertIn("add_one", evidence.symbols)
            self.assertTrue(evidence.disassembly)

            responses = iter(
                [
                    "```c\nint add_one(int x) { return x + ; }\n```",
                    "```c\nint add_one(int x) { return x + 1; }\n```",
                ]
            )
            prompts = []

            def fake_provider(prompt):
                prompts.append(prompt)
                return next(responses)

            attempts = mini_re.reverse_object(
                original_object,
                recovered_source,
                recovered_object,
                fake_provider,
                attempts=2,
                timeout=30,
            )
            self.assertEqual(attempts, 2)
            self.assertTrue(recovered_object.is_file())
            self.assertIn("Compiler diagnostic", prompts[1])

    def test_compileable_candidate_missing_symbol_is_repaired(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "original.c"
            original_object = root / "original.o"
            recovered_source = root / "recovered.c"
            recovered_object = root / "recovered.o"
            source.write_text("int wanted(void) { return 9; }\n", encoding="utf-8")
            subprocess.run(["cc", "-c", str(source), "-o", str(original_object)], check=True)

            responses = iter(
                [
                    "```c\nint unrelated(void) { return 0; }\n```",
                    "```c\nint wanted(void) { return 9; }\n```",
                ]
            )
            prompts = []

            def fake_provider(prompt):
                prompts.append(prompt)
                return next(responses)

            attempts = mini_re.reverse_object(
                original_object,
                recovered_source,
                recovered_object,
                fake_provider,
                attempts=2,
            )
            self.assertEqual(attempts, 2)
            self.assertIn("missing required global symbols", prompts[1])

    def test_dump_evidence_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "x.c"
            object_file = root / "x.o"
            source.write_text("int x(void) { return 1; }\n", encoding="utf-8")
            subprocess.run(["cc", "-c", str(source), "-o", str(object_file)], check=True)
            self.assertEqual(mini_re.main([str(object_file), "--dump-evidence"]), 0)


if __name__ == "__main__":
    unittest.main()
