#!/usr/bin/env python3
"""Offline full-pipeline demo on a complex object file."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from advanced import GhidraBridge, find_function, run_review_pipeline  # noqa: E402
from mini_re import object_global_symbols  # noqa: E402


BAD_CANDIDATE = r"""int analyze_samples(
    const int16_t *samples,
    size_t count,
    AnalysisStats *stats
) {
    if (samples == NULL || stats == NULL || count == 0) {
        return -1;
    }
    stats->weighted_sum = 0;
    stats->minimum = samples[0];
    stats->maximum = samples[0];
    stats->transitions = 0;
    for (size_t bucket = 0; bucket < 8; ++bucket) {
        stats->histogram[bucket] = 0;
    }
    return 0;
}
"""


class ScriptedReverser:
    """Returns a flawed first function, then requires feedback before fixing it."""

    def __init__(self, correct_function: str) -> None:
        self.correct_function = correct_function
        self.calls = 0
        self.feedback_observed = False

    def __call__(self, prompt: str) -> str:
        self.calls += 1
        if self.calls == 1:
            return "```c\n" + BAD_CANDIDATE + "\n```"
        required_markers = (
            "Previous candidate to repair",
            "sample traversal is missing",
            "weighted switch is missing",
            "project overlay build/test/runtime gate failed",
            "[build] $ cc -O2 -c complex.c -o rebuilt.o",
        )
        self.feedback_observed = all(marker in prompt for marker in required_markers)
        if not self.feedback_observed:
            raise RuntimeError(
                "round 2 did not receive the previous candidate, checker feedback, and build result"
            )
        return "```c\n" + self.correct_function + "\n```"


class ScriptedChecker:
    """Produces the strict JSON contract required from a checker LLM."""

    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, prompt: str) -> str:
        self.calls += 1
        if self.calls == 1:
            return json.dumps(
                {
                    "verdict": "FAIL",
                    "summary": "major control-flow and arithmetic logic is absent",
                    "issues": [
                        "sample traversal is missing",
                        "weighted switch is missing",
                    ],
                    "fix_instructions": [
                        "restore min/max, transitions, histogram updates, and all switch cases"
                    ],
                }
            )
        expected_tokens = (
            "for (size_t index = 0; index < count; ++index)",
            "switch (index & 3u)",
            "stats->weighted_sum ^=",
            "Ghidra pcode",
            "Ghidra cfg",
        )
        if not all(token in prompt for token in expected_tokens):
            return json.dumps(
                {
                    "verdict": "FAIL",
                    "summary": "repair or evidence remains incomplete",
                    "issues": ["one or more required operations/evidence items are absent"],
                    "fix_instructions": ["restore the missing operations"],
                }
            )
        return json.dumps(
            {
                "verdict": "PASS",
                "summary": "candidate contains the required control flow and arithmetic",
                "issues": [],
                "fix_instructions": [],
            }
        )


def _write_strict_fake_ghidra(path: Path) -> None:
    path.write_text(
        """#!/usr/bin/env python3
import json
import sys

command = sys.argv[1]
target = sys.argv[2]
if command == "decompile":
    print("int analyze_samples(int16_t *samples, size_t count, AnalysisStats *stats) { /* loop, branches, switch */ }")
elif command == "context":
    print(json.dumps({
        "kind": "function-context",
        "function": {"address": target, "name": "analyze_samples", "callees": []},
        "strings": [],
        "globals": [],
    }))
elif command == "asm":
    print("cmp x1, #0\\nb.eq fail\\nloop: ldrsh w8, [x0], #2\\nsubs x1, x1, #1\\nb.ne loop\\nret")
elif command == "pcode":
    print("CBRANCH count == 0; LOAD sample; INT_SLESS; INT_ADD; CBRANCH loop")
elif command == "cfg":
    print(json.dumps({"blocks": ["entry", "loop", "switch", "exit"], "edges": [[0,1],[1,2],[2,1],[1,3]]}))
elif command == "xrefs-from":
    print("No outgoing xrefs")
elif command == "xrefs-to":
    print("0x0800 caller")
else:
    sys.exit(2)
""",
        encoding="utf-8",
    )
    path.chmod(0o755)


def run_demo(output_dir: Path) -> dict[str, object]:
    output_dir.mkdir(parents=True, exist_ok=True)
    source = Path(__file__).with_name("complex.c")
    correct_text = source.read_text(encoding="utf-8")
    correct_location = find_function(source, "analyze_samples")
    signature_start = correct_text.rfind("\nint analyze_samples", 0, correct_location.body_start) + 1
    correct_function = correct_text[signature_start : correct_location.body_end]

    object_file = output_dir / "complex.o"
    candidate_file = output_dir / "complex.recovered.c"
    candidate_object = output_dir / "complex.recovered.o"
    reports = output_dir / "reports"
    project = output_dir / "project"
    project.mkdir(parents=True, exist_ok=True)
    project_source = project / "complex.c"
    stubbed_project = (
        correct_text[: correct_location.body_start]
        + "{\n    (void)samples;\n    (void)count;\n    (void)stats;\n    return 0;\n}"
        + correct_text[correct_location.body_end :]
    )
    project_source.write_text(stubbed_project, encoding="utf-8")
    (project / "harness.c").write_text(
        """#include <stddef.h>
#include <stdint.h>
typedef struct AnalysisStats {
    int64_t weighted_sum;
    int32_t minimum;
    int32_t maximum;
    uint32_t transitions;
    uint32_t histogram[8];
} AnalysisStats;
int analyze_samples(const int16_t *, size_t, AnalysisStats *);
int main(void) {
    const int16_t values[] = {1, -2, 7, -5};
    AnalysisStats stats;
    int range = analyze_samples(values, 4, &stats);
    return (range == 12 && stats.minimum == -5 && stats.maximum == 7 &&
            stats.transitions == 3 && stats.histogram[0] == 4) ? 0 : 1;
}
""",
        encoding="utf-8",
    )

    subprocess.run(
        ["cc", "-O2", "-c", str(source), "-o", str(object_file)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    fake_ghidra = output_dir / "fake-ghidra"
    _write_strict_fake_ghidra(fake_ghidra)

    reverser = ScriptedReverser(correct_function)
    checker = ScriptedChecker()
    bridge = GhidraBridge(str(fake_ghidra), project, strict=True)
    rounds = run_review_pipeline(
        object_file,
        candidate_file,
        output_dir / "unused.o",
        reverser,
        checker,
        reports,
        review_rounds=3,
        language="c",
        timeout=60,
        ghidra_bridge=bridge,
        address="0x1000",
        project_root=project,
        source_file=Path("complex.c"),
        function_name="analyze_samples",
        build_commands=["cc -O2 -c complex.c -o rebuilt.o"],
        test_commands=["nm rebuilt.o | grep analyze_samples"],
        runtime_commands=["cc -O2 complex.c harness.c -o verify && ./verify"],
        require_tests=True,
        require_runtime=True,
        keep_overlay=True,
    )

    result = json.loads((reports / "result.json").read_text(encoding="utf-8"))
    final_overlay = Path(result["overlay_root"])
    shutil.copy2(final_overlay / "rebuilt.o", candidate_object)
    round_1 = json.loads((reports / "logs" / "round-01.json").read_text(encoding="utf-8"))
    round_2 = json.loads((reports / "logs" / "round-02.json").read_text(encoding="utf-8"))
    input_symbols = sorted(object_global_symbols(object_file))
    candidate_symbols = sorted(object_global_symbols(candidate_object))
    round_1_gates = {gate["kind"]: gate["status"] for gate in round_1["validation"]["gates"]}
    round_2_gates = {gate["kind"]: gate["status"] for gate in round_2["validation"]["gates"]}
    summary = {
        "success": True,
        "rounds": rounds,
        "reverser_calls": reverser.calls,
        "checker_calls": checker.calls,
        "feedback_observed_by_reverser": reverser.feedback_observed,
        "strict_ghidra_artifacts": sorted(bridge.collect("0x1000").artifacts),
        "knowledge_graph_persisted": (reports / "knowledge-graph.json").is_file(),
        "round_1_checker_verdict": round_1["checker"]["verdict"],
        "round_1_objective_verdict": round_1["objective"]["verdict"],
        "round_1_parity": round_1["parity"]["status"],
        "round_1_overlay_build": round_1_gates.get("build") == "PASS",
        "round_1_overlay_test": round_1_gates.get("test") == "PASS",
        "round_1_overlay_runtime": round_1_gates.get("runtime") == "PASS",
        "round_1_validation": round_1["validation"]["ok"],
        "round_2_checker_verdict": round_2["checker"]["verdict"],
        "round_2_objective_verdict": round_2["objective"]["verdict"],
        "round_2_parity": round_2["parity"]["status"],
        "round_2_overlay_build": round_2_gates.get("build") == "PASS",
        "round_2_overlay_test": round_2_gates.get("test") == "PASS",
        "round_2_overlay_runtime": round_2_gates.get("runtime") == "PASS",
        "round_2_validation": round_2["validation"]["ok"],
        "round_2_gate_kinds": [gate["kind"] for gate in round_2["validation"]["gates"]],
        "project_source_unchanged": project_source.read_text(encoding="utf-8") == stubbed_project,
        "input_global_symbols": input_symbols,
        "candidate_global_symbols": candidate_symbols,
        "global_symbols_preserved": set(input_symbols).issubset(candidate_symbols),
        "input_object": str(object_file),
        "candidate_source": str(candidate_file),
        "candidate_object": str(candidate_object),
        "final_overlay": str(final_overlay),
        "round_1_log": str(reports / "logs" / "round-01.json"),
        "round_2_log": str(reports / "logs" / "round-02.json"),
    }
    (output_dir / "loop-test-summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, default=PROJECT_ROOT / "work" / "complex-loop-demo")
    args = parser.parse_args()
    print(json.dumps(run_demo(args.output_dir), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
