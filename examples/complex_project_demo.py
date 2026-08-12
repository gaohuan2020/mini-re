#!/usr/bin/env python3
"""Run mini-re against a multi-file C++ project with real build/test/runtime gates."""

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


TARGET_SIGNATURE = (
    "int Analyzer::score(const std::vector<int> &samples, "
    "const Options &options) const"
)

BAD_CANDIDATE = r"""int Analyzer::score(
    const std::vector<int> &samples,
    const Options &options
) const {
    if (samples.empty()) {
        return options.bias;
    }
    return normalize(samples.front()) + options.bias;
}
"""


class ScriptedReverser:
    def __init__(self, correct_candidate: str) -> None:
        self.correct_candidate = correct_candidate
        self.calls = 0
        self.feedback_observed = False

    def __call__(self, prompt: str) -> str:
        self.calls += 1
        if self.calls == 1:
            return "```cpp\n" + BAD_CANDIDATE + "\n```"
        required = (
            "Previous candidate to repair",
            "vector traversal loop is missing",
            "four-way switch is missing",
            "binary evidence contains a loop",
            "project overlay build/test/runtime gate failed",
            "clamped vector score mismatch",
        )
        self.feedback_observed = all(value in prompt for value in required)
        if not self.feedback_observed:
            raise RuntimeError("round 2 did not receive all checker/objective/runtime feedback")
        return "```cpp\n" + self.correct_candidate + "\n```"


class ScriptedChecker:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, prompt: str) -> str:
        self.calls += 1
        if self.calls == 1:
            return json.dumps(
                {
                    "verdict": "FAIL",
                    "summary": "candidate omits the core vector scoring algorithm",
                    "issues": [
                        "vector traversal loop is missing",
                        "four-way switch is missing",
                    ],
                    "fix_instructions": [
                        "restore normalization, clamping, transitions, and all switch paths"
                    ],
                }
            )
        required = (
            "for (std::size_t index = 0; index < samples.size(); ++index)",
            "switch ((index + options.window) & 3u)",
            "transitions * 11",
            "Ghidra pcode",
            "Ghidra cfg",
        )
        passed = all(value in prompt for value in required)
        return json.dumps(
            {
                "verdict": "PASS" if passed else "FAIL",
                "summary": "candidate restores supported structure" if passed else "candidate remains incomplete",
                "issues": [] if passed else ["required vector scoring operations are absent"],
                "fix_instructions": [] if passed else ["restore all evidenced operations"],
            }
        )


def _extract_vector_definition(reference: Path) -> str:
    text = reference.read_text(encoding="utf-8")
    location = find_function(reference, "Analyzer::score", TARGET_SIGNATURE)
    signature_start = text.rfind("\nint Analyzer::score", 0, location.body_start) + 1
    return text[signature_start : location.body_end]


def _write_fake_ghidra(path: Path) -> None:
    path.write_text(
        """#!/usr/bin/env python3
import json
import sys

command = sys.argv[1]
target = sys.argv[2]
if command == "decompile":
    print("int Analyzer::score(vector<int> &samples, Options &options) const { if (samples.empty()) return options.bias; for (...) { normalize(...); if (...) ...; switch (...) { case 0: ...; case 1: ...; case 2: ...; default: ...; } } return ...; }")
elif command == "context":
    print(json.dumps({
        "kind": "function-context",
        "function": {
            "address": target,
            "name": "scoring::Analyzer::score(vector,Options)",
            "callees": [{"addr": "0x2000", "name": "scoring::normalize"}],
        },
        "strings": [],
        "globals": [],
    }))
elif command == "asm":
    print("test size,size\\nje empty\\nloop: call normalize\\ntest value,value\\njs clamp\\ncmp selector,3\\nja switch_default\\nadd total,value\\ninc index\\ncmp index,size\\njb loop\\nret")
elif command == "pcode":
    print("CBRANCH size == 0; CALL normalize; CBRANCH value < 0; BRANCHIND switch; INT_ADD; CBRANCH loop; RETURN")
elif command == "cfg":
    print(json.dumps({"blocks": ["entry", "empty", "loop", "clamp", "switch", "case0", "case1", "case2", "default", "latch", "exit"], "edges": [[0,1],[0,2],[2,3],[2,4],[4,5],[4,6],[4,7],[4,8],[5,9],[6,9],[7,9],[8,9],[9,2],[9,10]]}))
elif command == "xrefs-from":
    print("0x2000 scoring::normalize")
elif command == "xrefs-to":
    print("0x3000 scoring_cli; 0x3100 scoring_unit_tests")
else:
    sys.exit(2)
""",
        encoding="utf-8",
    )
    path.chmod(0o755)


def _gate_status(round_log: dict[str, object]) -> dict[str, str]:
    validation = round_log["validation"]
    assert isinstance(validation, dict)
    gates = validation["gates"]
    assert isinstance(gates, list)
    return {str(gate["kind"]): str(gate["status"]) for gate in gates}


def run_demo(output_dir: Path) -> dict[str, object]:
    fixture = Path(__file__).with_name("complex_project")
    project = output_dir / "project"
    reports = output_dir / "reports"
    output_dir.mkdir(parents=True, exist_ok=True)
    shutil.copytree(fixture, project)

    source = project / "src" / "analyzer.cpp"
    original_source = source.read_text(encoding="utf-8")
    reference = project / "reference" / "analyzer_reference.cpp"
    candidate = output_dir / "analyzer.recovered.cpp"
    object_file = output_dir / "analyzer-reference.o"
    subprocess.run(
        [
            "c++",
            "-std=c++17",
            "-O2",
            "-I",
            str(project / "include"),
            "-c",
            str(reference),
            "-o",
            str(object_file),
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    fake_ghidra = output_dir / "fake-ghidra"
    _write_fake_ghidra(fake_ghidra)
    reverser = ScriptedReverser(_extract_vector_definition(reference))
    checker = ScriptedChecker()
    bridge = GhidraBridge(str(fake_ghidra), project, strict=True)

    rounds = run_review_pipeline(
        object_file,
        candidate,
        output_dir / "unused.o",
        reverser,
        checker,
        reports,
        review_rounds=3,
        language="c++",
        timeout=120,
        ghidra_bridge=bridge,
        address="0x1000",
        project_root=project,
        address_map=Path("address-map.json"),
        build_commands=["make clean all"],
        test_commands=["make test"],
        runtime_commands=["make runtime"],
        require_tests=True,
        require_runtime=True,
        keep_overlay=True,
    )

    result = json.loads((reports / "result.json").read_text(encoding="utf-8"))
    round_1 = json.loads((reports / "logs" / "round-01.json").read_text(encoding="utf-8"))
    round_2 = json.loads((reports / "logs" / "round-02.json").read_text(encoding="utf-8"))
    overlay = Path(result["overlay_root"])
    overlay_source = (overlay / "src" / "analyzer.cpp").read_text(encoding="utf-8")
    round_1_gates = _gate_status(round_1)
    round_2_gates = _gate_status(round_2)
    summary = {
        "success": True,
        "rounds": rounds,
        "reverser_calls": reverser.calls,
        "checker_calls": checker.calls,
        "feedback_observed_by_reverser": reverser.feedback_observed,
        "target_signature": result["target_signature"],
        "address_map_used": result["address_map"],
        "strict_ghidra_artifacts": sorted(bridge.collect("0x1000").artifacts),
        "knowledge_graph_persisted": (reports / "knowledge-graph.json").is_file(),
        "round_1_checker": round_1["checker"]["verdict"],
        "round_1_objective": round_1["objective"]["verdict"],
        "round_1_build": round_1_gates.get("build"),
        "round_1_test": round_1_gates.get("test"),
        "round_1_runtime": round_1_gates.get("runtime"),
        "round_2_checker": round_2["checker"]["verdict"],
        "round_2_objective": round_2["objective"]["verdict"],
        "round_2_build": round_2_gates.get("build"),
        "round_2_test": round_2_gates.get("test"),
        "round_2_runtime": round_2_gates.get("runtime"),
        "source_project_unchanged": source.read_text(encoding="utf-8") == original_source,
        "scalar_overload_preserved": "return normalize(sample) + 1;" in overlay_source,
        "vector_overload_recovered": "transitions * 11" in overlay_source,
        "full_project_overlay": all(
            (overlay / name).exists()
            for name in ("CMakeLists.txt", "Makefile", "app", "include", "src", "tests")
        ),
        "overlay_root": str(overlay),
        "object_file": str(object_file),
        "round_1_log": str(reports / "logs" / "round-01.json"),
        "round_2_log": str(reports / "logs" / "round-02.json"),
    }
    (output_dir / "complex-project-summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output-dir", type=Path, default=PROJECT_ROOT / "work" / "complex-project-demo"
    )
    args = parser.parse_args()
    print(json.dumps(run_demo(args.output_dir), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
