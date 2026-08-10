#!/usr/bin/env python3
"""Run configured real-Ghidra, dual-model ELF/COFF/C++ integration cases."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Optional, Sequence


def _option(command: list[str], name: str, value: object) -> None:
    if value is not None and str(value):
        command.extend([name, str(value)])


def _load_config(path: Path) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("cases"), list):
        raise ValueError("matrix config must be an object containing a cases array")
    return payload


def run_matrix(config_path: Path, output_dir: Path) -> int:
    config = _load_config(config_path)
    defaults = config.get("defaults", {})
    if not isinstance(defaults, dict):
        raise ValueError("defaults must be an object")
    output_dir.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, object]] = []

    for raw_case in config["cases"]:  # type: ignore[index]
        if not isinstance(raw_case, dict):
            raise ValueError("each matrix case must be an object")
        case = {**defaults, **raw_case}
        name = str(case.get("name", "")).strip()
        if not name:
            raise ValueError("each matrix case requires a name")
        object_file = Path(str(case.get("object_file", ""))).resolve()
        project_root = Path(str(case.get("project_root", ""))).resolve()
        expected_format = str(case.get("format", ""))
        if expected_format not in {"ELF", "COFF", "Mach-O"}:
            raise ValueError(f"{name}: format must be ELF, COFF, or Mach-O")
        metadata = subprocess.run(
            ["file", str(object_file)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        if metadata.returncode != 0 or expected_format not in metadata.stdout:
            raise ValueError(
                f"{name}: object format mismatch; expected {expected_format}: {metadata.stdout.strip()}"
            )
        for gate_name in ("build_commands", "test_commands", "runtime_commands"):
            if not isinstance(case.get(gate_name), list) or not case[gate_name]:
                raise ValueError(f"{name}: real matrix requires non-empty {gate_name}")

        case_output = output_dir / name
        reports = case_output / "reports"
        source_output = case_output / "candidate.cpp"
        command = [
            sys.executable,
            str(Path(__file__).with_name("mini_re.py")),
            str(object_file),
            "-o",
            str(source_output),
            "--project-root",
            str(project_root),
            "--reports-dir",
            str(reports),
            "--require-tests",
            "--require-runtime",
        ]
        for key, flag in (
            ("provider", "--provider"),
            ("model", "--model"),
            ("base_url", "--base-url"),
            ("openai_api", "--openai-api"),
            ("checker_provider", "--checker-provider"),
            ("checker_model", "--checker-model"),
            ("checker_base_url", "--checker-base-url"),
            ("checker_openai_api", "--checker-openai-api"),
            ("ghidra_cli", "--ghidra-cli"),
            ("address", "--address"),
            ("source_file", "--source-file"),
            ("function", "--function"),
            ("function_signature", "--function-signature"),
            ("address_map", "--address-map"),
            ("review_rounds", "--review-rounds"),
        ):
            _option(command, flag, case.get(key))
        if case.get("parity_fail_on_yellow"):
            command.append("--parity-fail-on-yellow")
        if case.get("keep_overlay"):
            command.append("--keep-overlay")
        for key, flag in (
            ("build_commands", "--build-command"),
            ("test_commands", "--test-command"),
            ("runtime_commands", "--runtime-command"),
        ):
            for value in case[key]:  # type: ignore[index]
                command.extend([flag, str(value)])

        proc = subprocess.run(
            command,
            cwd=str(project_root),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=int(case.get("matrix_timeout", 3600)),
            check=False,
        )
        result_file = reports / "result.json"
        result_payload: object = None
        if result_file.is_file():
            result_payload = json.loads(result_file.read_text(encoding="utf-8"))
        results.append(
            {
                "name": name,
                "format": expected_format,
                "ok": proc.returncode == 0,
                "exit_code": proc.returncode,
                "output": proc.stdout,
                "result": result_payload,
            }
        )

    summary = {
        "config": str(config_path.resolve()),
        "all_passed": all(bool(item["ok"]) for item in results),
        "cases": results,
    }
    (output_dir / "matrix-summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return 0 if summary["all_passed"] else 1


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("reports/real-matrix"))
    args = parser.parse_args(argv)
    try:
        return run_matrix(args.config, args.output_dir)
    except (OSError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
        print(f"matrix error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
